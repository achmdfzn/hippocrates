"""FastAPI application for the Hippocrates ML Detection Engine."""

import asyncio
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import settings
from app.models import AnalyzeRequest, AnalyzeResponse, AnalyzerResult
from app.analyzers import PromptInjectionAnalyzer, AdvancedObfuscationAnalyzer, ContentRiskAnalyzer

logger = logging.getLogger("hippocrates-ml")

# ── Analyzer instances ────────────────────────────────────────────────

prompt_injection = PromptInjectionAnalyzer()
obfuscation_advanced = AdvancedObfuscationAnalyzer()
content_risk = ContentRiskAnalyzer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    logger.info("Hippocrates ML Engine starting")
    yield
    logger.info("Hippocrates ML Engine shutting down")


app = FastAPI(
    title="Hippocrates ML Detection Engine",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "analyzers": {
            "prompt_injection": settings.enable_prompt_injection,
            "obfuscation_advanced": settings.enable_obfuscation_advanced,
            "content_risk": settings.enable_content_risk,
        },
    }


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest):
    """
    Analyze a request for ML-detectable threats.

    Runs enabled analyzers in parallel and returns aggregated threat score.
    """
    analyses: dict[str, AnalyzerResult] = {}
    all_tags: list[str] = []
    total_score = 0

    async def run_analyzer(name: str, enabled: bool, coro):
        if not enabled:
            analyses[name] = AnalyzerResult(score=0, tags=[], confidence=0.0)
            return
        try:
            result = await asyncio.wait_for(
                coro,
                timeout=settings.request_timeout_seconds,
            )
            analyses[name] = result
            return result
        except asyncio.TimeoutError:
            logger.warning("Analyzer %s timed out", name)
            analyses[name] = AnalyzerResult(score=0, tags=["timeout"], confidence=0.0)
        except Exception:
            logger.exception("Analyzer %s failed", name)
            analyses[name] = AnalyzerResult(score=0, tags=["error"], confidence=0.0)

    tasks = [
        run_analyzer(
            "prompt_injection",
            settings.enable_prompt_injection,
            prompt_injection.analyze(payload.body, payload.body_raw),
        ),
        run_analyzer(
            "obfuscation_advanced",
            settings.enable_obfuscation_advanced,
            obfuscation_advanced.analyze(payload.body, payload.body_raw),
        ),
        run_analyzer(
            "content_risk",
            settings.enable_content_risk,
            content_risk.analyze(payload.body, payload.body_raw),
        ),
    ]

    results = await asyncio.gather(*tasks)

    for result in results:
        if result is None:
            continue
        total_score += result.score
        all_tags.extend(result.tags)

    # Deduplicate tags
    all_tags = list(dict.fromkeys(all_tags))

    # Cap at 100
    total_score = min(100, total_score)

    return AnalyzeResponse(
        score=total_score,
        tags=all_tags,
        analyses=analyses,
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Last-resort catch-all that never leaks internal details."""
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_error"},
    )


def start():
    """Entry point for `python -m app.main`."""
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
    )


if __name__ == "__main__":
    start()
