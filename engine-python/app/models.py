"""Pydantic models for the ML engine API."""

from pydantic import BaseModel, Field
from typing import Any


class AnalyzeRequest(BaseModel):
    """Incoming request from the Hippocrates plugin."""

    request_id: str = Field(default="", description="Hippocrates request correlation ID")
    ip: str = Field(default="", description="Client IP address")
    method: str = Field(default="POST", description="HTTP method")
    path: str = Field(default="/", description="Request path")
    headers: dict[str, str] = Field(default_factory=dict, description="Request headers")
    body: dict[str, Any] | list[Any] | str | None = Field(default=None, description="Parsed request body")
    body_raw: str | None = Field(default=None, description="Raw body string")


class AnalyzerResult(BaseModel):
    """Result from a single analyzer."""

    score: int = Field(ge=0, le=100, description="0-100 threat score contribution")
    tags: list[str] = Field(default_factory=list, description="Violation tags")
    confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Detection confidence")


class AnalyzeResponse(BaseModel):
    """Response sent back to the Hippocrates plugin."""

    score: int = Field(ge=0, le=100, description="Aggregated threat score 0-100")
    tags: list[str] = Field(default_factory=list, description="All violation tags")
    analyses: dict[str, AnalyzerResult] = Field(default_factory=dict, description="Per-analyzer breakdown")
