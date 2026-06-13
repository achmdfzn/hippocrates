# HIPPOCRATES KNOWLEDGE BASE

**Generated:** 2026-06-13
**Stack:** TypeScript, Next.js App Router, Redis (Upstash/ioredis), Zod, tsup, Vitest

## OVERVIEW

Next.js App Router security middleware library (NPM: `hippocrates-middleware`). Wraps route handlers with Redis-backed cumulative threat scoring. Silently routes high-score requests to a decoy honeypot (200 OK with fake data) instead of the real handler.

## STRUCTURE

```
hippocrates/
├── src/
│   ├── index.ts                    # Entry point + HOF (242 lines, re-exports all modules)
│   ├── engine/
│   │   ├── types.ts                # Type definitions (332 lines)
│   │   ├── constants.ts            # Defaults, UA patterns, obfuscation patterns (218 lines)
│   │   ├── analyzers.ts            # Plugin placeholders L1-L6 (112 lines)
│   │   └── threat-score-engine.ts  # ThreatScoreEngine class (401 lines)
│   ├── plugins/
│   │   └── ml-engine.ts            # Python sidecar AnalyzerPlugin (152 lines)
│   ├── system/
│   │   ├── honeypot.ts             # Decoy, honeypot, stats, Redis degradation (152 lines)
│   │   ├── pipeline.ts             # Pipeline orchestration (386 lines)
│   │   └── validator.ts            # Zod validatePayload + ensureStrict (206 lines)
│   ├── utils/
│   │   └── ip.ts                   # IPv6 normalization (102 lines)
│   └── __tests__/
│       ├── helpers.ts                          # Test mocks (Redis, NextRequest, NextResponse)
│       ├── ip.test.ts                          # 29 tests (IPv6 normalization)
│       ├── threat-score-engine.test.ts          # 35 tests
│       ├── validate-payload.test.ts             # 7 tests
│       ├── decoy.test.ts                       # 9 tests
│       ├── with-hippocrates.test.ts             # 37 tests (integration — all layers)
│       ├── ensure-strict.test.ts                # 23 tests (recursive .strict() including ZodMap/ZodSet)
│       ├── redis-degradation.test.ts            # 6 tests (Redis fallback/circuit breaker)
│       ├── stats.test.ts                       # 5 tests (request statistics)
│       ├── stats-integration.test.ts            # 13 tests (StatsTracker wiring all layers)
│       └── ml-engine-integration.test.ts        # 13 tests (ML engine plugin integration)
├── engine-python/
│   ├── app/
│   │   ├── main.py                 # FastAPI app — POST /analyze, GET /health
│   │   ├── config.py               # Pydantic settings (HIPPO_ML_*)
│   │   ├── models.py               # AnalyzeRequest/Response Pydantic models
│   │   └── analyzers/
│   │       ├── __init__.py         # Exports PromptInjection, Obfuscation, ContentRisk
│   │       ├── prompt_injection.py # Heuristic + entropy injection detection
│   │       ├── obfuscation_advanced.py  # Shannon entropy + transform chaining
│   │       └── content_risk.py     # SQLi, XSS, path traversal, command injection
│   ├── tests/
│   │   ├── test_analyzers.py       # 225+ lines, unit tests for 3 analyzers
│   │   └── test_api.py             # 135+ lines, integration tests
│   ├── Dockerfile                  # python:3.12-slim + curl + requirements
│   ├── requirements.txt            # fastapi, uvicorn, pydantic, scikit-learn
│   ├── pyproject.toml
│   ├── smoke-test.ps1              # Docker Compose smoke test
│   └── README.md                   # ML engine standalone docs
├── example/
│   └── app/api/data/route.ts  # Reference implementation
├── docker-compose.yml        # Redis + ML engine, healthchecks, hippocrates-net
├── .github/workflows/ci.yml  # GitHub Actions (lint → typecheck → test → build → docker)
├── eslint.config.mjs         # ESLint flat config v10
├── package.json              # tsup build, peer deps (next, zod)
├── tsconfig.json             # strict + exactOptionalPropertyTypes + noUncheckedIndexedAccess
├── vitest.config.ts          # Vitest config (globals: true)
├── .gitignore
├── LICENSE                   # MIT
├── SKILL.md                  # Loadable skill definition for OpenCode agents
├── AGENTS.md                 # This file
├── CLAUDE.md                 # Project orientation
└── README.md                 # Public docs
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Entry point + HOF | `src/index.ts` | `withHippocrates()` — primary export, ~242 lines |
| Type definitions | `src/engine/types.ts` | `RedisClient`, `HippocratesConfig`, `ThreatScoringWeights`, `AnalyzerPlugin`, `HippocratesHooks` |
| Constants & defaults | `src/engine/constants.ts` | `DEFAULTS`, `DEFAULT_WEIGHTS`, `AGENT_UA_PATTERNS` (40+ entries), `PRESETS` |
| Per-layer analyzers | `src/engine/analyzers.ts` | Placeholder plugins for L1-L6 (actual logic runs in pipeline) |
| ThreatScoreEngine | `src/engine/threat-score-engine.ts` | Redis-integrated scoring with circuit breaker (30s auto-recovery) |
| Pipeline orchestration | `src/system/pipeline.ts` | Runs L-1 → L0 → pre-body → score gate → body → post-body → final gate |
| Honeypot + decoy | `src/system/honeypot.ts` | `generateDecoyResponse()` (4 templates), `serveHoneypot()`, custom violation messages |
| Zod validator | `src/system/validator.ts` | `validatePayload<T>()`, `ensureStrict<T>()` — handles 14+ Zod types (including ZodMap/ZodSet) |
| IPv6 normalization | `src/utils/ip.ts` | `normalizeIp()`, `resolveClientIp()` |
| ML Engine plugin | `src/plugins/ml-engine.ts` | `mlEnginePlugin()` — HTTP client to Python sidecar |
| Integration tests | `src/__tests__/with-hippocrates.test.ts` | 37 tests, covers all layers + v1.6 features |
| Unit tests (engine) | `src/__tests__/threat-score-engine.test.ts` | 35 tests (includes L6 header tests) |
| Decoy/honeypot tests | `src/__tests__/decoy.test.ts` | 9 tests |
| Validator tests | `src/__tests__/validate-payload.test.ts` | 7 tests |
| ensureStrict tests | `src/__tests__/ensure-strict.test.ts` | 23 tests (recursive .strict() including ZodMap/ZodSet) |
| Redis degradation tests | `src/__tests__/redis-degradation.test.ts` | 6 tests (Redis fallback, circuit breaker) |
| Stats tests | `src/__tests__/stats.test.ts` | 5 tests (request counts, score histograms) |
| Stats integration | `src/__tests__/stats-integration.test.ts` | 13 tests (StatsTracker wiring all layers) |
| ML engine integration | `src/__tests__/ml-engine-integration.test.ts` | 13 tests (ML engine plugin integration) |
| IPv6 normalization tests | `src/__tests__/ip.test.ts` | 29 tests |
| Example consumer | `example/app/api/data/route.ts` | Reference impl |
| CI pipeline | `.github/workflows/ci.yml` | Node 18/20/22 matrix + Docker build job |
| Skill definition | `SKILL.md` | Loadable by task agents |
| Orientation | `CLAUDE.md` | Onboarding + invariants |

## MODULE MAP

| Module | File | Lines | Key Exports |
|--------|------|:-----:|-------------|
| Types | `src/engine/types.ts` | 332 | `RedisClient`, `HippocratesConfig`, `ThreatScoringWeights`, `AppRouteHandler`, `ValidationResult`, `AnalyzerPlugin`, `HippocratesHooks`, `AllowlistConfig`, `SecurityStats`, `StatsTracker` |
| Constants | `src/engine/constants.ts` | 218 | `DEFAULTS`, `DEFAULT_WEIGHTS`, `AGENT_UA_PATTERNS`, `OBFUSCATION_PATTERNS`, `HEADER_ANOMALY_PATTERNS`, `PRESETS`, `DEFAULT_BODY_LIMIT` |
| Analyzers | `src/engine/analyzers.ts` | 112 | `timingAnalyzer`, `velocityAnalyzer`, `userAgentAnalyzer`, `obfuscationAnalyzer`, `schemaAnalyzer`, `headerAnalyzer`, `BUILT_IN_ANALYZERS` |
| Engine | `src/engine/threat-score-engine.ts` | 401 | `ThreatScoreEngine` — `getScore()`, `addScore()`, `analyzeRequestTiming()`, `analyzeVelocity()`, `analyzeUserAgent()`, `analyzeHeaders()`, `detectObfuscation()`, `runAnalyzers()`, Redis circuit breaker (30s auto-recovery), in-memory stats |
| ML Plugin | `src/plugins/ml-engine.ts` | 152 | `mlEnginePlugin()` — creates AnalyzerPlugin, HTTP POST to Python sidecar |
| Honeypot | `src/system/honeypot.ts` | 152 | `generateDecoyResponse()` (4 templates), `serveHoneypot()`, custom violation messages |
| Pipeline | `src/system/pipeline.ts` | 386 | `HippocratesPipeline` — L-1 allowlist, L0 pre-flight, pre-body (L1/L2/L3/L6), body parsing (L4/L5), post-body plugins, final score gate |
| Validator | `src/system/validator.ts` | 206 | `validatePayload<T>()`, `ensureStrict<T>()` — handles 14+ Zod types recursively (ZodMap/ZodSet) |
| Index | `src/index.ts` | 242 | `withHippocrates()`, `resolveConfig()`, `ensureStrict()`, `validatePayload()`, re-exports, `z`, `ZodSchema` |

## CONVENTIONS
- **Aggressive TypeScript**: `strict`, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`, `noImplicitReturns`.
- **ValidationResult** uses `ok: true/false` (NOT `success`) to avoid collision with API response shapes.
- **Generic constraint**: `T extends Record<string, unknown>` for Zod schema type param.
- **`/* @internal */` exports** for testing only — documented with `@internal` JSDoc.
- **Config merging once** at HOF call time, not per request.
- **Redis keys**: `hc:{type}:{ip}` namespace, short keys (Upstash tier charges by key size).
- **Velocity list** capped at 500 entries via `ltrim`.
- **Redis circuit breaker** auto-recovers after 30s cooldown (transient Redis failures don't permanently disable security).
- **Test files** use `vi.mock("next/server")` for Next.js mocks. Vitest globals enabled.
- **`noUncheckedIndexedAccess`** means array access returns `T | undefined` — use `.filter()` or explicit checks.

## ANTI-PATTERNS (THIS PROJECT)

- **NEVER** return `403`/`429` to detected threats — always `serveHoneypot()` with 200 OK.
- **NEVER** expose Zod error details — error message must be vague (no field names, no types).
- **NEVER** use `as any`, `@ts-ignore`, `@ts-expect-error` — type safety is critical.
- **NEVER** create the `ThreatScoreEngine` per-request — construct once in the HOF.
- **NEVER** call `req.text()` or `req.json()` twice — body stream is consumed once.
- **NEVER** use `Buffer.from()` — breaks Edge Runtime. Use `btoa()` instead.
- **NEVER** lower the base64 regex threshold below 24 chars — causes false positives on UUIDs/tokens.
- **NEVER** leak `err.message` or stack traces in the last-resort catch block.
- **NEVER** use broad keyword UA patterns (`/framework/i`) without version awareness — prefer `/framework\/[\d.]+/i`.
- **NEVER** let the ML engine sidecar block security — always degrade gracefully on failure.

## CRITICAL INVARIANTS

1. Zod schemas MUST use `.strict()` — otherwise L5 is effectively disabled.
2. Error messages leak schema structure — always generic count-only format.
3. `content-length` header MUST be deleted on forwarded requests (stale after re-serialization).
4. Internal headers `x-hippocrates-score` and `x-hippocrates-clean` MUST be stripped before forwarding to third-party services. The `x-request-id` header is also added for log correlation.
5. IPv6 normalization is handled via `resolveClientIp()` from `src/utils/ip.ts` — `::1` → `127.0.0.1`, `::ffff:x.x.x.x` → IPv4.

## COMMANDS

```bash
npm run build          # tsup → dist/ (CJS + ESM + .d.ts)
npm run dev            # tsup --watch
npm run typecheck      # tsc --noEmit
npm run lint           # ESLint flat config
npm test               # Vitest (177 tests across 10 files)
npm run test:watch     # Vitest watch mode
npm run prepublishOnly # typecheck + build

# Python ML engine
cd engine-python && pip install -r requirements.txt && pytest -v

# Docker
docker compose up --build
```

## PITFALLS & GOTCHAS

- **`req.text()` consumes body** — forward `JSON.stringify(validatedBody)` on clean request.
- **Upstash vs ioredis** — `set()` options differ. `RedisClient` interface uses Upstash-style `{ ex: n }`.
- **Debug logs are sync** — don't rely on log order in serverless environments. Correlate by `requestId`.
- **Velocity list never explicitly deleted** — expires via TTL naturally.
- **Redis circuit breaker** trips after 3 Redis errors, auto-recovers after 30s. During degraded mode, all checks return safe defaults (score=0).
- **`::1` and `127.0.0.1` are now normalized** to the same key (via `src/utils/ip.ts`).
- **dist/ is never committed** — generated on `prepublishOnly`.
- **BodyLimit `enabled` defaults to `true`** — partial config like `{ maxBytes: 100 }` auto-inherits `enabled: true` from `DEFAULT_BODY_LIMIT`.
- **ML engine runs post-body** — `context.bodyRaw` is populated by pipeline; ML engine never calls `req.text()` itself.
- **ML engine unreachable is non-fatal** — returns `score: 0` with `tags: ["ml-engine-unreachable"]` on failure.
- **Python sidecar has 4 env-togglable analyzers** — prompt injection, obfuscation, content risk. All toggleable via `HIPPO_ML_ENABLE_*`.
- **Docker healthchecks need curl** — `python:3.12-slim` doesn't include curl; installed explicitly in Dockerfile.
