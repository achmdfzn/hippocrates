# CLAUDE.md — hippocrates

Project orientation file for Claude Code and new contributors.
Read this before touching any file in this repo.

---

## What This Project Is

`hippocrates-middleware` is a Next.js App Router security middleware library published to NPM.
It exports one primary function — `withHippocrates` — that wraps any App Router
route handler with a **Strict Stateful Defense Architecture**.

The core loop is: evaluate every incoming request against a cumulative Threat Score
stored in Redis, and silently route high-score requests to a decoy generator instead
of the real handler. The attacker always receives a `200 OK` — never a `403` or `429`.

---

## File Map

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
│   /
│   │   ├── honeypot.ts             # Decoy, honeypot, Redis degradation (152 lines)
│   │   ├── pipeline.ts             # Pipeline orchestration (386 lines)
│   │   └── validator.ts            # Zod validatePayload + ensureStrict (206 lines)
│   ├── utils/
│   │   └── ip.ts                   # IPv6 normalization (102 lines)
│   └── __tests__/
│       ├── helpers.ts                          # Test mocks (159 lines)
│       ├── ip.test.ts                          # 29 tests (IPv6 normalization)
│       ├── threat-score-engine.test.ts          # 35 tests
│       ├── validate-payload.test.ts             # 7 tests
│       ├── decoy.test.ts                       # 9 tests
│       ├── with-hippocrates.test.ts             # 37 tests (integration — all layers)
│       ├── ensure-strict.test.ts                # 23 tests (recursive .strict() + ZodMap/ZodSet)
│       ├── redis-degradation.test.ts            # 6 tests (Redis fallback/circuit breaker)
│       ├── stats.test.ts                       # 5 tests (request statistics)
│       ├── stats-integration.test.ts            # 13 tests (StatsTracker wiring all layers)
│       └── ml-engine-integration.test.ts        # 13 tests (ML engine plugin integration)
├── engine-python/
│   ├── app/
│   │   ├── main.py                 # FastAPI app — POST /analyze, GET /health (141 lines)
│   │   ├── config.py               # Pydantic settings (HIPPO_ML_* env vars)
│   │   ├── models.py               # AnalyzeRequest/Response Pydantic models
│   │   └── analyzers/
│   │       ├── __init__.py         # Exports PromptInjection, Obfuscation, ContentRisk
│   │       ├── prompt_injection.py # Heuristic + entropy prompt injection detection
│   │       ├── obfuscation_advanced.py  # Shannon entropy + transform chaining
│   │       └── content_risk.py     # SQLi, XSS, path traversal, command injection
│   ├── tests/
│   │   ├── test_analyzers.py       # 225+ lines, unit tests for all 3 analyzers
│   │   └── test_api.py             # 135+ lines, integration tests for /analyze, /health
│   ├── Dockerfile                  # python:3.12-slim + curl + requirements
│   ├── requirements.txt            # fastapi, uvicorn, pydantic, scikit-learn
│   ├── pyproject.toml
│   ├── smoke-test.ps1              # Docker Compose smoke test (healthchecks + analyze)
│   └── README.md                   # ML engine standalone docs
├── example/
│   └── app/api/data/route.ts  # Reference implementation
├── docker-compose.yml        # Redis + ML engine, healthchecks, hippocrates-net
├── .github/workflows/ci.yml  # GitHub Actions (lint → typecheck → test → build → docker)
├── eslint.config.mjs         # ESLint flat config v10
├── package.json              # tsup build, peer deps (next, zod)
├── tsconfig.json             # strict + exactOptionalPropertyTypes + noUncheckedIndexedAccess
├── vitest.config.ts          # Vitest config (globals: true)
├── SKILL.md                  # Loadable skill definition for OpenCode agents
├── AGENTS.md                 # Hierarchical knowledge base
├── CLAUDE.md                 # This file
├── README.md                 # Public-facing documentation
├── LICENSE                   # MIT
└── .gitignore
```

The library is modular but designed so that consumers import everything from a single
entry point (`hippocrates` / `src/index.ts`). No internal imports needed at the
consumer level. Modules are separated by concern:
- **`engine/`** — type definitions, constants, per-layer analyzers, and the scoring engine
- **`system/`** — pipeline orchestration, honeypot/decoys, validation, stats, and Redis degradation
- **`plugins/`** — optional AnalyzerPlugin implementations (ML engine Python sidecar)
- **`utils/`** — IPv6 normalization utility

---

## Architecture Mental Model

```
Incoming Request
      │
      ▼
   L-1: IP allowlist? ──── YES? ──→ Forward to handler (skip all checks)
      │ (no)
      ▼
   L0: Pre-flight score check ──── score ≥ threshold? ──→ HONEYPOT (200 OK + fake data)
      │ (no)
      ▼
   Pre-body analyzers (L1, L2, L3, L6 + custom AnalyzerPlugin)
   L1: Timing analysis ──── interval < 50ms? ──→ +25 pts
   L2: Velocity check ──── req count > max in window? ──→ +40 pts
   L3: User-Agent analysis ──── known agent UA? ──→ +15 pts
   L6: Header anomalies ──── missing/wildcard? ──→ +15 pts
      │ score ≥ threshold?
      ├──YES──→ HONEYPOT
      │ (no)
      ▼
   Body parse → post-body analyzers (L4, L5 + custom AnalyzerPlugin)
   L4: Obfuscation scan ──── Base64/Hex in payload? ──→ +100 pts (instant max)
   L5: Zod .strict() validation ──── schema violation? ──→ +100 pts (instant max)
      │ score ≥ threshold?
      ├──YES──→ HONEYPOT
      │ (no)
      ▼
   PASS → forward clean, validated request to actual handler
```

All state lives in Redis under the `hc:` namespace. No in-memory state.
The library is stateless from Next.js's perspective — each invocation is
a fresh function call, but threat memory persists across requests via Redis.

---

## Module Map

The codebase is organized into 3 module groups under `src/`. Each module has a
single responsibility and is independently testable.

| Module | File | Responsibility |
|--------|------|----------------|
| Types | `src/engine/types.ts` | `RedisClient`, `HippocratesConfig`, `ThreatScoringWeights`, `AnalyzerPlugin`, `HippocratesHooks`, `AllowlistConfig`, `SecurityStats`, `StatsTracker` |
| Constants | `src/engine/constants.ts` | `DEFAULTS`, `DEFAULT_WEIGHTS`, `AGENT_UA_PATTERNS` (40+ entries), `OBFUSCATION_PATTERNS` (5), `HEADER_ANOMALY_PATTERNS` (4), `PRESETS`, `DEFAULT_BODY_LIMIT` |
| Analyzers | `src/engine/analyzers.ts` | `timingAnalyzer`, `velocityAnalyzer`, `userAgentAnalyzer`, `obfuscationAnalyzer`, `schemaAnalyzer`, `headerAnalyzer`, `BUILT_IN_ANALYZERS` |
| Engine | `src/engine/threat-score-engine.ts` | `ThreatScoreEngine` class — `getScore()`, `addScore()`, `analyzeRequestTiming()`, `analyzeVelocity()`, `analyzeUserAgent()`, `analyzeHeaders()`, `detectObfuscation()`, `runAnalyzers()`, Redis circuit breaker (30s auto-recovery), in-memory stats |
| ML Plugin | `src/plugins/ml-engine.ts` | `mlEnginePlugin()` factory — creates AnalyzerPlugin that POSTs to Python sidecar |
| Honeypot | `src/system/honeypot.ts` | `generateDecoyResponse()` (4 templates), `serveHoneypot()`, custom violation messages, Redis degradation |
| Pipeline | `src/system/pipeline.ts` | Pipeline orchestration — L-1 allowlist, L0 pre-flight, pre-body (L1/L2/L3/L6), body parsing (L4/L5), post-body (custom plugins + ML engine), final score gate |
| Validator | `src/system/validator.ts` | `validatePayload<T>()`, `ensureStrict<T>()` — handles 14+ Zod types recursively (including ZodMap/ZodSet) |
| Index | `src/index.ts` | Public API entry point — `withHippocrates()` HOF, `resolveConfig()`, `ensureStrict()`, `validatePayload()`, all re-exports |

---

## Development Commands

```bash
npm run build          # tsup → dist/ (CJS + ESM + .d.ts)
npm run dev            # tsup --watch
npm run typecheck      # tsc --noEmit
npm run lint           # ESLint flat config v10 (eslint.config.mjs)
npm test               # Vitest — 177 tests across 10 files
npm run test:watch     # Vitest watch mode
npm run prepublishOnly # typecheck + build
npm run test:all       # TS tests + Python tests

# Python ML engine (full test suite: 39 tests)
cd engine-python
pip install -r requirements.txt
pytest -v              # Python tests (31 analyzers + 8 API)
python -m pytest tests/ -v --cov  # With coverage

# Full stack
docker compose up --build   # Redis + ML engine (health-checked)
npm test && cd engine-python && pytest -v  # Run all 216 tests
```

The build tool is `tsup`. Output goes to `dist/`. Never commit `dist/` — it is
generated on `prepublishOnly`.

---

## Critical Invariants — Never Violate These

These rules are architectural constraints, not style preferences.
Breaking them degrades security without warning.

### 1. Never return 403 or 429 to a detected threat

```typescript
// ❌ Wrong — tells the attacker what triggered detection
return NextResponse.json({ error: "Rate limited" }, { status: 429 });

// ✓ Correct — always route through serveHoneypot()
return serveHoneypot(req, decoyFn, ip, score, violations, debug);
```

A `4xx` response is a signal. The attacker reads it, adapts, retries.
A convincing `200 OK` with fake data wastes their budget and halts agentic
pipelines that chain decisions on API output.

### 2. Never expose Zod error details to the caller

```typescript
// ❌ Wrong — leaks schema structure
return NextResponse.json({ error: err.issues }, { status: 422 });

// ✓ Correct — intentionally vague
return { ok: false, error: `Validation failed (${err.issues.length} constraints)` };
```

Detailed Zod errors let an attacker enumerate the schema field by field
and craft payloads that survive validation while carrying injections.

### 3. Always use .strict() on Zod schemas

```typescript
// ❌ Wrong — Zod strips extra fields silently, they pass through
const Schema = z.object({ id: z.string() });

// ✓ Correct — extra fields trigger schemaViolation (100 pts, instant honeypot)
const Schema = z.object({ id: z.string() }).strict();
```

Without `.strict()`, the library's L5 layer is effectively disabled.

### 4. The last-resort catch must never leak internals

```typescript
// ✓ The catch block in withHippocrates — keep it exactly like this
} catch (err) {
  if (cfg.debugMode) console.error("[hc:error]", err);
  return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
}
```

Stack traces and error messages are intelligence for an attacker.
The generic `500` response body must never contain `err.message` or similar.

### 5. Config merging happens once at HOF call time, not per request

```typescript
// ✓ Inside withHippocrates(), before the returned function
const cfg = { ...DEFAULTS, ...config };
const weights = { ...DEFAULT_WEIGHTS, ...(config.scoring ?? {}) };
const engine = new ThreatScoreEngine(redis, cfg, weights);

// ❌ Wrong — recreating engine on every request is expensive
return async function(req) {
  const engine = new ThreatScoreEngine(...); // Don't do this
}
```

The HOF is called once at module load time. The returned async function
is what Next.js calls per request. Keep expensive setup outside it.

### 6. Never use Buffer.from() — breaks Edge Runtime

```typescript
// ❌ Wrong — Buffer is not available in Edge Runtime
accessToken: Buffer.from(data).toString("base64"),

// ✓ Correct — btoa() works everywhere (Edge, Node, browser)
accessToken: btoa(data),
```

Next.js Edge Runtime (Vercel Edge Functions, Cloudflare Workers) does not
have `Buffer`. Use `btoa()` for base64 encoding instead.

---

## How to Extend the Library

### Adding a custom AnalyzerPlugin (most common approach)

Create an `AnalyzerPlugin` object and register it via `config.plugins`:

```typescript
import { type AnalyzerPlugin, withHippocrates } from "hippocrates";

const geoAnalyzer: AnalyzerPlugin = {
  name: "geo_block",
  phase: "pre-body",       // "pre-body" | "post-body"
  priority: 10,            // Lower = runs first
  async analyze(req, ctx) {
    const country = req.headers.get("x-country");
    if (country === "blocked") {
      return { score: 50, tags: ["geo:blocked"] };
    }
    return { score: 0, tags: [] };
  },
};
```

Plugins run alongside built-in L1-L6 analyzers, sorted by priority.

### Adding a new User-Agent pattern

Edit `AGENT_UA_PATTERNS` in `src/engine/constants.ts`. Always use
`ReadonlyArray<RegExp>`. Add a comment explaining what the pattern targets.

```typescript
// In AGENT_UA_PATTERNS array:
/new-llm-framework\/[\d.]+/i,   // YourFramework HTTP client
```

Prefer specific version-aware patterns (`/framework\/[\d.]+/i`) over
broad keyword matches (`/framework/i`) to reduce false positives.

The array currently has 40+ entries (see AGENTS.md for complete list).

### Adding a new obfuscation pattern

Edit `OBFUSCATION_PATTERNS` in `src/engine/constants.ts`. Each entry needs
`name` and `pattern`.

```typescript
{
  name: "double_encoding",
  pattern: /(?:%25[0-9a-fA-F]{2}){3,}/,  // URL-encoded percent signs
},
```

Test your regex against real payloads before adding. The `name` field
appears in the violation tag logged to Redis and in `debugMode` output.

### Adding a new detection layer (hardcoded, not plugin)

1. Add an analyzer function to `src/engine/analyzers.ts`.
2. Add the corresponding weight key to `ThreatScoringWeights` in `src/engine/types.ts`.
3. Add a default value to `DEFAULT_WEIGHTS` in `src/engine/constants.ts`.
4. Call the analyzer inside `src/system/pipeline.ts`, following the
   existing L1–L3 pattern (run analyzer, check result, call `addScore`).
5. Wire the analyzer into `ThreatScoreEngine` in `src/engine/threat-score-engine.ts`.

New layers always go BEFORE the body-parsing block (L4+L5). Header and
behavioral checks are cheap; body parsing is expensive — keep that last.

### Adding a new decoy response template

Edit `generateDecoyResponse()` in `src/system/honeypot.ts`. Add a new
`if (slot === N)` branch and increment the slot count:
`Math.floor(Math.random() * (N+1))`.

Mirror realistic API response shapes. Include `requestId`, `timestamp`,
nested `data` objects. Avoid obviously fake values like `"fake_data"`.

---

## Redis Key Schema

All keys use the `hc:` namespace. Keep key names short — Upstash free
tier charges per key size in some configurations.

| Key Pattern | Purpose | Default TTL |
|------------|---------|------------|
| `hc:s:{ip}` | Cumulative threat score (integer 0–100) | `threatTtlSeconds` (3600s) |
| `hc:t:{ip}` | Request timestamp list for velocity window | `velocityWindowMs/1000 + 10s` |
| `hc:l:{ip}` | Last-seen timestamp for timing analysis | 300s (hardcoded) |

> **Stats are in-memory only** (via the `StatsTracker` interface), not stored in Redis.
> The `hc:stats:*` Redis keys do not exist — counters live on the `ThreatScoreEngine` instance
> and can be read via `engine.getStats()`.

The `hc:t:{ip}` key uses a Redis list capped at 500 entries via `ltrim`.
Never change this cap without considering Upstash/Redis memory limits.

---

## Internal Headers Set by the Middleware

When a request passes all layers and is forwarded to the real handler,
Hippocrates injects two internal headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `x-hippocrates-score` | Integer string, e.g. `"12"` | Threat score for audit logging |
| `x-hippocrates-clean` | `"1"` | Signals the request passed all checks |
| `x-request-id` | UUID string | Unique request identifier for log correlation |

Read them in your handler via `req.headers.get("x-hippocrates-score")`.
Strip them before forwarding to third-party services.

`content-length` is deleted from the forwarded headers because the
body may have been re-serialized (validated data only) and the original
length is stale.

---

## TypeScript Conventions

This project uses aggressive TypeScript settings. Respect them.

- `strict: true` — no implicit any, strict null checks
- `exactOptionalPropertyTypes: true` — `undefined` and missing are different
- `noUncheckedIndexedAccess: true` — array/object access returns `T | undefined`
- `noImplicitReturns: true` — all code paths must return

Generic constraints use `T extends Record<string, unknown>` for the schema
type parameter because Zod object schemas always infer object types.
Do not loosen this to `T extends object` — it loses too much type info.

The `ValidationResult<T>` discriminated union uses `ok: true/false` not
`success` to avoid collision with the `success` field commonly returned
by API responses (which would cause confusing naming at call sites).

---

## v1.6 Features Summary

Features added since v1.5:

| Feature | Config Field | Since |
|---------|-------------|-------|
| **IP Allowlist** | `allowlist: { ips: string[] }` | v1.6 |
| **Body Size Limits** | `bodyLimit: { maxBytes, enabled }` | v1.6 |
| **Config Presets** | `preset: "strict" | "moderate" | "relaxed"` | v1.6 |
| **Method Thresholds** | `methodThresholds: Record<string, number>` | v1.6 |
| **Custom Violation Messages** | `violationMessages: object` | v1.6 |
| **Stats Tracker** | `statsTracker: StatsTracker` | v1.6 |
| **Redis Circuit Breaker** | Automatic (internal) | v1.6 |

## v1.7 Features Summary

| Feature | Config Field | Since |
|---------|-------------|-------|
| **ML Engine Plugin** | `plugins: [mlEnginePlugin(...)]` | v1.7 |
| **Docker Compose** | `docker-compose.yml` | v1.7 |
| **Stats Integration** | `statsTracker` forwarded from pipeline | v1.7 |
| **bodyRaw in Context** | `AnalysisContext.bodyRaw` for post-body plugins | v1.7 |
| **Python Sidecar** | `engine-python/` — FastAPI + 3 analyzers | v1.7 |
| **CI Docker Build** | GitHub Actions verifies Docker build | v1.7 |

## Pitfalls and Gotchas

**The base64 regex has a minimum length of 24 chars.**
Short base64-looking strings (like UUIDs or short tokens) are common in
legitimate payloads and would cause massive false positives if flagged.
Do not lower this threshold.

**`req.text()` consumes the body stream.**
After calling `await req.text()`, the original `req` body is exhausted.
The middleware re-serializes the validated body into `cleanReq`. If you
modify the body-passing logic, always use `JSON.stringify(validatedBody)`
on the new request, not the original `req.body`.

**`ThreatScoreEngine` is constructed once per HOF call, not per request.**
It holds no per-request state. All state is in Redis. This is intentional
and safe for concurrent requests.

**`debugMode` logs are synchronous `console.log/warn/error`.**
In serverless environments (Vercel), logs are buffered. Don't rely on
log order for debugging concurrent requests. Use `requestId` correlation.

**The velocity list (`hc:t:{ip}`) is never explicitly deleted.**
It expires naturally via Redis TTL. If you change `velocityWindowMs`
dynamically (not recommended), old timestamps from a larger window may
inflate counts. Use a consistent window per deployment.

**Upstash Redis vs ioredis method signatures differ slightly.**
Upstash `set()` accepts `{ ex: number }` as the options object.
ioredis `set()` uses positional args: `set(key, value, 'EX', seconds)`.
The `RedisClient` interface only covers the Upstash-style signature.
If using ioredis, provide a thin adapter wrapper — do not change the interface.

**IPv6 normalization is handled by `src/utils/ip.ts`.**
`::1` (loopback) normalizes to `127.0.0.1`. `::ffff:x.x.x.x` extracts
the IPv4 portion. Zone IDs (e.g., `fe80::1%eth0`) are stripped.
The `resolveClientIp()` function handles all header sources.

**The Redis circuit breaker auto-recovers after 30s.**
After 3 consecutive Redis errors, `redisHealthy` flips to `false` and all
`getScore()` calls return `0` (safe default). A lightweight `hc:ping` key
is attempted after 30s — if it succeeds, the circuit breaker resets.
This prevents transient Redis outages from permanently disabling security.

**ML engine runs in post-body phase with priority 50.**
It fires after L4/L5 built-in analyzers. The `bodyRaw` field is populated
by the pipeline before plugins run — ML engine never calls `req.text()` itself.

**ML engine unreachable is non-fatal.**
The plugin returns `score: 0` with `tags: ["ml-engine-unreachable"]` on any
fetch failure. Security never depends on the sidecar being available.

**Docker Compose healthchecks require curl.**
`python:3.12-slim` does not include curl — it's installed explicitly in the
Dockerfile via `apt-get`. Without it, `HEALTHCHECK --interval=5s` fails.

**Python ML engine supports 3 analyzers.**
- `PromptInjectionAnalyzer` — heuristic + entropy prompt injection detection
- `AdvancedObfuscationAnalyzer` — Shannon entropy + encoding chaining analysis
- `ContentRiskAnalyzer` — SQLi, XSS, path traversal, command injection patterns

Each is independently toggleable via `HIPPO_ML_ENABLE_*` env vars.

---

## CI Pipeline

GitHub Actions runs on push/PR to `main`:

```
quality (Node 18/20/22):
  lint → typecheck → test (npm test) → build (tsup)

docker:
  build ML engine Docker image → healthcheck → verify container starts
```

The `docker` job builds `engine-python/Dockerfile` without push. It verifies
the Python sidecar compiles, starts, and responds to `GET /health`.

## What This Library Does NOT Do

- Does not replace a WAF (Web Application Firewall). Use Cloudflare WAF or
  AWS Shield for network-layer protection alongside this library.
- Does not handle authentication or authorization. Hippocrates validates
  payload *structure* — not whether the user has permission to act.
- Does not protect GET endpoints automatically. The body validation layers
  (L4, L5) only run for methods with a body (POST, PUT, PATCH, DELETE).
  Protect GET endpoints with velocity/timing layers by wrapping them too.
- Does not persist violations across Redis restarts. A Redis flush clears
  all threat scores. This is acceptable — a fresh start is not a security hole.
