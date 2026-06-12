# CLAUDE.md — hippocrates

Project orientation file for Claude Code and new contributors.
Read this before touching any file in this repo.

---

## What This Project Is

`hippocrates` is a Next.js App Router security middleware library published to NPM.
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
│   ├── index.ts                    # Entry point + HOF (221 lines, re-exports all modules)
│   ├── engine/
│   │   ├── types.ts                # Type definitions (279 lines)
│   │   ├── constants.ts            # Defaults, UA patterns, obfuscation patterns (199 lines)
│   │   ├── analyzers.ts            # Individual layer analyzers (97 lines)
│   │   └── threat-score-engine.ts  # ThreatScoreEngine class (306 lines)
│   ├── system/
│   │   ├── honeypot.ts             # Decoy, honeypot, stats, Redis degradation (152 lines)
│   │   ├── pipeline.ts             # Pipeline orchestration (327 lines)
│   │   └── validator.ts            # Zod validatePayload + ensureStrict (174 lines)
│   ├── utils/
│   │   └── ip.ts                   # IPv6 normalization (90 lines)
│   └── __tests__/
│       ├── helpers.ts                          # Test mocks (Redis, NextRequest, NextResponse)
│       ├── ip.test.ts                          # 29 tests (IPv6 normalization)
│       ├── threat-score-engine.test.ts          # 35 tests
│       ├── validate-payload.test.ts             # 7 tests
│       ├── decoy.test.ts                       # 9 tests
│       ├── with-hippocrates.test.ts             # 30 tests
│       ├── ensure-strict.test.ts                # 22 tests (recursive .strict())
│       ├── redis-degradation.test.ts            # 6 tests (Redis fallback/circuit breaker)
│       └── stats.test.ts                       # 5 tests (request statistics)
├── example/
│   └── app/api/data/route.ts  # Reference implementation
├── .github/workflows/ci.yml   # GitHub Actions (lint → typecheck → test → build)
├── eslint.config.mjs          # ESLint flat config v10
├── package.json               # tsup build, peer deps (next, zod)
├── tsconfig.json              # strict + exactOptionalPropertyTypes + noUncheckedIndexedAccess
├── vitest.config.ts           # Vitest config (globals: true)
├── SKILL.md                   # Loadable skill definition for OpenCode agents
├── AGENTS.md                  # Hierarchical knowledge base
├── CLAUDE.md                  # This file
├── README.md                  # Public-facing documentation
├── LICENSE                    # MIT
└── .gitignore
```

The library is modular but designed so that consumers import everything from a single
entry point (`hippocrates` / `src/index.ts`). No internal imports needed at the
consumer level. Modules are separated by concern:
- **`engine/`** — type definitions, constants, per-layer analyzers, and the scoring engine
- **`system/`** — pipeline orchestration, honeypot/decoys, validation, stats, and Redis degradation
- **`utils/`** — IPv6 normalization utility

---

## Architecture Mental Model

```
Incoming Request
      │
      ▼
   L0: Pre-flight score check ──── score ≥ threshold? ──→ HONEYPOT (200 OK + fake data)
      │ (no)
      ▼
   L1: Timing analysis ──── interval < 50ms? ──→ +25 pts
      │
      ▼
   L2: Velocity check ──── req count > max in window? ──→ +40 pts
      │
      ▼
   L3: User-Agent analysis ──── known agent UA? ──→ +15 pts
      │
      ▼
   L4: Obfuscation scan ──── Base64/Hex in payload? ──→ +100 pts (instant max)
      │
      ▼
   L5: Zod .strict() validation ──── schema violation? ──→ +100 pts (instant max)
      │
      ▼
   Score gate ──── score ≥ threshold? ──→ HONEYPOT (200 OK + fake data)
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
| Types | `src/engine/types.ts` | `RedisClient`, `HippocratesConfig`, `ThreatScoringWeights`, `AppRouteHandler`, `ValidationResult` |
| Constants | `src/engine/constants.ts` | `DEFAULTS`, `DEFAULT_WEIGHTS`, `AGENT_UA_PATTERNS` (35+ entries), `OBFUSCATION_PATTERNS` (5), `HEADER_ANOMALY_PATTERNS` (4) |
| Analyzers | `src/engine/analyzers.ts` | `analyzeRequestTiming()`, `analyzeVelocity()`, `analyzeUserAgent()`, `detectObfuscation()`, `analyzeHeaders()` — pure functions, no Redis |
| Engine | `src/engine/threat-score-engine.ts` | `ThreatScoreEngine` class — `getScore()`, `addScore()`, orchestrates analyzers with Redis |
| Honeypot | `src/system/honeypot.ts` | `generateDecoyResponse()` (4 templates), `serveHoneypot()`, `getStats()`, `resetStats()`, Redis degradation handling |
| Pipeline | `src/system/pipeline.ts` | Pipeline orchestration — runs L0–L6 analyzers, builds `cleanReq`, manages `requestId` |
| Validator | `src/system/validator.ts` | `validatePayload<T>()`, `ensureStrict<T>()` — Zod wrapper with vague errors + recursive `.strict()` |
| Index | `src/index.ts` | Public API entry point — `withHippocrates()` HOF, `ensureStrict()`, `validatePayload()`, re-exports |

---

## Development Commands

```bash
npm run build          # tsup → dist/ (CJS + ESM + .d.ts)
npm run dev            # tsup --watch
npm run typecheck      # tsc --noEmit
npm run lint           # ESLint flat config v10 (eslint.config.mjs)
npm test               # Vitest — 143 tests across 8 files
npm run test:watch     # Vitest watch mode
npm run prepublishOnly # typecheck + build
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

### Adding a new User-Agent pattern (most common task)

Edit `AGENT_UA_PATTERNS` in `src/engine/constants.ts`. Always use
`ReadonlyArray<RegExp>`. Add a comment explaining what the pattern targets.

```typescript
// In AGENT_UA_PATTERNS array:
/new-llm-framework\/[\d.]+/i,   // YourFramework HTTP client
```

Prefer specific version-aware patterns (`/framework\/[\d.]+/i`) over
broad keyword matches (`/framework/i`) to reduce false positives.

The array currently has 35+ entries (see AGENTS.md for complete list).

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

### Adding a new detection layer (e.g., L6: header pattern analysis)

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
| `hc:stats:requests` | Total request counter (atomic incr) | Persistent |
| `hc:stats:honeypot` | Honeypot trigger counter | Persistent |
| `hc:stats:scores` | Score distribution histogram | Persistent |

The `hc:t:{ip}` key uses a Redis list capped at 500 entries via `ltrim`.
Never change this cap without considering Upstash/Redis memory limits.

`hc:stats:*` keys are only created when `enableStats: true` is set in config.
They use Redis `INCR` for atomic counters and are not scoped per IP.

---

## Internal Headers Set by the Middleware

When a request passes all layers and is forwarded to the real handler,
Hippocrates injects two internal headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `x-hippocrates-score` | Integer string, e.g. `"12"` | Threat score for audit logging |
| `x-hippocrates-clean` | `"1"` | Signals the request passed all checks |
| `x-hippocrates-request-id` | UUID string | Unique request identifier for log correlation |

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

---

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
