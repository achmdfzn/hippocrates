# HIPPOCRATES KNOWLEDGE BASE

**Generated:** 2026-06-12
**Stack:** TypeScript, Next.js App Router, Redis (Upstash/ioredis), Zod, tsup, Vitest

## OVERVIEW

Next.js App Router security middleware library (NPM: `hippocrates`). Wraps route handlers with Redis-backed cumulative threat scoring. Silently routes high-score requests to a decoy honeypot (200 OK with fake data) instead of the real handler.

## STRUCTURE

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
├── .gitignore
├── LICENSE                    # MIT
├── SKILL.md                   # Loadable skill definition for OpenCode agents
├── AGENTS.md                  # This file
├── CLAUDE.md                  # Project orientation
└── README.md                  # Public docs
```

## WHERE TO LOOK

| Task | Location | Notes |
|------|----------|-------|
| Entry point + HOF | `src/index.ts` | `withHippocrates()` — primary export, ~221 lines |
| Type definitions | `src/engine/types.ts` | `RedisClient`, `HippocratesConfig`, `ThreatScoringWeights` |
| Constants & defaults | `src/engine/constants.ts` | `DEFAULTS`, `DEFAULT_WEIGHTS`, `AGENT_UA_PATTERNS` |
| Per-layer analyzers | `src/engine/analyzers.ts` | Pure functions: timing, velocity, UA, obfuscation, headers |
| ThreatScoreEngine | `src/engine/threat-score-engine.ts` | Redis-integrated scoring (get/add score) |
| Pipeline orchestration | `src/system/pipeline.ts` | Runs L0–L6, builds cleanReq, manages requestId |
| Honeypot + decoy | `src/system/honeypot.ts` | `generateDecoyResponse()`, `serveHoneypot()`, stats, Redis degradation |
| Zod validator | `src/system/validator.ts` | `validatePayload<T>()`, `ensureStrict<T>()` |
| IPv6 normalization | `src/utils/ip.ts` | `normalizeIp()`, `resolveClientIp()` |
| Integration tests | `src/__tests__/with-hippocrates.test.ts` | 30 tests, covers all layers |
| Unit tests (engine) | `src/__tests__/threat-score-engine.test.ts` | 35 tests (includes L6 header tests) |
| Decoy/honeypot tests | `src/__tests__/decoy.test.ts` | 9 tests |
| Validator tests | `src/__tests__/validate-payload.test.ts` | 7 tests |
| ensureStrict tests | `src/__tests__/ensure-strict.test.ts` | 22 tests (recursive .strict()) |
| Redis degradation tests | `src/__tests__/redis-degradation.test.ts` | 6 tests (Redis fallback, circuit breaker) |
| Stats tests | `src/__tests__/stats.test.ts` | 5 tests (request counts, score histograms) |
| IPv6 normalization tests | `src/__tests__/ip.test.ts` | 29 tests |
| Example consumer | `example/app/api/data/route.ts` | Reference impl |
| CI pipeline | `.github/workflows/ci.yml` | Node 18/20/22 matrix |
| Skill definition | `SKILL.md` | Loadable by task agents |
| Orientation | `CLAUDE.md` | Onboarding + invariants |

## MODULE MAP

| Module | File | Lines | Key Exports |
|--------|------|:-----:|-------------|
| Types | `src/engine/types.ts` | 279 | `RedisClient`, `HippocratesConfig`, `ThreatScoringWeights`, `AppRouteHandler`, `ValidationResult` |
| Constants | `src/engine/constants.ts` | 199 | `DEFAULTS`, `DEFAULT_WEIGHTS`, `AGENT_UA_PATTERNS`, `OBFUSCATION_PATTERNS`, `HEADER_ANOMALY_PATTERNS` |
| Analyzers | `src/engine/analyzers.ts` | 97 | `analyzeRequestTiming()`, `analyzeVelocity()`, `analyzeUserAgent()`, `detectObfuscation()`, `analyzeHeaders()` |
| Engine | `src/engine/threat-score-engine.ts` | 306 | `ThreatScoreEngine` — `getScore()`, `addScore()`, `calculateScore()` |
| Honeypot | `src/system/honeypot.ts` | 152 | `generateDecoyResponse()` (4 templates), `serveHoneypot()`, `getStats()`, `resetStats()` |
| Pipeline | `src/system/pipeline.ts` | 327 | Pipeline orchestration — runs L0–L6 analyzers, builds `cleanReq` |
| Validator | `src/system/validator.ts` | 174 | `validatePayload<T>()`, `ensureStrict<T>()` |
| Index | `src/index.ts` | 221 | `withHippocrates()`, `ensureStrict()`, `validatePayload()`, re-exports |

## CONVENTIONS
- **Aggressive TypeScript**: `strict`, `exactOptionalPropertyTypes`, `noUncheckedIndexedAccess`, `noImplicitReturns`.
- **ValidationResult** uses `ok: true/false` (NOT `success`) to avoid collision with API response shapes.
- **Generic constraint**: `T extends Record<string, unknown>` for Zod schema type param.
- **`/* @internal */` exports** for testing only — documented with `@internal` JSDoc.
- **Config merging once** at HOF call time, not per request.
- **Redis keys**: `hc:{type}:{ip}` namespace, short keys (Upstash tier charges by key size).
- **Velocity list** capped at 500 entries via `ltrim`.
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

## CRITICAL INVARIANTS

1. Zod schemas MUST use `.strict()` — otherwise L5 is effectively disabled.
2. Error messages leak schema structure — always generic count-only format.
3. `content-length` header MUST be deleted on forwarded requests (stale after re-serialization).
4. Internal headers `x-hippocrates-score` and `x-hippocrates-clean` MUST be stripped before forwarding to third-party services.
5. IPv6 normalization is handled via `resolveClientIp()` from `src/utils/ip.ts` — `::1` → `127.0.0.1`, `::ffff:x.x.x.x` → IPv4.

## COMMANDS

```bash
npm run build          # tsup → dist/ (CJS + ESM + .d.ts)
npm run dev            # tsup --watch
npm run typecheck      # tsc --noEmit
npm run lint           # ESLint flat config
npm test               # Vitest (143 tests across 8 files)
npm run test:watch     # Vitest watch mode
npm run prepublishOnly # typecheck + build
```

## PITFALLS & GOTCHAS

- **`req.text()` consumes body** — forward `JSON.stringify(validatedBody)` on clean request.
- **Upstash vs ioredis** — `set()` options differ. `RedisClient` interface uses Upstash-style `{ ex: n }`.
- **Debug logs are sync** — don't rely on log order in serverless environments. Correlate by `requestId`.
- **Velocity list never explicitly deleted** — expires via TTL naturally.
- **`::1` and `127.0.0.1` are now normalized** to the same key (via `src/utils/ip.ts`).
- **dist/ is never committed** — generated on `prepublishOnly`.
