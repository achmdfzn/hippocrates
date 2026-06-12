# HIPPOCRATES KNOWLEDGE BASE

**Generated:** 2026-06-12
**Stack:** TypeScript, Next.js App Router, Redis (Upstash/ioredis), Zod, tsup, Vitest

## OVERVIEW

Next.js App Router security middleware library (NPM: `hippocrates`). Wraps route handlers with Redis-backed cumulative threat scoring. Silently routes high-score requests to a decoy honeypot (200 OK with fake data) instead of the real handler.

## STRUCTURE

```
hippocrates/
├── src/
│   ├── index.ts          # Main library (1026 lines, single entry point)
│   ├── utils/
│   │   └── ip.ts         # IPv6 normalization utility
│   └── __tests__/
│       ├── helpers.ts                    # Test mocks (Redis, NextRequest, NextResponse)
│       ├── ip.test.ts                    # 29 tests (IPv6 normalization)
│       ├── threat-score-engine.test.ts   # 35 tests
│       ├── validate-payload.test.ts      # 7 tests
│       ├── decoy.test.ts                 # 9 tests
│       ├── with-hippocrates.test.ts      # 21 tests
│       └── ensure-strict.test.ts         # 14 tests (recursive .strict())
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
| Core logic (all layers) | `src/index.ts` | 8 sections (§1-§8), 1026 lines |
| IPv6 normalization | `src/utils/ip.ts` | `normalizeIp()`, `resolveClientIp()` |
| Integration tests | `src/__tests__/with-hippocrates.test.ts` | 21 tests, covers all layers |
| Unit tests (engine) | `src/__tests__/threat-score-engine.test.ts` | 35 tests (includes L6 header tests) |
| Decoy/honeypot tests | `src/__tests__/decoy.test.ts` | 9 tests |
| Validator tests | `src/__tests__/validate-payload.test.ts` | 7 tests |
| ensureStrict tests | `src/__tests__/ensure-strict.test.ts` | 14 tests (recursive .strict()) |
| IPv6 normalization tests | `src/__tests__/ip.test.ts` | 29 tests |
| Example consumer | `example/app/api/data/route.ts` | Reference impl |
| CI pipeline | `.github/workflows/ci.yml` | Node 18/20/22 matrix |
| Skill definition | `SKILL.md` | Loadable by task agents |
| Orientation | `CLAUDE.md` | Onboarding + invariants |

## src/index.ts SECTION MAP

| § | Content | Lines | Key Exports |
|---|---------|-------|-------------|
| §1 | Type definitions | 31–139 | `RedisClient`, `HippocratesConfig`, `ThreatScoringWeights`, `AppRouteHandler`, `ValidationResult` |
| §2 | Constants & defaults | 140–301 | `DEFAULTS`, `DEFAULT_WEIGHTS`, `AGENT_UA_PATTERNS`, `OBFUSCATION_PATTERNS`, `MIN_HUMAN_INTERVAL_MS`, `HEADER_ANOMALY_PATTERNS` |
| §3 | ThreatScoreEngine | 302–510 | `getScore()`, `addScore()`, `analyzeRequestTiming()`, `analyzeVelocity()`, `analyzeUserAgent()`, `detectObfuscation()`, `analyzeHeaders()` |
| §4 | Decoy generator | 511–621 | `generateDecoyResponse()` — 4 rotating templates |
| §5 | Honeypot response | 623–669 | `serveHoneypot()` — builds fake 200 OK |
| §6 | Zod validator + ensureStrict | 671–802 | `validatePayload<T>()`, `ensureStrict<T>()` |
| §7 | withHippocrates HOF | 804–1017 | `withHippocrates()` — primary export, orchestrates all layers |
| §8 | Re-exports | 1019–1026 | `z` (Zod), `ZodSchema` type |

## CONVENTIONS

- **Single-file library** until ~1200 lines. Do NOT split unless exceeded.
- **8 sections** clearly marked with `§` comments in `src/index.ts`. Edit in the correct section.
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
npm test               # Vitest (115 tests across 6 files)
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
