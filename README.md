# Hippocrates

[![npm version](https://img.shields.io/npm/v/hippocrates-middleware)](https://www.npmjs.com/package/hippocrates-middleware)
[![CI](https://github.com/achmdfzn/hippocrates/actions/workflows/ci.yml/badge.svg)](https://github.com/achmdfzn/hippocrates/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/achmdfzn/hippocrates/branch/main/graph/badge.svg)](https://codecov.io/gh/achmdfzn/hippocrates)
[![License](https://img.shields.io/github/license/achmdfzn/hippocrates)](https://github.com/achmdfzn/hippocrates/blob/main/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/achmdfzn/hippocrates)](https://github.com/achmdfzn/hippocrates)

Next.js App Router security middleware that routes malicious requests to a decoy handler instead of blocking them. Uses Redis-backed cumulative threat scoring across six detection layers.

```
npm install hippocrates-middleware zod
```

---

## Contents

- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Tutorial](#tutorial)
- [Codebase Structure](#codebase-structure)
- [Pairing the Repo](#pairing-the-repo)
- [Defense Layers](#defense-layers)
- [Configuration](#configuration)
- [Plugin System](#plugin-system)
- [Event Hooks](#event-hooks)
- [Stats Tracking](#stats-tracking)
- [ML Engine (Python Sidecar)](#ml-engine-python-sidecar)
- [License](#license)

---

## How It Works

Every incoming request passes through detection layers. Each layer can add points to an IP's cumulative threat score stored in Redis. If the score crosses the threshold, the request is routed to a decoy generator instead of the real handler. The decoy returns a 200 OK with fake data. The caller never sees a 403 or 429 and gets no signal they were detected.

```
Incoming Request
      |
      v
 L-1  Allowlist? ---- YES --> Forward to handler (skip all checks)
      | NO
      v
 L0   Pre-flight score check ---- score >= threshold? ---- YES --> HONEYPOT (200 OK, fake data)
      | NO
      v
 Pre-body analyzers: L1 Timing, L2 Velocity, L3 UA, L4 Headers
      | score >= threshold?
      |-- YES --> HONEYPOT
      | NO
      v
 Body parsing + Post-body analyzers: L5 Obfuscation, L6 Schema
      | score >= threshold?
      |-- YES --> HONEYPOT
      | NO
      v
 Forward clean request to real handler
```

---

## Requirements

- Node.js >= 18
- Next.js >= 14 (peer dependency)
- Zod >= 3.22 (peer dependency)
- Redis client (Upstash, ioredis, or compatible)

---

## Tutorial

This tutorial walks through protecting a Next.js App Router endpoint from scratch.

### 1. Create or open a Next.js project

```bash
npx create-next-app@latest my-app --typescript
cd my-app
```

### 2. Install dependencies

```bash
npm install hippocrates-middleware zod
npm install @upstash/redis   # or your Redis client of choice
```

### 3. Set up a route

Create `app/api/users/route.ts`:

```typescript
import { NextRequest, NextResponse } from "next/server";
import { Redis } from "@upstash/redis";
import { withHippocrates, z } from "hippocrates-middleware";

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

// Schemas must use .strict() -- extra fields trigger a violation
const CreateUserSchema = z.object({
  name: z.string().min(1),
  email: z.string().email(),
}).strict();

async function handler(req: NextRequest): Promise<NextResponse> {
  const body = await req.json();
  // body is already validated by the middleware
  return NextResponse.json({ id: crypto.randomUUID(), ...body });
}

export const POST = withHippocrates(handler, CreateUserSchema, redis);
```

### 4. Add environment variables

Create `.env.local`:

```
UPSTASH_REDIS_REST_URL=https://your-redis-url.upstash.io
UPSTASH_REDIS_REST_TOKEN=your-token
```

### 5. Run

```bash
npm run dev
```

Send a valid request:

```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice", "email": "alice@example.com"}'
# Response: 200 OK with { id, name, email }
```

The middleware validates the body against the Zod schema. If the body is valid, it passes through to `handler`.

### 6. Trigger the honeypot

Send a request with extra fields:

```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{"name": "Alice", "email": "alice@example.com", "role": "admin"}'
```

The `.strict()` schema rejects unknown fields. The request is routed to the decoy generator and you receive a 200 OK with fake data.

Send too many requests from the same IP quickly, or use a tool with a suspicious User-Agent:

```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -H "User-Agent: python-requests/2.31.0" \
  -d '{"name": "Bob", "email": "bob@example.com"}'
```

The UA pattern `python-requests` triggers L3. Repeat this 10+ times within 10 seconds and L2 velocity tracking adds more points. Cross the threshold and you get the honeypot.

### 7. With custom configuration

```typescript
export const POST = withHippocrates(handler, CreateUserSchema, redis, {
  preset: "strict",
  allowlist: { ips: ["10.0.0.0/8", "127.0.0.1"] },
  bodyLimit: { maxBytes: 524288, enabled: true },
  scoring: {
    impossibleTiming: 35,
    suspiciousUserAgent: 25,
  },
  hooks: {
    onHoneypot: (event) => {
      console.log(`Honeypot served to ${event.ip}`);
    },
  },
});
```

---

## Codebase Structure

```
src/
  index.ts                     # Entry point -- withHippocrates() HOF, re-exports
  engine/
    types.ts                   # Type definitions (RedisClient, HippocratesConfig, etc.)
    constants.ts               # Default values, UA patterns, obfuscation patterns
    analyzers.ts               # Built-in analyzer plugin placeholders (L1-L6)
    threat-score-engine.ts     # Redis-backed scoring engine with circuit breaker
  system/
    pipeline.ts                # Request processing pipeline
    honeypot.ts                # Decoy response generator
    validator.ts               # Zod validation helpers (validatePayload, ensureStrict)
  plugins/
    ml-engine.ts               # Python sidecar AnalyzerPlugin
  utils/
    ip.ts                      # IPv6 normalization and client IP resolution
  __tests__/
    helpers.ts                 # Test mocks
    ip.test.ts                 # 30 tests
    threat-score-engine.test.ts # 45 tests
    validate-payload.test.ts   # 8 tests
    decoy.test.ts              # 11 tests
    with-hippocrates.test.ts   # 51 tests (integration)
    ensure-strict.test.ts      # 25 tests
    redis-degradation.test.ts  # 6 tests
    stats.test.ts              # 5 tests
    stats-integration.test.ts  # 13 tests
    ml-engine-integration.test.ts # 15 tests
engine-python/
  app/
    main.py                    # FastAPI application
    config.py                  # Environment-based settings
    models.py                  # Request/response models
    analyzers/                 # ML detection modules
      prompt_injection.py
      obfuscation_advanced.py
      content_risk.py
  tests/
    test_analyzers.py          # 31 tests
    test_api.py                # 8 tests
  Dockerfile
  requirements.txt
example/
  app/api/data/route.ts        # Reference implementation
```

---

## Pairing the Repo

```bash
git clone https://github.com/achmdfzn/hippocrates.git
cd hippocrates

npm install
npm run build
npm test                       # 209 tests
npm run typecheck              # tsc --noEmit, zero errors
npm run lint                   # ESLint, zero errors
```

To run the full stack with the Python ML engine:

```bash
# Requires: Docker, Python 3.12+
docker compose up -d           # Redis + ML engine
npm test                       # TS tests (209)
cd engine-python && pytest -v  # Python tests (39)
```

Development workflow:

```bash
npm run dev                    # tsup --watch (recompiles on source changes)
npm run test:watch             # Vitest watch (reruns tests on changes)
```

CI pipeline (GitHub Actions):

```
quality (Node 18/20/22): lint -> typecheck -> test -> build
docker:                        build ML engine image -> healthcheck
```

---

## Defense Layers

| Layer | Check | Points | Condition |
|-------|-------|--------|-----------|
| L-1 | IP allowlist | 0 (bypass all) | IP is in allowlist config |
| L0 | Pre-flight score | Instant honeypot | Existing Redis score >= threshold |
| L1 | Request timing | +25 | Interval < 50ms |
| L2 | Request velocity | +40 | Burst > 15 req / 10s window |
| L3 | User-Agent | +15 | Suspicious or missing UA |
| L4 | HTTP headers | +15 | Missing or wildcard Accept, etc. |
| L5 | Payload obfuscation | +100 | Base64, hex, URL encoding, Unicode |
| L6 | Zod schema | +100 | .strict() violation |

L5 and L6 push the score to 100 immediately on detection.

UA patterns (40+): LLM SDKs (anthropic-sdk, openai-node, langchain), HTTP libs (python-requests, curl, axios), browser automation (playwright, puppeteer), 2026 AI agents (claude, cursor, perplexitybot, opencode).

Obfuscation patterns: Base64 (>=24 chars), hex encoding (>=16 chars), URL encoding (5+ consecutive), Unicode escapes, HTML entities.

---

## Configuration

```typescript
interface HippocratesConfig {
  preset?: "strict" | "moderate" | "relaxed";
  threatScoreThreshold?: number;          // Default: 65
  velocityWindowMs?: number;              // Default: 10000
  velocityMaxRequests?: number;           // Default: 15
  threatTtlSeconds?: number;              // Default: 3600
  scoring?: Partial<ThreatScoringWeights>;
  decoyGenerator?: (req: NextRequest) => Record<string, unknown>;
  debugMode?: boolean;                    // Default: false
  plugins?: AnalyzerPlugin[];
  hooks?: HippocratesHooks;
  allowlist?: { ips: string[] };
  bodyLimit?: { maxBytes: number; enabled: boolean };
  methodThresholds?: Partial<Record<string, number>>;
  violationMessages?: Record<string, (violation: string) => Record<string, unknown>>;
  statsTracker?: StatsTracker;
}
```

Preset values:

| Preset | Threshold | Velocity Max | Window |
|--------|-----------|-------------|--------|
| strict | 40 | 10 req | 10s |
| moderate | 65 | 15 req | 10s |
| relaxed | 80 | 30 req | 30s |

Redis key layout:

| Key | Purpose | TTL |
|-----|---------|-----|
| `hc:s:{ip}` | Threat score (0-100) | `threatTtlSeconds` |
| `hc:t:{ip}` | Request timestamps (velocity) | `windowMs + 10s` |
| `hc:l:{ip}` | Last-seen timestamp (timing) | 300s |

Custom violation messages:

```typescript
export const POST = withHippocrates(handler, schema, redis, {
  violationMessages: {
    obfuscation: (violation) => ({
      error: "invalid_payload_format",
      code: "OBFUSCATION_DETECTED",
    }),
    schema: (violation) => ({
      error: "validation_failed",
    }),
  },
});
```

The key is the violation type prefix (obfuscation, schema, ua, velocity, timing, header). The function receives the full violation tag string and returns an object that merges with the decoy response.

---

## Plugin System

Implement custom detection logic with the AnalyzerPlugin interface:

```typescript
import { type AnalyzerPlugin } from "hippocrates-middleware";

const geoBlock: AnalyzerPlugin = {
  name: "geo_block",
  phase: "pre-body",      // "pre-body" | "post-body"
  priority: 50,           // Lower runs first. Default: 100
  analyze(req, ctx) {
    const country = req.headers.get("x-country");
    if (country === "blocked") {
      return { score: 50, tags: ["geo:blocked"] };
    }
    return { score: 0, tags: [] };
  },
};

export const POST = withHippocrates(handler, schema, redis, {
  plugins: [geoBlock],
});
```

Plugins sorted by priority ascending within each phase. Same priority preserves registration order.

Additional use-case examples:

**Rate-limit mimic — add score on high request frequency without blocking:**

```typescript
const rateMimic: AnalyzerPlugin = {
  name: "rate_mimic",
  phase: "pre-body",
  priority: 90,
  analyze(req, ctx) {
    const freq = parseInt(req.headers.get("x-request-frequency") ?? "0");
    if (freq > 100) return { score: 30, tags: ["rate:high"] };
    if (freq > 50)  return { score: 15, tags: ["rate:medium"] };
    return { score: 0, tags: [] };
  },
};
```

**Known scraper detection — match URL patterns for specific routes:**

```typescript
const scraperDetect: AnalyzerPlugin = {
  name: "scraper_detect",
  phase: "pre-body",
  priority: 40,
  analyze(req, ctx) {
    const url = req.nextUrl.pathname;
    const sensitivePaths = ["/api/users", "/api/orders", "/api/admin"];
    if (sensitivePaths.some((p) => url.startsWith(p))) {
      const ua = req.headers.get("user-agent") ?? "";
      if (ua.includes("python-requests") || ua.includes("axios")) {
        return { score: 25, tags: ["scraper:sensitive"] };
      }
    }
    return { score: 0, tags: [] };
  },
};
```

---

## Event Hooks

```typescript
export const POST = withHippocrates(handler, schema, redis, {
  hooks: {
    onViolation: (event) => {
      console.log(`${event.ip} - ${event.violations}`);
    },
    onPass: (event) => {
      metrics.recordPass(event.ip, event.score);
    },
    onHoneypot: (event) => {
      alertService.notify(`Honeypot served to ${event.ip}`);
    },
  },
});
```

---

## Stats Tracking

In-memory counters accessible via `ThreatScoreEngine.getStats()`. Pass a custom `StatsTracker` for external persistence:

```typescript
import { type StatsTracker } from "hippocrates-middleware";

const tracker: StatsTracker = {
  increment(counter) {
    console.log(`Event: ${counter}`);
  },
  getStats() {
    return { totalRequests: 0, blockedByPreflight: 0, /* ... */ };
  },
  reset() {},
};
```

Warning: In serverless environments (Vercel Edge, AWS Lambda), each cold start creates a fresh `ThreatScoreEngine` instance -- stats reset on every invocation. Use a custom `StatsTracker` that persists to an external store for production monitoring.

Available counters: `totalRequests`, `blockedByPreflight`, `blockedByTiming`, `blockedByVelocity`, `blockedByObfuscation`, `blockedBySchema`, `passedToHandler`, `honeypotServed`, `redisErrors`.

Redis-backed StatsTracker example:

```typescript
import { type StatsTracker } from "hippocrates-middleware";
import { Redis } from "@upstash/redis";

function createRedisStatsTracker(redis: Redis): StatsTracker {
  const key = "hc:stats";

  return {
    increment(counter) {
      redis.hincrby(key, counter, 1).catch(() => {});
    },
    async getStats() {
      const data = await redis.hgetall<Record<string, string>>(key);
      if (!data) {
        return {
          totalRequests: 0, blockedByPreflight: 0, blockedByTiming: 0,
          blockedByVelocity: 0, blockedByObfuscation: 0, blockedBySchema: 0,
          passedToHandler: 0, honeypotServed: 0, redisErrors: 0,
        };
      }
      return Object.fromEntries(
        Object.entries(data).map(([k, v]) => [k, Number(v)]),
      ) as SecurityStats;
    },
    reset() {
      redis.del(key).catch(() => {});
    },
  };
}
```

Pass it to `withHippocrates` to persist stats across cold starts:

```typescript
export const POST = withHippocrates(handler, schema, redis, {
  statsTracker: createRedisStatsTracker(redis),
});
```

---

## ML Engine (Python Sidecar)

Optional ML-based detection: prompt injection, advanced obfuscation, content risk scoring (SQLi, XSS, path traversal, command injection). Runs in a Python FastAPI sidecar.

```bash
docker compose up -d
```

```typescript
import { mlEnginePlugin } from "hippocrates-middleware";

export const POST = withHippocrates(handler, schema, redis, {
  plugins: [mlEnginePlugin({
    baseUrl: "http://ml-engine:8000",
    timeoutMs: 3000,
    minScoreThreshold: 10,
  })],
});
```

If the ML engine is unreachable, it returns score 0 with a `ml-engine-unreachable` tag. The plugin has its own circuit breaker: 3 consecutive failures trip a 30s cooldown.

ML engine config options:

| Option | Default | Description |
|--------|---------|-------------|
| `baseUrl` | `http://localhost:8000` | ML engine endpoint |
| `timeoutMs` | `3000` | Request timeout |
| `minScoreThreshold` | `10` | Minimum ML score to contribute |
| `maxRetries` | `1` | Retries before degrading |
| `circuitBreakerCooldownMs` | `30000` | Cooldown after max failures |
| `maxConsecutiveFailures` | `3` | Failures before circuit trips |

---

## License

MIT (c) achmdfzn
