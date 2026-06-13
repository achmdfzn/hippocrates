---
name: hippocrates-skill
description: "Next.js App Router security middleware — Strict Stateful Defense Architecture. Protects APIs from autonomous AI agents, LLM-based attackers, and automated scripts via Redis-backed cumulative threat scoring with silent honeypot routing. WHEN: add security to Next.js API routes, protect from AI agents/LLM crawlers, implement rate limiting with Redis, detect automated API attacks, obfuscation/payload injection defense, Zero-Trust payload validation with Zod, honeypot/shadow-ban pattern for API security, prevent prompt injection attacks, block headless browser scrapers."
license: MIT
metadata:
  author: hippocrates
  version: "1.7.0"
---

# Hippocrates Skill

**hippocrates** is an NPM library (`hippocrates-middleware`) that wraps any Next.js App Router route handler with a **Strict Stateful Defense Architecture**.

The core loop: evaluate every incoming request against a cumulative Threat Score stored in Redis, and silently route high-score requests to a decoy generator instead of the real handler. The attacker always receives a `200 OK` — never a `403` or `429`.

## When to Use This Skill

- User wants to **add security** to a Next.js App Router API route
- User wants to **prevent automated AI agents / LLM crawlers** from consuming API resources
- User needs **Redis-backed rate limiting** with behavioral analysis
- User wants **Zero-Trust payload validation** (Zod `.strict()`) with vague error responses
- User wants **obfuscation detection** (Base64, Hex, URL-encoded payloads)
- User wants a **silent honeypot / shadow-ban** pattern instead of returning `403`/`429`
- User sees suspicious traffic from known agent User-Agents (`python-requests`, `curl`, `playwright`, etc.)

## Prerequisites

- **Next.js 14+** project with App Router
- **Redis** instance (Upstash recommended for Vercel/Edge deployments)
- **Zod** (peer dependency for schema validation)
- Node.js 18+

## Architecture Overview

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
   Timing, velocity, UA, headers — check + accumulate score
      │ score ≥ threshold?
      ├──YES──→ HONEYPOT
      │ (no)
      ▼
   Body parse → Post-body analyzers (L4, L5 + custom AnalyzerPlugin)
   Obfuscation scan, Zod validation, ML engine sidecar
      │ score ≥ threshold?
      ├──YES──→ HONEYPOT
      │ (no)
      ▼
   PASS → forward clean, validated request to actual handler
```

All state lives in Redis under the `hc:` namespace. No in-memory state.

## Quick Start

```typescript
import { NextRequest, NextResponse } from "next/server";
import { Redis } from "@upstash/redis";
import { withHippocrates, z } from "hippocrates-middleware";

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

// .strict() is MANDATORY — any extra field triggers the honeypot instantly
const Schema = z.object({
  userId: z.string().uuid(),
  action: z.enum(["read", "write"]),
}).strict();

async function handler(req: NextRequest): Promise<NextResponse> {
  // Body is guaranteed validated at this point
  const body = await req.json();
  return NextResponse.json({ success: true, received: body });
}

export const POST = withHippocrates(handler, Schema, redis);
```

## Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `preset` | `"strict" | "moderate" | "relaxed"` | — | One-liner tuning overrides all below |
| `threatScoreThreshold` | `number` | `65` | Score (0–100) that triggers honeypot. Lower = stricter |
| `velocityWindowMs` | `number` | `10_000` | Sliding window for velocity tracking |
| `velocityMaxRequests` | `number` | `15` | Max requests per IP per velocity window |
| `threatTtlSeconds` | `number` | `3_600` | How long flagged IPs stay flagged in Redis |
| `debugMode` | `boolean` | `false` | Verbose logging (dev only) |
| `decoyGenerator` | `function` | built-in | Custom decoy response generator |
| `scoring` | `Partial<ThreatScoringWeights>` | — | Per-layer scoring overrides |
| `plugins` | `AnalyzerPlugin[]` | — | Custom detection analyzers (v1.5) |
| `hooks` | `HippocratesHooks` | — | Event hooks for violation/pass/honeypot (v1.5) |
| `allowlist` | `{ ips: string[] }` | — | Exact + CIDR IP bypass (v1.6) |
| `bodyLimit` | `{ maxBytes, enabled }` | `{ maxBytes: 1MB, enabled: true }` | Payload size enforcement (v1.6) |
| `methodThresholds` | `Partial<Record<string, number>>` | — | Per-HTTP-method threat threshold overrides (v1.6) |
| `violationMessages` | `object` | — | Custom error messages per violation type (v1.6) |
| `statsTracker` | `StatsTracker` | — | In-memory request stats interface (v1.6) |

## Custom Analyzer Plugins (v1.5)

```typescript
const myAnalyzer: AnalyzerPlugin = {
  name: "custom_check",
  phase: "pre-body",      // "pre-body" | "post-body"
  priority: 50,           // Lower runs first (built-in: L1=10, L2=20, L3=30, L6=40)
  analyze(req, ctx) {
    if (req.headers.get("x-custom") === "bad") {
      return { score: 30, tags: ["custom:bad"] };
    }
    return { score: 0, tags: [] };
  },
};

export const POST = withHippocrates(handler, schema, redis, {
  plugins: [myAnalyzer],
});
```

## Event Hooks (v1.5)

```typescript
export const POST = withHippocrates(handler, schema, redis, {
  hooks: {
    onViolation: (event) => console.log("Violation:", event),
    onPass: (event) => /* forward to metrics */,
    onHoneypot: (event) => /* alert security team */,
  },
});
```

## Critical Invariants (NEVER Violate)

1. **Never return 403/429** — always route through `serveHoneypot()`. A `4xx` response tells the attacker what triggered detection.
2. **Never expose Zod error details** — the error message must be intentionally vague. E.g., `"Validation failed (2 constraints)"` — no field names, no types.
3. **Always use `.strict()`** on Zod schemas. Without it, unknown fields pass through silently.
4. **Last-resort catch must never leak internals** — always return `{ error: "Internal Server Error" }` with status 500.
5. **Config merging happens once** at HOF call time (`withHippocrates()`), not per request.
6. **Never use `Buffer.from()`** — breaks Edge Runtime. Use `btoa()` instead.

## ML Engine Plugin (v1.7)

Hippocrates ships with an optional Python sidecar for ML-based threat detection:

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

The sidecar analyzes each request for:
- **Prompt Injection** — DAN, jailbreak, system prompt hijack
- **Advanced Obfuscation** — Shannon entropy, encoding chains
- **Content Risk** — SQLi, XSS, path traversal, command injection

Start the sidecar: `docker compose up -d`

## Stats Tracker (v1.6)

```typescript
import { type StatsTracker } from "hippocrates-middleware";

const tracker: StatsTracker = {
  increment(counter) { /* forward to metrics */ },
  getStats() { return { ... }; },
  reset() {},
};

export const POST = withHippocrates(handler, schema, redis, {
  statsTracker: tracker,
});
```

Counters: `totalRequests`, `blockedByPreflight`, `blockedByTiming`, `blockedByVelocity`, `blockedByObfuscation`, `blockedBySchema`, `passedToHandler`, `honeypotServed`, `redisErrors`.

## Defense Layers Detail

### L-1 — IP Allowlist (v1.6)
Exact match + CIDR prefix (e.g. `10.0.0.0/8`). Trusted IPs bypass all checks entirely.

### L0 — Pre-flight Check
Looks up the IP's existing cumulative threat score in Redis. If ≥ threshold, instant honeypot.

### L1 — Timing Analysis
Detects sub-human request intervals (< 50ms). Autonomous agents generate requests faster than any human could manually type and submit.

### L2 — Velocity (Sliding Window)
Maintains a Redis list of timestamps per IP. Counts how many fall within `velocityWindowMs`. Capped at 500 entries via `ltrim`.

### L3 — User-Agent Fingerprinting
Checks UA header against curated patterns for HTTP libraries, LLM SDKs (Anthropic, OpenAI, LangChain, LlamaIndex, Gemini, Claude, etc.), and headless browsers.

### L4 — Obfuscation Detection
Recursively walks parsed payload and checks string values against Base64, Hex, URL-encoding, Unicode escape, and HTML entity patterns.

### L5 — Zod Zero-Trust Validation
Validates payload with Zod `.strict()`. Extra fields, wrong types, or coercion failures trigger instant max score.

### L6 — Header Anomaly Detection
Flags missing or wildcard Accept/Accept-Language/Accept-Encoding headers — signals non-browser HTTP clients.

## Redis Key Schema

| Key | Purpose | TTL |
|-----|---------|-----|
| `hc:s:{ip}` | Cumulative threat score (0–100) | `threatTtlSeconds` (default 3600s) |
| `hc:t:{ip}` | Request timestamp list (velocity) | `ceil(windowMs/1000) + 10s` |
| `hc:l:{ip}` | Last-seen timestamp (timing) | 300s (hardcoded) |

Stats are in-memory only (via `StatsTracker` interface) — not stored in Redis.

## User-Agent Detection Coverage

**HTTP libs:** python-requests, aiohttp, httpx, axios, node-fetch, got, curl, wget, java, go-http-client, ruby

**LLM / AI SDKs:** anthropic-sdk, claude, openai-node, openai-python, google-gemini, google-ai-generativelanguage, langchain, llamaindex, autogen, crewai, smolagents, agentops, cohere, mistral, together, groq, deepseek, dspy, semantic-kernel, haystack, copilot-github, huggingface

**Headless browsers:** headlesschrome, playwright, puppeteer, selenium, cypress, phantomjs

**Generic:** bot, spider, crawler, scraper

**2026 AI Agents:** claudebot, claude-user, claude-searchbot, claude-code, cursor, cursoragent, perplexitybot, githubcopilot, opencode, windsurf

*(40+ patterns total)*

## Honeypot Decoy Templates

Hippocrates ships with 4 rotating decoy response templates:
- **Template A**: Generic resource/data endpoint (`success`, `data`, `requestId`, `timestamp`)
- **Template B**: Auth/token endpoint (`accessToken`, `tokenType`, `expiresIn`, `scope`)
- **Template C**: Paginated list endpoint (`items[]`, `pagination`)
- **Template D**: Analytics/dashboard endpoint (`metrics[]`, `summary`, `period`)

## Development Commands

```bash
npm run build            # tsup → CJS + ESM + .d.ts
npm run dev              # Watch mode
npm run typecheck        # tsc --noEmit
npm run lint             # ESLint
npm test                 # Vitest (177 tests across 10 files)
npm run prepublishOnly   # typecheck + build (runs automatically on npm publish)

# Python ML engine (39 tests)
cd engine-python
pip install -r requirements.txt
pytest -v                # 31 analyzer tests + 8 API tests

# Full stack
docker compose up --build   # Redis + ML engine (health-checked)
npm test && cd engine-python && pytest -v   # All 216 tests
```

## Extending the Library

### New UA Pattern
Edit `AGENT_UA_PATTERNS` array in `src/engine/constants.ts`:
```typescript
/new-llm-framework\/[\d.]+/i,  // YourFramework HTTP client
```

### New Obfuscation Pattern
Edit `OBFUSCATION_PATTERNS` in `src/engine/constants.ts`:
```typescript
{ name: "double_encoding", pattern: /(?:%25[0-9a-fA-F]{2}){3,}/ },
```

### New Decoy Template
Edit `generateDecoyResponse()` in `src/system/honeypot.ts`. Increment slot count: `Math.floor(Math.random() * (N+1))`.

### New Detection Layer
1. Add analyzer function to `src/engine/analyzers.ts`
2. Add weight key to `ThreatScoringWeights` in `src/engine/types.ts`
3. Add default to `DEFAULT_WEIGHTS` in `src/engine/constants.ts`
4. Call analyzer inside `src/system/pipeline.ts` before body-parsing block (L4+L5)

## Pitfalls

- **Base64 regex min length is 24 chars** — lowering it causes false positives on UUIDs/tokens
- **`req.text()` consumes the body stream** — always re-serialize with `JSON.stringify(validatedBody)` on forwarded request
- **`ThreatScoreEngine` constructed once per HOF call** — NOT per request. Holds no per-request state.
- **Upstash vs ioredis API difference** — Upstash uses `{ ex: n }`, ioredis uses positional args. Use an adapter.
- **Redis circuit breaker** — after 3 consecutive Redis errors, all checks degrade to safe defaults (score=0, not excessive). Recovers automatically after 30s cooldown.
- **IPv6 normalization** is handled via `src/utils/ip.ts` — `::1` → `127.0.0.1`, `::ffff:x.x.x.x` → IPv4 extraction
