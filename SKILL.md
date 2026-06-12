---
name: hippocrates-skill
description: "Next.js App Router security middleware — Strict Stateful Defense Architecture. Protects APIs from autonomous AI agents, LLM-based attackers, and automated scripts via Redis-backed cumulative threat scoring with silent honeypot routing. WHEN: add security to Next.js API routes, protect from AI agents/LLM crawlers, implement rate limiting with Redis, detect automated API attacks, obfuscation/payload injection defense, Zero-Trust payload validation with Zod, honeypot/shadow-ban pattern for API security, prevent prompt injection attacks, block headless browser scrapers."
license: MIT
metadata:
  author: hippocrates
  version: "0.1.0"
---

# Hippocrates Skill

**hippocrates** is an NPM library (`hippocrates`) that wraps any Next.js App Router route handler with a **Strict Stateful Defense Architecture**.

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

## Quick Start

```typescript
import { NextRequest, NextResponse } from "next/server";
import { Redis } from "@upstash/redis";
import { withHippocrates, z } from "hippocrates";

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
| `threatScoreThreshold` | `number` | `65` | Score (0-100) that triggers honeypot. Lower = stricter |
| `velocityWindowMs` | `number` | `10_000` | Sliding window for velocity tracking |
| `velocityMaxRequests` | `number` | `15` | Max requests per IP per velocity window |
| `threatTtlSeconds` | `number` | `3_600` | How long flagged IPs stay flagged in Redis |
| `debugMode` | `boolean` | `false` | Verbose logging (dev only) |
| `decoyGenerator` | `function` | built-in | Custom decoy response generator |
| `scoring` | `Partial<ThreatScoringWeights>` | — | Per-layer scoring overrides |

## Critical Invariants (NEVER Violate)

1. **Never return 403/429** — always route through `serveHoneypot()`. A `4xx` response tells the attacker what triggered detection.
2. **Never expose Zod error details** — the error message must be intentionally vague. E.g., `"Validation failed (2 constraints)"` — no field names, no types.
3. **Always use `.strict()`** on Zod schemas. Without it, unknown fields pass through silently.
4. **Last-resort catch must never leak internals** — always return `{ error: "Internal Server Error" }` with status 500.
5. **Config merging happens once** at HOF call time (`withHippocrates()`), not per request.

## Defense Layers Detail

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

## Redis Key Schema

| Key | Purpose | TTL |
|-----|---------|-----|
| `hc:s:{ip}` | Cumulative threat score | `threatTtlSeconds` |
| `hc:t:{ip}` | Request timestamp list (velocity) | `velocityWindowMs + 10s` |
| `hc:l:{ip}` | Last-seen timestamp (timing) | 300s (hardcoded) |

## User-Agent Detection Coverage

**HTTP libs:** python-requests, aiohttp, httpx, axios, node-fetch, got, curl, wget, java, go-http-client, ruby

**LLM / AI SDKs:** anthropic-sdk, claude, openai-node, openai-python, google-gemini, google-ai-generativelanguage, langchain, llamaindex, autogen, crewai, smolagents, agentops, cohere, mistral, together, groq, deepseek, dspy, semantic-kernel, haystack, copilot-github, huggingface

**Headless browsers:** headlesschrome, playwright, puppeteer, selenium, cypress, phantomjs

**Generic:** bot, spider, crawler, scraper

## Honeypot Decoy Templates

Hippocrates ships with 4 rotating decoy response templates:
- **Template A**: Generic resource/data endpoint (`success`, `data`, `requestId`, `timestamp`)
- **Template B**: Auth/token endpoint (`accessToken`, `tokenType`, `expiresIn`, `scope`)
- **Template C**: Paginated list endpoint (`items[]`, `pagination`)
- **Template D**: Analytics/dashboard endpoint (`metrics[]`, `summary`, `period`)

## Development Commands

```bash
npm run build       # tsup → CJS + ESM + .d.ts
npm run dev         # Watch mode
npm run typecheck   # tsc --noEmit
npm run lint        # ESLint
npm test            # Vitest
```

## Extending the Library

### New UA Pattern
Edit `AGENT_UA_PATTERNS` array in `src/index.ts` §2:
```typescript
/new-llm-framework\/[\d.]+/i,  // YourFramework HTTP client
```

### New Obfuscation Pattern
Edit `OBFUSCATION_PATTERNS` in §2:
```typescript
{ name: "double_encoding", pattern: /(?:%25[0-9a-fA-F]{2}){3,}/ },
```

### New Decoy Template
Edit `generateDecoyResponse()` in §4. Increment slot count: `Math.floor(Math.random() * (N+1))`.

### New Detection Layer
1. Add analyzer method to `ThreatScoreEngine` (§3)
2. Add weight key to `ThreatScoringWeights` (§1)
3. Add default to `DEFAULT_WEIGHTS` (§2)
4. Call analyzer inside `withHippocrates()` (§7) before body-parsing block (L4+L5)

## Pitfalls

- **Base64 regex min length is 24 chars** — lowering it causes false positives on UUIDs/tokens
- **`req.text()` consumes the body stream** — always re-serialize with `JSON.stringify(validatedBody)` on forwarded request
- **`ThreatScoreEngine` constructed once per HOF call** — NOT per request. Holds no per-request state.
- **Upstash vs ioredis API difference** — Upstash uses `{ ex: n }`, ioredis uses positional args. Use an adapter.
- **IPv6 normalization** is handled via `src/utils/ip.ts` — `::1` → `127.0.0.1`, `::ffff:x.x.x.x` → IPv4 extraction
