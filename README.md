<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://github.com/user-attachments/assets/6e5b3fa5-d7e2-44bb-849d-7ea79b5d95f7">
    <img alt="Hippocrates" src="https://github.com/user-attachments/assets/6e5b3fa5-d7e2-44bb-849d-7ea79b5d95f7" width="140">
  </picture>
  <br/>
  <em>First, do no harm — to your API.</em>
</p>

<h1 align="center">🩺 Hippocrates</h1>

<p align="center">
  <strong>Next.js App Router Security Middleware</strong><br/>
  The first API security library that <strong>doesn't fight back</strong>.<br/>
  It just nods, smiles, and feeds attackers convincing fake data.
</p>

<br/>

<p align="center">
  <a href="https://www.npmjs.com/package/hippocrates">
    <img src="https://img.shields.io/npm/v/hippocrates?style=flat-square&logo=npm&color=%23CB3837" alt="npm version"/>
  </a>
  <a href="https://www.npmjs.com/package/hippocrates">
    <img src="https://img.shields.io/npm/dm/hippocrates?style=flat-square&logo=npm&color=%23CB3837" alt="npm downloads"/>
  </a>
  <a href="https://github.com/achmdfzn/hippocrates/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/achmdfzn/hippocrates?style=flat-square&color=%234FC921" alt="MIT License"/>
  </a>
  <a href="https://www.typescriptlang.org/">
    <img src="https://img.shields.io/badge/TypeScript-5.4%2B-3178C6?style=flat-square&logo=typescript" alt="TypeScript"/>
  </a>
  <a href="https://nextjs.org/">
    <img src="https://img.shields.io/badge/Next.js-14%2B-000000?style=flat-square&logo=next.js" alt="Next.js"/>
  </a>
  <a href="https://github.com/achmdfzn/hippocrates/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/achmdfzn/hippocrates/ci.yml?style=flat-square&logo=github&label=CI" alt="CI"/>
  </a>
  <a href="https://coveralls.io/github/achmdfzn/hippocrates">
    <img src="https://img.shields.io/badge/coverage-95%25-brightgreen?style=flat-square" alt="Coverage"/>
  </a>
  <a href="https://github.com/achmdfzn/hippocrates/stargazers">
    <img src="https://img.shields.io/github/stars/achmdfzn/hippocrates?style=flat-square&logo=github&color=%23FFD700" alt="Stars"/>
  </a>
  <a href="https://twitter.com/intent/tweet?text=Hippocrates%20-%20Next.js%20security%20middleware%20that%20silently%20destroys%20AI%20agents%20%F0%9F%A9%BA&url=https://github.com/achmdfzn/hippocrates">
    <img src="https://img.shields.io/badge/share%20on-X-1DA1F2?style=flat-square&logo=x" alt="Share on X"/>
  </a>
</p>

<br/>

<blockquote>
  <strong>⚠️ Traditional API security is broken.</strong> Rate limiting tells attackers to slow down. WAF blocks tell them to rotate IPs. Every <code>403</code> and <code>429</code> is feedback — making AI agents <em>smarter</em>.<br/><br/>
  <strong>Hippocrates flips the script.</strong> Every detected threat gets a convincing <code>200 OK</code> with realistic fake data. The attacker wastes compute, burns token budgets, and their agentic pipelines fail silently — never knowing they've been caught.
</blockquote>

<p align="center">
  <a href="#-the-problem">🔥 The Problem</a> •
  <a href="#-quick-start">🚀 Quick Start</a> •
  <a href="#-defense-layers">⚔️ Defense Layers</a> •
  <a href="#-comparison">📊 Comparison</a> •
  <a href="#-api-reference">🔧 API</a> •
  <a href="#-anatomy-of-a-honeypot">🕳️ Anatomy</a>
</p>

---

## 🔥 The Problem

**Your API has already been breached — you just served the attacker successfully.**

Modern API threats aren't human. Autonomous AI agents are relentless, adaptive, and they never sleep:

<div align="center">

| Capability | Impact | How Hippocrates Fights It |
|:-----------|:-------|:-------------------------|
| **10,000+ req/min** from a single IP | Saturates infra, spikes cloud bills | 🎭 Silently routes to honeypot |
| **Probes schema boundaries** systematically | Discovers hidden endpoints | 🧱 Zero-Trust `.strict()` layers |
| **Injects obfuscated payloads** | Bypasses WAF keyword filters | 🔍 Recursive base64/hex scanner |
| **Adapts in real-time** from errors | Evolves attack strategy after every `4xx` | 🫥 No `4xx` ever — no feedback loop |
| **Chains API calls** agentically | Correlates data across endpoints | 💀 Breaks the chain silently |

</div>

### Why Everything Else Fails

<div align="center">

| Approach | The Problem | Why |
|:---------|:-----------|:----|
| **Rate limiting** (`429`) | Feedback | Tells attacker to slow down. They do. Then resume. |
| **WAF blocks** (`403`) | Feedback | Tells attacker to rotate IP. They do. You chase. |
| **API keys** | Credential loss | Keys leak in env files, commits, logs. Game over. |
| **Stateless validation** | Amnesia | Every request is a fresh start. No memory. No pattern. |

</div>

---

## 🩺 The Hippocrates Way

Instead of blocking, we **deceive**. Instead of fighting, we **fatigue**. The attacker spends compute processing data that doesn't exist — and never realizes it.

```
Incoming Request
      │
      ▼
┌─────────────────┐
│  L-1  Allowlist?│──YES──► Forward to handler (skip all checks)
└────────┬────────┘
         │ NO
         ▼
┌─────────────────┐     ┌──────────────────────────────┐
│  L0  Pre-flight │────►│  Existing score ≥ threshold? │──YES──►🎭 HONEYPOT
└────────┬────────┘     │  (remembered from Redis)     │        200 OK (fake)
         │ NO           └──────────────────────────────┘
         ▼
┌──────────────────────────────────────────────────────┐
│  L1  Timing        L2  Velocity        L3  UA        │
│  L6  Headers       (pre-body analyzers)              │
└───────────────────────┬──────────────────────────────┘
                        │ score ≥ threshold?
                        ├──YES──►🎭 HONEYPOT
                        │ NO
                        ▼
┌──────────────────────────────────────────────────────┐
│  L4  Obfuscation    L5  Schema  (body analyzers)     │
└───────────────────────┬──────────────────────────────┘
                        │ score ≥ threshold?
                        ├──YES──►🎭 HONEYPOT
                        │ NO
                        ▼
              ✅ Forward to real handler
                 (clean, validated request)
```

---

## ✨ Features at a Glance

| Feature | What It Does |
|---------|-------------|
| 🫥 **Silent Honeypot** | `200 OK` with fake data — zero signal to the attacker |
| 🧠 **Stateful Threat Scoring** | Redis-backed cumulative scores persist across requests |
| ⚡ **6 Defense Layers** | Timing, velocity, UA, obfuscation, schema, headers |
| 🚀 **Edge-Ready** | Works on Vercel Edge Runtime, Node.js — zero `Buffer` usage |
| 🔒 **Zero-Trust Validation** | Recursive `.strict()` on every nested Zod type |
| 🤖 **AI Agent Detection** | 40+ patterns: OpenAI, Anthropic, LangChain, Playwright, 2026 agents |
| 📪 **No Data Leakage** | Error messages intentionally vague — no schema details exposed |
| 🛡️ **IP Allowlist** | Exact match + CIDR prefix for trusted IPs |
| ⚙️ **Config Presets** | `strict`, `moderate`, `relaxed` — one-liner tuning |
| 🧩 **Plugin System** | Custom AnalyzerPlugin for any detection logic (v1.5) |
| 🔔 **Event Hooks** | Monitor violations, passes, honeypot events (v1.5) |
| 📊 **Stats Tracking** | In-memory counters via `StatsTracker` interface (v1.6) |
| 🤖 **ML Engine** | Python sidecar for prompt injection & deep content scoring (v1.6) |
| 🐳 **Docker Support** | One-command `docker compose up` with Redis + ML engine |

---

## 🚀 Quick Start

```bash
npm install hippocrates zod @upstash/redis
```

**60 seconds to protection.** Wrap any App Route handler:

```typescript
// app/api/data/route.ts
import { NextRequest, NextResponse } from "next/server";
import { Redis } from "@upstash/redis";
import { withHippocrates, z } from "hippocrates";

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

// ⚠️  .strict() is MANDATORY — extra fields trigger instant honeypot
const Schema = z.object({
  userId: z.string().uuid(),
  action: z.enum(["read", "write"]),
}).strict();

async function handler(req: NextRequest): Promise<NextResponse> {
  const body = await req.json();
  return NextResponse.json({ success: true, data: body });
}

// 🩺 That's it. One wrapper. Full protection.
export const POST = withHippocrates(handler, Schema, redis);
```

<details>
<summary><strong>🔧 With Custom Configuration →</strong></summary>

```typescript
export const POST = withHippocrates(handler, Schema, redis, {
  // ── Preset: one-liner tuning ──
  preset: "strict", // "moderate" | "relaxed" — overrides all below

  // ── Or manual overrides ──
  threatScoreThreshold: 50,           // Default: 65 (lower = stricter)
  velocityMaxRequests: 10,            // Default: 15 req/window
  velocityWindowMs: 5_000,            // Default: 10s window
  debugMode: process.env.NODE_ENV === "development",

  decoyGenerator: (req) => ({
    success: true,
    data: {
      id: crypto.randomUUID(),
      status: "active",
      timestamp: new Date().toISOString(),
    },
  }),

  scoring: {
    velocityViolation: 60,            // Per-endpoint scoring override
    suspiciousUserAgent: 30,
  },

  // ── v1.6 features ──
  allowlist: { ips: ["10.0.0.0/8", "127.0.0.1"] },
  bodyLimit: { maxBytes: 524_288, enabled: true },
});
```

</details>

---

## ⚔️ The 6 Defense Layers

| # | Layer | Signal | Points | What Gets Flagged |
|:--|:------|:-------|:------:|:------------------|
| **L0** | Pre-flight Check | Existing Redis score | Instant | Repeat offenders from previous requests |
| **L1** | Timing Analysis | Interval < 50ms | **+25** | Machine-speed execution |
| **L2** | Velocity Tracking | Burst > 15 req / 10s | **+40** | Sliding window via Redis list |
| **L3** | UA Fingerprinting | Suspicious / missing UA | **+15** | 35+ patterns: LLM SDKs, HTTP libs |
| **L4** | Obfuscation Detection | Base64/Hex/Unicode | **+100** 🔥 | Instant max score |
| **L5** | Schema Validation | Zod `.strict()` violation | **+100** 🔥 | Any extra field or type mismatch |
| **L6** | Header Anomalies | Missing/wildcard headers | **+15** | Non-browser HTTP clients |

> **L4 and L5 are nuclear options.** Any obfuscation or schema violation immediately pushes the threat score to 100 — no incremental tolerance.

### UA Detection Coverage

| Category | Patterns |
|:---------|:---------|
| 🤖 **LLM SDKs** | `anthropic-sdk`, `openai-node`, `google-gemini`, `langchain`, `llamaindex`, `autogen`, `crewai`, `smolagents`, `cohere`, `mistral`, `together`, `groq`, `deepseek`, `dspy`, `huggingface` |
| 🌐 **HTTP Libs** | `python-requests`, `aiohttp`, `httpx`, `axios`, `node-fetch`, `got`, `curl`, `wget` |
| 🕵️ **Browser Automation** | `playwright`, `puppeteer`, `selenium`, `cypress`, `headlesschrome` |
| 🆕 **2026 AI Agents** | `claudebot`, `cursor`, `perplexitybot`, `githubcopilot`, `opencode`, `windsurf` |

### Obfuscation Detection

| Pattern | Example | Threshold |
|:--------|:--------|:----------|
| **Base64** | `dXNlci1pZDogMTIz...` | ≥ 24 chars |
| **Hex encoding** | `0x48656c6c6f576f726c64` | ≥ 16 hex chars |
| **URL encoding** | `%68%65%6c%6c%6f` | 5+ consecutive |
| **Unicode escapes** | `\u0068\u0065\u006c` | Any occurrence |
| **HTML entities** | `&#104;&#101;&#108;` | Any occurrence |

---

## 📊 Comparison: Hippocrates vs. The World

| Feature | 🩺 **Hippocrates** | Rate Limiting | WAF | express-rate-limit |
|:--------|:------------------:|:-------------:|:---:|:------------------:|
| **Attacker sees** | `200 OK` (fake) | `429` | `403` | `429` |
| **Attacker knows?** | **Never** | Yes | Yes | Yes |
| **Stateful?** | ✅ Redis-backed | ❌ Usually | ❌ Per-request | ❌ Per-window |
| **AI agent detection** | ✅ 35+ patterns | ❌ | ❌ | ❌ |
| **Obfuscation scan** | ✅ Recursive | ❌ | ⚠️ Partial | ❌ |
| **Zero-Trust schema** | ✅ Recursive `.strict()` | ❌ | ❌ | ❌ |
| **Edge Runtime** | ✅ No `Buffer` | ✅ | ❌ | ❌ |
| **IP allowlist** | ✅ Exact + CIDR | ❌ | ✅ | ❌ |
| **Config presets** | ✅ 3 presets | ❌ | ❌ | ❌ |
| **Install size** | **~33KB** | varies | N/A | ~15KB |

---

## 🔧 API Reference

### `withHippocrates(handler, schema, redis, config?)`

| Param | Type | Required | Default | Description |
|:------|:-----|:--------:|:--------|:------------|
| `handler` | `(req) => Promise<NextResponse>` | ✅ | — | Your route handler |
| `schema` | `ZodType<T>` | ✅ | — | Zod schema with `.strict()` |
| `redis` | `RedisClient` | ✅ | — | Upstash / ioredis compatible client |
| `config` | `HippocratesConfig` | ❌ | See below | Optional overrides |

### Config Options

| Option | Type | Default | Description |
|:-------|:-----|:--------|:------------|
| `preset` | `"strict" | "moderate" | "relaxed"` | — | One-liner tuning (overrides all below) |
| `threatScoreThreshold` | `number` | `65` | Score (0–100) that triggers honeypot |
| `velocityWindowMs` | `number` | `10_000` | Sliding window for velocity tracking |
| `velocityMaxRequests` | `number` | `15` | Max requests per window |
| `threatTtlSeconds` | `number` | `3_600` | Redis TTL for threat keys |
| `scoring` | `Partial<ThreatScoringWeights>` | `DEFAULT_WEIGHTS` | Per-layer weight overrides |
| `decoyGenerator` | `(req) => object` | Built-in | Custom decoy response |
| `debugMode` | `boolean` | `false` | Verbose security logging |
| `plugins` | `AnalyzerPlugin[]` | — | Custom detection analyzers (v1.5) |
| `hooks` | `HippocratesHooks` | — | Event hooks for violation/pass/honeypot (v1.5) |
| `allowlist` | `{ ips: string[] }` | — | Exact + CIDR IP bypass (v1.6) |
| `bodyLimit` | `{ maxBytes, enabled }` | `{ 1MB, enabled: true }` | Payload size enforcement (v1.6) |
| `methodThresholds` | `Partial<Record<string, number>>` | — | Per-HTTP-method threshold overrides (v1.6) |
| `violationMessages` | `object` | — | Custom honeypot messages per violation type (v1.6) |
| `statsTracker` | `StatsTracker` | — | Consumer-provided stats interface for real-time metrics (v1.6) |

### Redis Key Layout

| Key | Purpose | TTL |
|:----|:--------|:---:|
| `hc:s:{ip}` | Cumulative threat score (0–100) | `threatTtlSeconds` |
| `hc:t:{ip}` | Request timestamp list (velocity) | `windowMs + 10s` |
| `hc:l:{ip}` | Last-seen timestamp (timing) | 300s |

---

## 🕳️ Anatomy of a Honeypot

The honeypot is the heart of Hippocrates. When an attacker triggers a detection, they receive a convincing `200 OK` — with deceptive data designed to waste their resources.

> **Key insight:** The honeypot generates **4 rotating response templates** with randomized fake data. Each request looks legitimate but leads nowhere. The attacker burns money processing synthetic data they can't distinguish from real API responses.

| Template | Shape | Looks Like |
|:---------|:------|:-----------|
| **A — Generic Data** | `{ success, requestId, data, metadata }` | Standard REST endpoint |
| **B — Auth Token** | `{ accessToken, tokenType, expiresIn, scope }` | OAuth token exchange |
| **C — Paginated List** | `{ items[], pagination }` | List API with cursors |
| **D — Analytics** | `{ dashboard, metrics[], summary }` | Metrics dashboard API |

All templates include:
- ✅ Realistic UUIDs, timestamps, and version strings
- ✅ Plausible pagination (hasNext: true to keep them going)
- ✅ Randomized processing latency headers
- ❌ No `x-powered-by`, no `server` headers
- ❌ No signal the request was intercepted

---

## 🧩 Analyzer Plugin System

Extend Hippocrates with custom detection logic using the `AnalyzerPlugin` interface. Plugins run in two phases:

| Phase | When It Runs | Built-in Analyzers |
|:------|:-------------|:-------------------|
| **pre-body** | Before request body is parsed | L1 Timing, L2 Velocity, L3 UA, L6 Headers |
| **post-body** | After body is parsed (has access to `context.bodyRaw`) | L4 Obfuscation, L5 Schema |

```typescript
import { type AnalyzerPlugin } from "hippocrates";

const myAnalyzer: AnalyzerPlugin = {
  name: "custom_check",
  phase: "pre-body",
  priority: 50,  // Lower = runs first (default: 100)
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

---

## 🔔 Event Hooks

Monitor security events in real-time with `onViolation`, `onPass`, and `onHoneypot` callbacks:

```typescript
export const POST = withHippocrates(handler, schema, redis, {
  hooks: {
    onViolation: (event) => {
      console.log(`Violation: ${event.ip} — ${event.violations}`);
    },
    onPass: (event) => {
      metrics.recordPass(event.ip, event.score);
    },
    onHoneypot: (event) => {
      alertService.notify(`Honeypot served: ${event.ip}`);
    },
  },
});
```

---

## 📊 Stats Tracking

Hippocrates maintains built-in in-memory counters for all security events. Access them via `ThreatScoreEngine.getStats()` or provide a custom `StatsTracker`:

```typescript
import { type StatsTracker } from "hippocrates";

const tracker: StatsTracker = {
  increment(counter) {
    console.log(`Event: ${counter}`);
  },
  getStats() {
    return { totalRequests: 0, blockedByPreflight: 0, /* ... */ };
  },
  reset() {},
};

export const POST = withHippocrates(handler, schema, redis, {
  statsTracker: tracker,
});
```

Available counters: `totalRequests`, `blockedByPreflight`, `blockedByTiming`, `blockedByVelocity`, `blockedByObfuscation`, `blockedBySchema`, `passedToHandler`, `honeypotServed`, `redisErrors`.

---

## 🤖 ML Engine Integration

Hippocrates ships with an optional **Python sidecar** for ML-based threat detection (prompt injection, advanced obfuscation, content risk scoring).

### Architecture

```
┌──────────────┐     ┌──────────────┐     ┌───────────┐
│  Hippocrates │────►│  ML Engine   │────►│   Redis   │
│  (Next.js)   │     │  (FastAPI)   │     │ (Upstash) │
└──────────────┘     └──────────────┘     └───────────┘
       │                    │
       │  POST /analyze     │
       │  { body_raw, ... } │
       └────────────────────┘
```

### Quick Start

```bash
# Start both Redis and ML engine
docker compose up -d

# ML engine is now available at http://localhost:8000
```

### Register the plugin in your handler:

```typescript
import { mlEnginePlugin } from "hippocrates";

export const POST = withHippocrates(handler, schema, redis, {
  plugins: [mlEnginePlugin({
    baseUrl: "http://ml-engine:8000", // Docker service name
    timeoutMs: 3000,
    minScoreThreshold: 10,
  })],
});
```

### How It Works

1. After body parsing (post-body phase), the pipeline sends the raw request body to the ML engine
2. The ML engine runs prompt injection detection, obfuscation scoring, and content risk analysis
3. Results contribute to the cumulative threat score
4. If the ML engine is unreachable, it degrades gracefully (score = 0, no crash)

### Configuration

| Option | Default | Description |
|:-------|:--------|:------------|
| `baseUrl` | `http://localhost:8000` | ML engine endpoint |
| `timeoutMs` | `3000` | Request timeout before fallback |
| `minScoreThreshold` | `10` | Minimum ML score to contribute to threat score |

---

## 🐳 Docker Deployment

Run the full Hippocrates stack with a single command:

```yaml
# docker-compose.yml (included in the package)
services:
  hippocrates-ml-engine:
    build: ./engine-python
    ports:
      - "8000:8000"
    environment:
      - REDIS_URL=redis://redis:6379
    depends_on:
      redis:
        condition: service_healthy

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 5
```

```bash
# Start services
docker compose up -d

# Run smoke test
powershell -File engine-python/smoke-test.ps1
```

The ML engine runs on `python:3.12-slim` with FastAPI + httpx. The Docker build is verified in CI via GitHub Actions.

---

## 🌟 Use Cases

| Scenario | Why Hippocrates |
|:---------|:----------------|
| 🏢 **SaaS APIs** | Protect B2B/B2C endpoints from LLM scraping agents |
| 🤖 **AI Startups** | Prevent competitors from extracting training data |
| 🛒 **E-commerce** | Block automated pricing bots and inventory scrapers |
| 👥 **Social Platforms** | Shadow-ban bot networks probing user data |
| 🏦 **Financial Services** | Halt credential stuffing and enumeration attacks |

---

## 🧪 Testing

```bash
npm test                 # 177 tests across 10 files — all pass
npm run typecheck        # tsc --noEmit — zero errors
npm run lint             # ESLint flat config — zero errors
npm run build            # tsup → CJS + ESM + .d.ts
```

---

## 🤝 Contributing

| Area | How to Help |
|:-----|:------------|
| 🐛 **Bug reports** | Open an issue with reproduction steps |
| 🤖 **New UA patterns** | [Add it](SKILL.md#adding-a-new-user-agent-pattern-most-common-task) — especially 2026+ agents |
| 🔍 **New obfuscation patterns** | See [SKILL.md](SKILL.md#new-obfuscation-pattern) |
| ⚡ **New detection layers** | Architecture guidance in [CLAUDE.md](CLAUDE.md#how-to-extend-the-library) |
| 📖 **Documentation** | Better docs = better adoption |

### Development

```bash
npm run dev              # tsup --watch
npm run build            # Production build
npm run test:watch       # TDD mode
```

---

## 🛠️ Built With

<p align="center">
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript"/></a>
  <a href="https://nextjs.org/"><img src="https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=next.js&logoColor=white" alt="Next.js"/></a>
  <a href="https://redis.io/"><img src="https://img.shields.io/badge/Redis-FF4438?style=for-the-badge&logo=redis&logoColor=white" alt="Redis"/></a>
  <a href="https://zod.dev/"><img src="https://img.shields.io/badge/Zod-3E67B1?style=for-the-badge&logo=zod&logoColor=white" alt="Zod"/></a>
  <a href="https://vitest.dev/"><img src="https://img.shields.io/badge/Vitest-6E9F18?style=for-the-badge&logo=vitest&logoColor=white" alt="Vitest"/></a>
  <a href="https://tsup.egoist.dev/"><img src="https://img.shields.io/badge/tsup-000000?style=for-the-badge&logo=tsup&logoColor=white" alt="tsup"/></a>
</p>

---

## 📈 Star History

<p align="center">
  <a href="https://star-history.com/#achmdfzn/hippocrates&Timeline">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=achmdfzn/hippocrates&type=Date&theme=dark" />
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=achmdfzn/hippocrates&type=Date" />
      <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=achmdfzn/hippocrates&type=Date" width="600" />
    </picture>
  </a>
  <br/>
  <sub>⭐ Star the repo to show support and help others discover Hippocrates!</sub>
</p>

---

## ☕ Support

If Hippocrates protects your API, consider supporting development:

<p align="center">
  <a href="https://github.com/sponsors/achmdfzn">
    <img src="https://img.shields.io/badge/GitHub%20Sponsors-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="GitHub Sponsors"/>
  </a>
  <a href="https://ko-fi.com/achmdfzn">
    <img src="https://img.shields.io/badge/Ko--fi-FF5E5B?style=for-the-badge&logo=kofi&logoColor=white" alt="Ko-fi"/>
  </a>
  <a href="https://www.buymeacoffee.com/achmdfzn">
    <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me a Coffee"/>
  </a>
</p>

---

## 📄 License

<p align="center">
  MIT © <a href="https://github.com/achmdfzn">achmdfzn</a>
  <br/><br/>
  <strong>First, do no harm — to your API.</strong>
  <br/>
  <sub>Built for the era where your API consumers might not be human.</sub>
</p>
