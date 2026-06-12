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
  Silently destroys autonomous AI agents, LLM scrapers, and automated bots<br/>
  using <strong>Redis-backed stateful defense architecture</strong>.
</p>

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
    <img src="https://img.shields.io/github/actions/workflow/status/achmdfzn/hippocrates/ci.yml?style=flat-square&logo=github" alt="CI"/>
  </a>
  <a href="https://github.com/achmdfzn/hippocrates/issues">
    <img src="https://img.shields.io/github/issues/achmdfzn/hippocrates?style=flat-square&color=%23FF6B6B" alt="issues"/>
  </a>
  <a href="https://twitter.com/intent/tweet?text=Hippocrates%20-%20Next.js%20security%20middleware%20that%20silently%20destroys%20AI%20agents%20%F0%9F%A9%BA&url=https://github.com/achmdfzn/hippocrates">
    <img src="https://img.shields.io/badge/share%20on-X-1DA1F2?style=flat-square&logo=x" alt="Share on X"/>
  </a>
</p>

<p align="center">
  <a href="#-the-problem">The Problem</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-how-it-works">How It Works</a> •
  <a href="#-defense-layers">Defense Layers</a> •
  <a href="#-comparison">Comparison</a> •
  <a href="#-api-reference">API</a> •
  <a href="#-use-cases">Use Cases</a>
</p>

<br/>

> **🚨 Traditional API security is broken.** Rate limiting tells attackers to slow down. WAF blocks tell them to rotate IPs. `403` and `429` responses are *signals*, not defenses — they make AI agents *smarter*.
>
> **Hippocrates flips the script.** Every detected threat gets a convincing `200 OK` with realistic fake data. The attacker wastes compute, burns through token budgets, and their agentic pipelines break silently — never knowing they've been caught.

---

## ✨ Features at a Glance

| Feature | What It Does |
|---------|-------------|
| 🤫 **Silent Honeypot** | `200 OK` with fake data — zero signal to the attacker |
| 🧠 **Stateful Threat Scoring** | Redis-backed cumulative scores persist across requests |
| ⚡ **6 Defense Layers** | Timing, velocity, UA, obfuscation, schema, headers |
| 🚀 **Edge-Ready** | Works on Vercel Edge Runtime, Node.js — zero `Buffer` usage |
| 🔒 **Zero-Trust Validation** | Recursive `.strict()` on every nested Zod type |
| 🤖 **AI Agent Detection** | 40+ patterns: OpenAI, Anthropic, LangChain, Playwright, more |
| 📊 **No Data Leakage** | Error messages intentionally vague — no schema details exposed |

---

## 🔥 The Problem

Modern API threats **aren't human**. Autonomous AI agents can:

<table>
<tr>
  <th>Capability</th>
  <th>Impact</th>
</tr>
<tr>
  <td>Call your API <strong>10,000+ times/min</strong></td>
  <td>Saturate infrastructure, spike cloud bills</td>
</tr>
<tr>
  <td><strong>Probe schema boundaries</strong> systematically</td>
  <td>Discover hidden endpoints, infer data models</td>
</tr>
<tr>
  <td><strong>Inject obfuscated payloads</strong> (Base64, Hex, Unicode)</td>
  <td>Bypass WAF rules and keyword filters</td>
</tr>
<tr>
  <td><strong>Adapt in real-time</strong> from error responses</td>
  <td>Evolve attack strategy after each <code>403</code>/<code>429</code></td>
</tr>
<tr>
  <td><strong>Chain API calls</strong> in agentic pipelines</td>
  <td>Extract and correlate data across endpoints</td>
</tr>
</table>

### Why Traditional Defenses Fail

<table>
<tr>
  <th>Approach</th>
  <th>Why It Fails</th>
  <th>Hippocrates Solution</th>
</tr>
<tr>
  <td><strong>Rate limiting (429)</strong></td>
  <td>Tells attacker to slow down, adapt interval</td>
  <td>✅ <code>200 OK</code> with fake data — no signal</td>
</tr>
<tr>
  <td><strong>WAF blocks (403)</strong></td>
  <td>Gives attacker signal to rotate IP/proxy</td>
  <td>✅ Attacker can't detect they're blocked</td>
</tr>
<tr>
  <td><strong>Stateless validation</strong></td>
  <td>Misses cross-request behavioral patterns</td>
  <td>✅ Redis-backed cross-request state</td>
</tr>
<tr>
  <td><strong>Zod <code>.parse()</code> without <code>.strict()</code></strong></td>
  <td>Silently strips extra fields — attacker wins</td>
  <td>✅ Recursive <code>.strict()</code> — nothing slips through</td>
</tr>
<tr>
  <td><strong>Simple API keys</strong></td>
  <td>Agents can rotate keys from breached env files</td>
  <td>✅ Behavioral detection — keys don't matter</td>
</tr>
</table>

---

## 🚀 Quick Start

```bash
npm install hippocrates zod @upstash/redis
```

Then wrap **any** App Route handler in one function call:

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
});
```

</details>

---

## 🏗️ How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Incoming Request                             │
│                           (any IP)                                   │
└─────────────────────────┬───────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────────────────┐
│                  withHippocrates Middleware Pipeline                    │
│                                                                      │
│   ┌──────┐    ┌─────┐    ┌──────┐    ┌─────┐    ┌─────┐    ┌─────┐ │
│   │  L0  │───▶│ L1  │───▶│  L2  │───▶│ L3  │───▶│ L4  │───▶│ L5  │ │
│   │Score │    │Tim- │    │Velo- │    │ UA  │    │Obfus│    │Schema│ │
│   │Check │    │ing  │    │city  │    │Finger│    │cation│    │Valid │ │
│   └──────┘    └─────┘    └──────┘    └─────┘    └─────┘    └─────┘ │
│      │          │          │          │          │          │       │
│      ▼          ▼          ▼          ▼          ▼          ▼       │
│                                                                      │
│       ┌────────────────────────────────────────────────────┐         │
│       │         Cumulative Threat Score (0–100)            │         │
│       │           Persisted in Redis per IP                │         │
│       └──────────────────────┬─────────────────────────────┘         │
│                              │                                       │
│                              ▼                                       │
│              ┌──────────────────────────────┐                        │
│              │        Score ≥ Threshold?     │                        │
│              │        (default: 65)          │                        │
│              └──────────┬─────────┬─────────┘                        │
│                         │         │                                  │
│                    YES  │         │  NO                              │
│                         │         │                                  │
│                         ▼         ▼                                  │
│              ┌────────────────┐  ┌──────────────────┐                │
│              │   🚨 HONEYPOT  │  │  ✅ FORWARD TO    │                │
│              │ 200 OK (fake) │  │   REAL HANDLER    │                │
│              └────────────────┘  └──────────────────┘                │
└──────────────────────────────────────────────────────────────────────┘
```

### The Core Pattern

1. **Every request** enters the middleware pipeline
2. **6 defense layers** analyze timing, velocity, UA, obfuscation, schema, and headers
3. **A cumulative score (0–100)** is computed and stored in Redis per IP
4. **Score ≥ 65** → automatic routing to a convincing honeypot (`200 OK` with fake data)
5. **Score < 65** → request forwarded to your real handler with validated data

> **Key insight:** The honeypot generates realistic-looking responses that vary per request — 4 rotating templates with randomized fake data. The attacker burns compute processing fake data they can't distinguish from real API responses.

---

## ⚔️ The 6 Defense Layers

| # | Layer | Signal | Points | What Gets Flagged |
|---|-------|--------|:------:|-------------------|
| **L0** | Pre-flight Check | Existing Redis score | Instant | Repeat offenders from previous requests |
| **L1** | Timing Analysis | Request interval < 50ms | **+25** | Machine-speed execution (no human types that fast) |
| **L2** | Velocity Tracking | Burst > 15 req / 10s | **+40** | Sliding window via Redis list (capped at 500) |
| **L3** | UA Fingerprinting | Suspicious / missing UA | **+15** | 40+ patterns: LLM SDKs, HTTP libs, headless browsers |
| **L4** | Obfuscation Detection | Base64, Hex, Unicode in payload | **+100** 🚨 | Instant max score — no incremental tolerance |
| **L5** | Schema Validation | Zod `.strict()` violation | **+100** 🚨 | Any extra field or type mismatch |
| **L6** | Header Anomalies | Missing/wildcard headers | **+15** | Non-browser HTTP clients and scanners |

> **L4 and L5 are instant max.** Any obfuscation or schema violation immediately pushes the threat score to 100 — no incremental tolerance. These are the nuclear options.

### L1 — Timing Analysis
Two requests from the same IP within **50ms** is a near-certain autonomous signal. No human can navigate a browser and submit a form that fast.

### L2 — Velocity Tracking
Redis-backed sliding window tracks request counts per IP. Bursts exceeding `velocityMaxRequests` within `velocityWindowMs` trigger scoring. The timestamp list is capped at 500 entries via `ltrim` to manage memory.

### L3 — User-Agent Fingerprinting
Detects **40+ agent patterns** across 4 categories:

| Category | Patterns |
|----------|----------|
| **🤖 LLM SDKs** | `anthropic-sdk`, `openai-node`, `google-gemini`, `langchain`, `llamaindex`, `autogen`, `crewai`, `smolagents`, `cohere`, `mistral`, `together`, `groq`, `deepseek`, `dspy`, `huggingface` |
| **🌐 HTTP Libs** | `python-requests`, `aiohttp`, `httpx`, `axios`, `node-fetch`, `got`, `curl`, `wget`, `go-http-client`, `java/*`, `okhttp` |
| **🕵️ Browser Automation** | `playwright`, `puppeteer`, `selenium`, `cypress`, `phantomjs`, `headlesschrome` |
| **🚫 Generic** | `bot`, `spider`, `crawler`, `scraper` (with version awareness to minimize false positives) |

### L4 — Obfuscation Detection
Recursively scans all string values in JSON payloads for encoded/obfuscated content:

- **Base64** — strings ≥ 24 chars matching `[A-Za-z0-9+/=]{24,}`
- **Hex encoding** — strings ≥ 16 consecutive hex chars
- **URL encoding** — 5+ consecutive `%xx` sequences
- **Unicode escapes** — `\uXXXX` patterns
- **HTML entities** — `&#dd;` and `&lt;` style encoding

### L5 — Zero-Trust Schema Validation
Enforces `.strict()` recursively through the **entire schema tree** — including nested objects inside `refine()`, `transform()`, discriminated unions, tuples, branded types, and `ZodEffects`. **No extra field survives.**

### L6 — Header Anomaly Detection
Checks for missing or wildcard HTTP headers:
- Missing `Accept` header
- Missing `Accept-Language` header
- Missing `Accept-Encoding` header
- Wildcard `*/*` Accept header

These are patterns typical of non-browser HTTP clients, scanners, and bots that don't bother setting proper headers.

---

## 📊 Comparison: Hippocrates vs Traditional Solutions

<table>
<tr>
  <th>Feature</th>
  <th>🩺 Hippocrates</th>
  <th>Rate Limiting</th>
  <th>WAF</th>
  <th>express-rate-limit</th>
</tr>
<tr>
  <td><strong>Response to attacker</strong></td>
  <td>✅ <code>200 OK</code> (fake data)</td>
  <td>❌ <code>429</code></td>
  <td>❌ <code>403</code></td>
  <td>❌ <code>429</code></td>
</tr>
<tr>
  <td><strong>Attacker can detect?</strong></td>
  <td>✅ <strong>No</strong> — they think they succeeded</td>
  <td>❌ Yes — adapts interval</td>
  <td>❌ Yes — rotates IP</td>
  <td>❌ Yes — adapts interval</td>
</tr>
<tr>
  <td><strong>Stateful (cross-request)</strong></td>
  <td>✅ Redis-backed</td>
  <td>❌ Usually stateless</td>
  <td>❌ Per-request</td>
  <td>❌ Per-window</td>
</tr>
<tr>
  <td><strong>AI agent fingerprinting</strong></td>
  <td>✅ 40+ patterns</td>
  <td>❌</td>
  <td>❌</td>
  <td>❌</td>
</tr>
<tr>
  <td><strong>Obfuscation detection</strong></td>
  <td>✅ Recursive scan</td>
  <td>❌</td>
  <td>⚠️ Partial</td>
  <td>❌</td>
</tr>
<tr>
  <td><strong>Zero-Trust schema</strong></td>
  <td>✅ Recursive <code>.strict()</code></td>
  <td>❌</td>
  <td>❌</td>
  <td>❌</td>
</tr>
<tr>
  <td><strong>Edge Runtime</strong></td>
  <td>✅ No <code>Buffer</code></td>
  <td>✅</td>
  <td>❌</td>
  <td>❌</td>
</tr>
<tr>
  <td><strong>LLM SDK detection</strong></td>
  <td>✅ Anthropic, OpenAI, LangChain, etc.</td>
  <td>❌</td>
  <td>❌</td>
  <td>❌</td>
</tr>
</table>

---

## 🔧 API Reference

### `withHippocrates(handler, schema, redis, config?)`

| Param | Type | Required | Default | Description |
|-------|------|:--------:|---------|-------------|
| `handler` | `(req: NextRequest) => Promise<NextResponse>` | ✅ | — | Your route handler |
| `schema` | `ZodType<T>` | ✅ | — | Zod schema with `.strict()` |
| `redis` | `RedisClient` | ✅ | — | Upstash / ioredis compatible client |
| `config` | `HippocratesConfig` | ❌ | `See below` | Optional overrides |

### Config Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `threatScoreThreshold` | `number` | `65` | Score (0–100) that triggers honeypot |
| `velocityWindowMs` | `number` | `10_000` | Velocity tracking window in ms |
| `velocityMaxRequests` | `number` | `15` | Max requests per velocity window |
| `threatTtlSeconds` | `number` | `3_600` | TTL for Redis threat keys |
| `debugMode` | `boolean` | `false` | Enable security logging |
| `decoyGenerator` | `(req) => object` | Built-in | Custom decoy response generator |
| `scoring` | `Partial<ThreatScoringWeights>` | — | Per-endpoint weight overrides |

### Redis Key Schema

| Key | Purpose | TTL |
|-----|---------|:---:|
| `hc:s:{ip}` | Cumulative threat score (0–100) | `threatTtlSeconds` (3600s) |
| `hc:t:{ip}` | Request timestamp list for velocity | `velocityWindowMs + 10s` |
| `hc:l:{ip}` | Last-seen timestamp for timing | 300s |

---

## 🎯 Use Cases

| Scenario | Why Hippocrates |
|----------|----------------|
| **🏢 SaaS APIs** | Protect B2B/B2C API endpoints from LLM-powered scraping agents extracting your data |
| **🤖 AI Startups** | Prevent competitors from extracting your model's training data via API probes |
| **🛒 E-commerce** | Block automated pricing bots and inventory scrapers from harvesting product data |
| **👥 Social Platforms** | Detect and shadow-ban bot networks that probe user data or scrape profiles |
| **🏦 Financial Services** | Protect account endpoints from automated credential stuffing and enumeration attacks |

---

## 🧪 Testing

```bash
npm test                 # 123 tests across 6 files — all pass
npm run typecheck        # tsc --noEmit — zero errors
npm run lint             # ESLint flat config — zero errors
```

Hippocrates is fully tested with **Vitest**, covering all defense layers, the decoy system, Redis interactions, IPv6 normalization, recursive `.strict()` enforcement, and integration scenarios.

---

## 🤝 Contributing

We're actively looking for contributions in these areas:

- 🐛 **Bug reports** — Found an edge case? Open an issue
- 🤖 **New UA patterns** — Missing an AI agent framework? [Add it](SKILL.md#adding-a-new-user-agent-pattern-most-common-task)
- 🔍 **New obfuscation patterns** — See [SKILL.md](SKILL.md#new-obfuscation-pattern)
- ⚡ **New defense layers** — Architecture guidance in [CLAUDE.md](CLAUDE.md#how-to-extend-the-library)
- 📖 **Documentation** — Better docs = better adoption

### Development

```bash
npm run dev              # tsup --watch
npm run build            # Production build
npm run test:watch       # TDD mode
```

---

## 📦 Built With

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

If Hippocrates helps protect your API, consider supporting development:

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
