/**
 * @package hippocrates
 * @description Enterprise-grade Next.js App Router security middleware.
 *
 * A "digital vaccine" implementing Strict Stateful Defense Architecture
 * to protect APIs from autonomous AI agents (LLM-based tooling, agentic
 * pipelines, headless browsers) and malicious automated scripts.
 *
 * Core Philosophy — CIA Triad:
 *   - Integrity    : Zero-Trust payload validation (Zod .strict())
 *   - Availability : Autonomous agent throttling (Redis velocity tracking)
 *   - Confidentiality: Zero error leakage to external callers
 *
 * Defense Layers (in execution order):
 *   L0 — Pre-flight existing threat score check (instant honeypot for repeat offenders)
 *   L1 — Sub-human request timing detection (< 50ms intervals)
 *   L2 — Sliding-window velocity tracking (burst detection)
 *   L3 — User-Agent fingerprinting (HTTP libs, LLM SDKs, headless browsers)
 *   L4 — Payload obfuscation detection (Base64, Hex, URL-encoding, Unicode escapes)
 *   L5 — Zero-Trust Zod schema validation (.strict() enforced)
 *   L6 — Header anomaly detection (missing/wildcard Accept, Accept-Language, etc.)
 *
 * @version 0.1.0
 * @license MIT
 */

import { NextRequest, NextResponse } from "next/server";
import { z, ZodType, ZodError } from "zod";
import { resolveClientIp } from "./utils/ip";

// ┌──────────────────────────────────────────────────────────────────┐
// │  § 1  TYPE DEFINITIONS                                           │
// └──────────────────────────────────────────────────────────────────┘

/**
 * Minimal Redis adapter interface designed for maximum portability.
 *
 * Compatible with:
 *   - @upstash/redis  → Recommended for Vercel / Next.js Edge deployments
 *   - ioredis         → Recommended for self-hosted Node.js servers
 *   - redis (npm)     → Node.js official Redis client
 *
 * If your client has a slightly different API, a thin wrapper is sufficient.
 */
export interface RedisClient {
  get(key: string): Promise<string | null>;
  set(
    key: string,
    value: string | number,
    options?: { ex?: number }
  ): Promise<unknown>;
  lpush(key: string, ...values: string[]): Promise<number>;
  ltrim(key: string, start: number, stop: number): Promise<unknown>;
  lrange(key: string, start: number, stop: number): Promise<string[]>;
  expire(key: string, seconds: number): Promise<unknown>;
}

/**
 * Configurable scoring weights for each threat category.
 * All values are points on a 0-100 scale.
 *
 * Schema and obfuscation violations default to 100 (immediate max)
 * per the Zero-Trust spec: "injected fields immediately push the
 * Threat Score to the maximum."
 */
export interface ThreatScoringWeights {
  /** Missing UA or match against known agent UA patterns. @default 15 */
  suspiciousUserAgent: number;
  /** Zod .strict() failure: extra fields, wrong types, coercion failure. @default 100 */
  schemaViolation: number;
  /** Base64, Hex, URL-encoding, or Unicode escape sequences in payload. @default 100 */
  obfuscationDetected: number;
  /** Requests exceed velocityMaxRequests within velocityWindowMs. @default 40 */
  velocityViolation: number;
  /** Two consecutive requests less than 50ms apart (sub-human speed). @default 25 */
  impossibleTiming: number;
  /** Non-JSON body submitted to a structured JSON endpoint. @default 10 */
  nonJsonBody: number;
  /** Missing or suspicious HTTP headers (missing Accept, wildcard Accept, etc.). @default 15 */
  suspiciousHeaders: number;
}

export interface HippocratesConfig {
  /**
   * Cumulative threat score (0–100) that triggers silent honeypot routing.
   * Lower = stricter. Recommended enterprise range: 55–70.
   * @default 65
   */
  threatScoreThreshold?: number;

  /**
   * Sliding window width (ms) for request velocity tracking.
   * @default 10_000 (10 seconds)
   */
  velocityWindowMs?: number;

  /**
   * Maximum legitimate requests allowed per IP within one velocity window.
   * Exceeding this adds `velocityViolation` points to the threat score.
   * @default 15
   */
  velocityMaxRequests?: number;

  /**
   * TTL (seconds) for threat score keys stored in Redis.
   * Lower = faster "forgiveness". Higher = longer memory for bad actors.
   * @default 3600 (1 hour)
   */
  threatTtlSeconds?: number;

  /**
   * Custom function to generate decoy response bodies for the honeypot.
   * Mirror the real endpoint's response shape to fool persistent agents.
   * If omitted, the built-in randomized decoy generator is used.
   */
  decoyGenerator?: (req: NextRequest) => Record<string, unknown>;

  /**
   * Enable verbose console logging for all security events.
   * NEVER enable in production — logs may be scraped by the attacker.
   * @default false
   */
  debugMode?: boolean;

  /**
   * Partial override of the default scoring weights.
   * Useful to tune sensitivity per-endpoint.
   */
  scoring?: Partial<ThreatScoringWeights>;
}

export type AppRouteHandler = (
  req: NextRequest
) => Promise<NextResponse> | NextResponse;

type ValidationResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; isSchemaViolation: boolean };

// ┌──────────────────────────────────────────────────────────────────┐
// │  § 2  CONSTANTS & DEFAULTS                                       │
// └──────────────────────────────────────────────────────────────────┘

const DEFAULTS = {
  threatScoreThreshold: 65,
  velocityWindowMs: 10_000,
  velocityMaxRequests: 15,
  threatTtlSeconds: 3_600,
  debugMode: false,
} as const;

const DEFAULT_WEIGHTS: ThreatScoringWeights = {
  suspiciousUserAgent: 15,
  schemaViolation: 100, // Zero-Trust: any structural violation maxes score immediately
  obfuscationDetected: 100, // Obfuscation is never legitimate input — treat as hostile
  velocityViolation: 40,
  impossibleTiming: 25,
  nonJsonBody: 10,
  suspiciousHeaders: 15,
};

/**
 * User-Agent patterns for autonomous or scripted HTTP clients.
 *
 * UA-based detection is a soft signal — combine it with behavioral
 * analysis (L1/L2) against evasive agents that spoof their UA.
 */
const AGENT_UA_PATTERNS: ReadonlyArray<RegExp> = [
  /python-requests\/[\d.]+/i,
  /aiohttp\/[\d.]+/i,
  /httpx\/[\d.]+/i,
  /axios\/[\d.]+/i,
  /node-fetch\/[\d.]+/i,
  /got\/[\d.]+/i,
  /curl\/[\d.]+/i,
  /wget\/[\d.]+/i,
  /java\/[\d.]+/i,
  /go-http-client\/[\d.]+/i,
  /ruby\/[\d.]+/i,
  /anthropic-sdk/i, // Anthropic Python/TS SDK — covers Mythos API access
  /claude-[\d.]+/i, // Claude CLI / API clients
  /openai-node/i,
  /openai-python/i,
  /google-gemini/i, // Google Gemini SDK
  /google-ai-generativelanguage/i, // Google Generative Language API
  /langchain/i,
  /llamaindex/i,
  /autogen/i,
  /crewai/i,
  /smolagents/i, // Hugging Face smolagents
  /llm-agent/i,
  /agentops/i,
  /cohere[\s/-]/i, // Cohere API client
  /mistral[\s/-]/i, // Mistral AI client
  /together[\s/-]/i, // Together AI client
  /groq[\s/-]/i, // Groq SDK
  /deepseek[\s/-]/i, // DeepSeek API
  /dspy[\s/-]/i, // DSPy framework
  /semantic-kernel/i, // Microsoft Semantic Kernel
  /haystack/i, // deepset Haystack framework
  /copilot-github/i, // GitHub Copilot SDK
  /huggingface/i, // Hugging Face Inference API / SDK
  /headlesschrome/i,
  /playwright/i,
  /puppeteer/i,
  /selenium/i,
  /cypress/i,
  /phantomjs/i,
  /\bbot\b/i,
  /\bspider\b/i,
  /\bcrawler\b/i,
  /\bscraper\b/i,
];

/**
 * Payload string patterns that indicate encoding-based obfuscation.
 *
 * Autonomous agents encode injection payloads (prompt injections, SQLi,
 * path traversal) to bypass keyword filters. Scans all string values
 * recursively.
 */
const OBFUSCATION_PATTERNS: ReadonlyArray<{ name: string; pattern: RegExp }> =
  [
    {
      name: "base64",
      // Standard Base64 string, minimum 24 chars to avoid false positives on short tokens
      pattern:
        /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/,
    },
    {
      name: "hex",
      // Hex-encoded string with optional 0x prefix, minimum 16 hex chars
      pattern: /^(?:0x)?[0-9a-fA-F]{16,}$/,
    },
    {
      name: "url_encoding",
      // Five or more consecutive percent-encoded bytes — aggressive encoding
      pattern: /(?:%[0-9a-fA-F]{2}){5,}/,
    },
    {
      name: "unicode_escape",
      // JavaScript-style \uXXXX escape sequences embedded in strings
      pattern: /\\u[0-9a-fA-F]{4}/,
    },
    {
      name: "html_entity",
      // HTML entity encoding: &#60; &#x3C; &lt; etc.
      pattern: /&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]{2,8});/,
    },
  ];

/**
 * Below this inter-request interval, behavior is classified as autonomous.
 * A human physically cannot consistently submit structured POST requests
 * under 50ms apart — this threshold is a strong autonomous signal.
 */
const MIN_HUMAN_INTERVAL_MS = 50;

/**
 * Header anomaly patterns (L6).
 *
 * These check HTTP request headers for signals commonly associated
 * with automated scanners, non-browser HTTP clients, and scripts.
 * Browsers consistently send a rich set of headers; their absence
 * or unusual values is a strong (but soft) signal.
 */
interface HeaderAnomalyPattern {
  name: string;
  check: (headers: Headers) => boolean;
}

const HEADER_ANOMALY_PATTERNS: ReadonlyArray<HeaderAnomalyPattern> = [
  {
    name: "missing_accept",
    check: (h) => {
      const v = h.get("accept");
      return v === null || v.trim() === "";
    },
  },
  {
    name: "wildcard_accept",
    check: (h) => {
      const v = h.get("accept");
      return v !== null && v.trim() === "*/*";
    },
  },
  {
    name: "missing_accept_language",
    check: (h) => !h.has("accept-language"),
  },
  {
    name: "wildcard_accept_encoding",
    check: (h) => {
      const v = h.get("accept-encoding");
      return v !== null && v.trim() === "*";
    },
  },
];

const REDIS_NS = "hc";

// ┌──────────────────────────────────────────────────────────────────┐
// │  § 3  THREAT SCORE ENGINE                                        │
// └──────────────────────────────────────────────────────────────────┘

/** @internal */
export class ThreatScoreEngine {
  constructor(
    private readonly redis: RedisClient,
    private readonly config: HippocratesConfig,
    private readonly weights: ThreatScoringWeights
  ) {}

  // Keep keys short — Upstash free tier has key limits
  private kScore(ip: string) {
    return `${REDIS_NS}:s:${ip}`;
  }
  private kTimestamps(ip: string) {
    return `${REDIS_NS}:t:${ip}`;
  }
  private kLastSeen(ip: string) {
    return `${REDIS_NS}:l:${ip}`;
  }

  // ── Score operations ────────────────────────────────────────────

  async getScore(ip: string): Promise<number> {
    const raw = await this.redis.get(this.kScore(ip));
    return raw !== null ? Math.min(100, parseInt(raw, 10)) : 0;
  }

  /**
   * Adds `points` to the threat score for `ip`, capped at 100.
   * Resets the TTL on every write to keep active threats fresh.
   */
  async addScore(ip: string, points: number, tag: string): Promise<number> {
    const current = await this.getScore(ip);
    const updated = Math.min(100, current + points);
    const ttl =
      this.config.threatTtlSeconds ?? DEFAULTS.threatTtlSeconds;

    await this.redis.set(this.kScore(ip), updated, { ex: ttl });

    if (this.config.debugMode) {
      console.log(
        `[hc:score] ip=${ip} +${points} (${tag}) → ${updated}/100`
      );
    }

    return updated;
  }

  // ── Behavioral analyzers ────────────────────────────────────────

  /**
   * Timing Analysis (L1)
   *
   * Compares the current request timestamp against the last recorded
   * timestamp from this IP. Intervals below MIN_HUMAN_INTERVAL_MS
   * indicate machine-speed execution — a hallmark of agentic pipelines
   * that loop through API calls without human think-time between them.
   */
  async analyzeRequestTiming(ip: string): Promise<{
    isAnomalous: boolean;
    intervalMs: number;
  }> {
    const now = Date.now();
    const key = this.kLastSeen(ip);
    const lastRaw = await this.redis.get(key);

    // Always update — even anomalous requests need their timestamp recorded
    await this.redis.set(key, now.toString(), { ex: 300 });

    if (lastRaw === null) {
      return { isAnomalous: false, intervalMs: Infinity };
    }

    const intervalMs = now - parseInt(lastRaw, 10);
    return {
      isAnomalous: intervalMs < MIN_HUMAN_INTERVAL_MS,
      intervalMs,
    };
  }

  /**
   * Velocity Analysis (L2)
   *
   * Maintains a Redis list of request timestamps per IP and counts
   * how many fall within the sliding velocity window. Autonomous agents
   * generate sustained, structured request bursts that no human workflow
   * could replicate — this is the most reliable detection signal.
   */
  async analyzeVelocity(ip: string): Promise<{
    isExcessive: boolean;
    requestCount: number;
  }> {
    const now = Date.now();
    const windowMs =
      this.config.velocityWindowMs ?? DEFAULTS.velocityWindowMs;
    const maxReq =
      this.config.velocityMaxRequests ?? DEFAULTS.velocityMaxRequests;
    const key = this.kTimestamps(ip);
    const ttlSecs = Math.ceil(windowMs / 1_000) + 10;

    await this.redis.lpush(key, now.toString());
    await this.redis.ltrim(key, 0, 499);
    await this.redis.expire(key, ttlSecs);

    const all = await this.redis.lrange(key, 0, -1);
    const windowStart = now - windowMs;
    const recentCount = all.filter(
      (ts) => parseInt(ts, 10) > windowStart
    ).length;

    return {
      isExcessive: recentCount > maxReq,
      requestCount: recentCount,
    };
  }

  /**
   * User-Agent Analysis (L3)
   *
   * Checks the UA header against curated patterns for HTTP libraries,
   * LLM SDK clients (including Anthropic SDK used by Mythos-class models),
   * and headless automation frameworks.
   *
   * Note: A missing UA is the strongest signal — browsers always send one.
   * UA matching is a soft heuristic; sophisticated agents may spoof their UA.
   * Always pair with L1/L2 behavioral analysis for high-confidence detection.
   */
  analyzeUserAgent(ua: string | null): {
    isSuspicious: boolean;
    reason: string;
  } {
    if (!ua || ua.trim().length === 0) {
      return { isSuspicious: true, reason: "missing" };
    }
    for (const pattern of AGENT_UA_PATTERNS) {
      if (pattern.test(ua)) {
        return { isSuspicious: true, reason: "agent_ua_match" };
      }
    }
    return { isSuspicious: false, reason: "" };
  }

  /**
   * Header Anomaly Detection (L6)
   *
   * Checks HTTP request headers for patterns commonly associated with
   * automated scanners, non-browser clients, and scripts rather than
   * legitimate browser traffic.
   *
   * Browser requests reliably include Accept, Accept-Language, and
   * meaningful Accept-Encoding values. Their absence or wildcard values
   * is a characteristic signal of HTTP client libraries and scanners.
   */
  analyzeHeaders(headers: Headers): {
    isSuspicious: boolean;
    signals: string[];
  } {
    const signals: string[] = [];
    for (const pattern of HEADER_ANOMALY_PATTERNS) {
      if (pattern.check(headers)) {
        signals.push(pattern.name);
      }
    }
    return { isSuspicious: signals.length > 0, signals };
  }

  /**
   * Obfuscation Detection (L4)
   *
   * Recursively walks the parsed request payload and compares string
   * values against known obfuscation patterns. Automated agents encode
   * injection payloads (prompt injections, SQLi, XSS) in Base64 or hex
   * to evade keyword-based filters.
   */
  detectObfuscation(payload: Record<string, unknown>): {
    detected: boolean;
    fields: string[];
  } {
    const hits: string[] = [];

    const walk = (value: unknown, path: string): void => {
      if (typeof value === "string" && value.length > 20) {
        for (const { name, pattern } of OBFUSCATION_PATTERNS) {
          if (pattern.test(value)) {
            hits.push(`${path}[${name}]`);
            return; // One hit per field prevents duplicate scoring
          }
        }
      } else if (Array.isArray(value)) {
        value.forEach((item, i) => walk(item, `${path}[${i}]`));
      } else if (typeof value === "object" && value !== null) {
        for (const [k, v] of Object.entries(value)) {
          walk(v, path ? `${path}.${k}` : k);
        }
      }
    };

    for (const [k, v] of Object.entries(payload)) {
      walk(v, k);
    }

    return { detected: hits.length > 0, fields: hits };
  }
}

// ┌──────────────────────────────────────────────────────────────────┐
// │  § 4  DECOY DATA GENERATOR                                       │
// └──────────────────────────────────────────────────────────────────┘

/**
 * @internal
 *
 * Generates convincing synthetic API response data for the silent honeypot.
 *
 * Design goals: waste attacker resources, return data that appears
 * actionable but leads nowhere, halt agentic pipelines that chain on
 * API output, and rotate shapes to resist fingerprinting.
 *
 * When providing a custom `decoyGenerator`, mirror the real endpoint's
 * exact response structure.
 */
export function generateDecoyResponse(_req: NextRequest): Record<string, unknown> {
  const id = crypto.randomUUID();
  const pastTs = new Date(
    Date.now() - Math.floor(Math.random() * 7_200_000)
  ).toISOString();
  const slot = Math.floor(Math.random() * 4);

  // Generic resource endpoint
  if (slot === 0) {
    return {
      success: true,
      requestId: crypto.randomUUID(),
      timestamp: pastTs,
      data: {
        id,
        status: "active",
        metadata: {
          version: `${Math.floor(Math.random() * 3) + 1}.${Math.floor(Math.random() * 9)}.0`,
          region: ["us-east-1", "eu-west-1", "ap-southeast-1"][
            Math.floor(Math.random() * 3)
          ],
          latencyMs: parseFloat((Math.random() * 80 + 15).toFixed(2)),
        },
      },
    };
  }

  // Auth/token endpoint
  if (slot === 1) {
    return {
      success: true,
      accessToken: btoa(
        `${crypto.randomUUID()}:${Date.now()}:${crypto.randomUUID()}`
      ),
      tokenType: "Bearer",
      expiresIn: 3600,
      scope: "read:self",
      issuedAt: pastTs,
    };
  }

  // Analytics/dashboard endpoint
  if (slot === 3) {
    const metricCount = Math.floor(Math.random() * 4) + 4;
    const metrics = Array.from({ length: metricCount }, (_, i) => ({
      id: crypto.randomUUID(),
      name: [
        "active_users", "api_requests", "error_rate",
        "avg_latency", "throughput", "concurrent_sessions",
        "cache_hit_ratio", "cpu_utilization",
      ][i % 8],
      value: parseFloat((Math.random() * 1000).toFixed(2)),
      unit: ["count", "req/s", "%", "ms", "req/s", "count", "%", "%"][i % 8],
      trend: ["up", "down", "stable"][Math.floor(Math.random() * 3)],
      timestamp: new Date(
        Date.now() - Math.floor(Math.random() * 3_600_000)
      ).toISOString(),
    }));
    return {
      success: true,
      requestId: crypto.randomUUID(),
      dashboard: {
        period: {
          start: new Date(Date.now() - 86_400_000).toISOString(),
          end: new Date().toISOString(),
        },
        metrics,
        summary: {
          totalRequests: Math.floor(Math.random() * 1_000_000) + 100_000,
          avgResponseTime: parseFloat((Math.random() * 200 + 30).toFixed(2)),
          errorBudgetRemaining: parseFloat((Math.random() * 100).toFixed(1)),
        },
      },
    };
  }

  // Paginated list endpoint
  const count = Math.floor(Math.random() * 7) + 3;
  return {
    success: true,
    items: Array.from({ length: count }, (_, i) => ({
      id: crypto.randomUUID(),
      rank: i + 1,
      createdAt: new Date(Date.now() - i * 86_400_000).toISOString(),
      score: parseFloat((Math.random() * 100).toFixed(4)),
      label: `entry_${Math.floor(Math.random() * 90_000) + 10_000}`,
    })),
    pagination: {
      total: Math.floor(Math.random() * 300) + count,
      page: 1,
      pageSize: 20,
      hasNext: true,
    },
  };
}

// ┌──────────────────────────────────────────────────────────────────┐
// │  § 5  HONEYPOT RESPONSE                                          │
// └──────────────────────────────────────────────────────────────────┘

/**
 * @internal
 *
 * Serves a synthetic 200 OK to the detected attacker.
 *
 * Why NOT return 429/403? A block response tells the attacker what
 * triggered detection. A convincing 200 OK:
 *   1. Wastes agent token budget on fake data.
 *   2. Halts agentic pipelines that chain on API output.
 *   3. Gives the attacker no signal they've been detected.
 *
 * "Shadow Ban" pattern applied to API security.
 */
export function serveHoneypot(
  req: NextRequest,
  decoyFn: (r: NextRequest) => Record<string, unknown>,
  ip: string,
  score: number,
  violations: string[],
  debug: boolean
): NextResponse {
  if (debug) {
    console.warn(
      `[hc:honeypot] ip=${ip} score=${score}/100 violations=[${violations.join(" | ")}]`
    );
  }

  const body = decoyFn(req);
  // Randomize processing time to simulate real backend variance
  const fakeLatency = (Math.random() * 120 + 30).toFixed(2);

  const res = NextResponse.json(body, { status: 200 });

  res.headers.set("x-request-id", crypto.randomUUID());
  res.headers.set("x-processing-time", `${fakeLatency}ms`);
  res.headers.set("cache-control", "no-store");

  // Remove any header that might hint at the honeypot infrastructure
  res.headers.delete("x-powered-by");
  res.headers.delete("server");

  return res;
}

// ┌──────────────────────────────────────────────────────────────────┐
// │  § 6  ZERO-TRUST PAYLOAD VALIDATOR                               │
// └──────────────────────────────────────────────────────────────────┘

/**
 * @internal
 *
 * Validates raw parsed JSON against the Zod schema.
 *
 * Error messages are INTENTIONALLY vague. Detailed errors expose
 * the schema structure — an attacker who sees "field 'userId' must
 * be a UUID" can infer the schema and craft payloads that survive
 * validation. We report only constraint count.
 */
export function validatePayload<T>(
  raw: unknown,
  schema: ZodType<T>
): ValidationResult<T> {
  try {
    return { ok: true, data: schema.parse(raw) };
  } catch (err) {
    if (err instanceof ZodError) {
      return {
        ok: false,
        error: `Validation failed (${err.issues.length} constraint${err.issues.length !== 1 ? "s" : ""})`,
        isSchemaViolation: true,
      };
    }
    return {
      ok: false,
      error: "Invalid request format",
      isSchemaViolation: false,
    };
  }
}

/**
 * Recursively applies `.strict()` to all nested ZodObject schemas.
 *
 * Zod's `.strict()` only affects the immediate object it's called on.
 * Nested objects within the shape remain in their default `strip` mode,
 * silently discarding extra fields at those levels.
 *
 * This function walks the schema tree and applies `.strict()` to every
 * ZodObject it finds, ensuring zero-extra-field enforcement at all depths.
 *
 * Handles: objects, arrays, unions, intersections, effects (refine/transform),
 * optional, nullable, records, defaults, and readonly wrappers.
 * Unrecognized types are passed through unchanged.
 */
export function ensureStrict<T>(schema: ZodType<T>): ZodType<T> {
  const def = (schema as unknown as Record<string, unknown>)._def as Record<
    string,
    unknown
  >;
  const typeName = def.typeName as string;

  switch (typeName) {
    case "ZodObject": {
      const obj = schema as unknown as z.AnyZodObject;
      const shape: Record<string, z.ZodTypeAny> = {};
      for (const [key, fieldSchema] of Object.entries(obj.shape)) {
        shape[key] = ensureStrict(fieldSchema as z.ZodTypeAny);
      }
      return z.object(shape).strict() as unknown as ZodType<T>;
    }

    case "ZodArray": {
      const arr = schema as unknown as z.ZodArray<z.ZodTypeAny>;
      return z.array(
        ensureStrict(arr.element)
      ) as unknown as ZodType<T>;
    }

    case "ZodEffects": {
      // ZodEffectsDef uses `schema` (not `innerType`).
      // innerType exists only on ZodOptionalDef/ZodNullableDef.
      const innerSchema = def.schema as z.ZodTypeAny | undefined;
      if (!innerSchema) return schema;

      const strictInner = ensureStrict(innerSchema);
      const eff = def.effect as {
        type: string;
        refinement?: (...args: unknown[]) => unknown;
        transform?: (...args: unknown[]) => unknown;
      };

      // Preserve the original effect — do NOT replace with refine(() => true)
      // Use _refinement() (not refine()) because ZodType.refine() wraps the
      // function with check(val) which passes only `val`, losing the `ctx`
      // parameter that the existing refinement function uses for addIssue().
      if (eff.type === "refinement" && eff.refinement) {
        return strictInner._refinement(
          eff.refinement as z.RefinementEffect<T>["refinement"]
        ) as unknown as ZodType<T>;
      }
      if (eff.type === "transform" && eff.transform) {
        return strictInner.transform(eff.transform) as unknown as ZodType<T>;
      }
      if (eff.type === "preprocess" && eff.transform) {
        return z.preprocess(eff.transform, strictInner) as unknown as ZodType<T>;
      }

      return strictInner as unknown as ZodType<T>;
    }

    case "ZodOptional": {
      const inner = (schema as unknown as z.ZodOptional<z.ZodTypeAny>).unwrap();
      return ensureStrict(inner).optional() as unknown as ZodType<T>;
    }

    case "ZodNullable": {
      const inner = (schema as unknown as z.ZodNullable<z.ZodTypeAny>).unwrap();
      return ensureStrict(inner).nullable() as unknown as ZodType<T>;
    }

    case "ZodUnion": {
      const options = (def.options ?? []) as z.ZodTypeAny[];
      return z.union(
        options.map((o) => ensureStrict(o)) as [
          z.ZodTypeAny,
          z.ZodTypeAny,
          ...z.ZodTypeAny[]
        ]
      ) as unknown as ZodType<T>;
    }

    case "ZodIntersection": {
      return z.intersection(
        ensureStrict(def.left as z.ZodTypeAny),
        ensureStrict(def.right as z.ZodTypeAny)
      ) as unknown as ZodType<T>;
    }

    case "ZodRecord": {
      const rec = schema as unknown as z.ZodRecord;
      return z.record(
        ensureStrict(rec._def.valueType as z.ZodTypeAny)
      ) as unknown as ZodType<T>;
    }

    case "ZodDefault": {
      const inner = ensureStrict(def.innerType as z.ZodTypeAny);
      const dv = def.defaultValue as () => unknown;
      return inner.default(dv()) as unknown as ZodType<T>;
    }

    case "ZodReadonly": {
      return ensureStrict(def.innerType as z.ZodTypeAny)
        .readonly() as unknown as ZodType<T>;
    }

    case "ZodDiscriminatedUnion": {
      const discriminator = def.discriminator as string;
      const opts = (def.options ?? []) as z.ZodTypeAny[];
      return z.discriminatedUnion(
        discriminator,
        opts.map((o) => ensureStrict(o)) as [
          z.ZodDiscriminatedUnionOption<string>,
          ...z.ZodDiscriminatedUnionOption<string>[],
        ]
      ) as unknown as ZodType<T>;
    }

    case "ZodTuple": {
      const tupleItems = def.items as z.ZodTypeAny[] | undefined;
      if (!tupleItems) return schema;
      const strictItems = tupleItems.map(
        (i) => ensureStrict(i)
      ) as unknown as [z.ZodTypeAny, ...z.ZodTypeAny[]];
      const rest = def.rest as z.ZodTypeAny | null;
      return ((rest
        ? z.tuple(strictItems).rest(ensureStrict(rest))
        : z.tuple(strictItems)) as unknown) as ZodType<T>;
    }

    case "ZodBranded": {
      const inner = (
        schema as unknown as z.ZodBranded<z.ZodTypeAny, string>
      ).unwrap() as z.ZodTypeAny;
      return ensureStrict(inner).brand<string>() as unknown as ZodType<T>;
    }

    default:
      return schema;
  }
}

// ┌──────────────────────────────────────────────────────────────────┐
// │  § 7  withHippocrates — PRIMARY EXPORT                           │
// └──────────────────────────────────────────────────────────────────┘

/**
 * `withHippocrates(handler, schema, redis, config?)`
 *
 * A Higher-Order Function that wraps a Next.js App Router handler
 * with a Strict Stateful Defense Architecture.
 *
 * ### Threat Score Table
 *
 * | Layer | Signal                    | Default Points     | Notes                          |
 * |-------|---------------------------|--------------------|--------------------------------|
 * | L0    | Existing score in Redis   | Instant honeypot   | Skips all checks               |
 * | L1    | Request interval < 50ms   | +25 pts            | Sub-human timing               |
 * | L2    | Velocity window exceeded  | +40 pts            | Burst pattern                  |
 * | L3    | Suspicious User-Agent     | +15 pts            | Soft signal, combine with L1/L2|
 * | L4    | Obfuscation in payload    | +100 pts (max)     | Immediate honeypot             |
 * | L5    | Zod .strict() failure     | +100 pts (max)     | Immediate honeypot             |
 * | L6    | Suspicious headers        | +15 pts            | Missing/wildcard Accept, etc.  |
 *
 * ### Silent Honeypot
 * When cumulative score >= `threatScoreThreshold`, the request is
 * transparently rerouted to `decoyGenerator`. The attacker receives
 * a convincing `200 OK` with synthetic data — never a `403` or `429`.
 * The threat score persists in Redis for `threatTtlSeconds`, ensuring
 * all subsequent requests from the same IP are immediately honeypotted.
 *
 * @param handler - The original Next.js App Router route handler
 * @param schema  - Zod schema. **Always use `.strict()`** for Zero-Trust.
 * @param redis   - Redis client (Upstash, ioredis, or redis npm compatible)
 * @param config  - Optional configuration overrides
 *
 * @example
 * ```ts
 * const Schema = z.object({ id: z.string().uuid() }).strict();
 * export const POST = withHippocrates(myHandler, Schema, redisClient);
 * ```
 */
export function withHippocrates<T extends Record<string, unknown>>(
  handler: AppRouteHandler,
  schema: ZodType<T>,
  redis: RedisClient,
  config: HippocratesConfig = {}
): AppRouteHandler {
  // Merge config with defaults once at setup time, not per request
  const cfg = { ...DEFAULTS, ...config };
  const weights: ThreatScoringWeights = {
    ...DEFAULT_WEIGHTS,
    ...(config.scoring ?? {}),
  };
  const decoyFn = config.decoyGenerator ?? generateDecoyResponse;
  const engine = new ThreatScoreEngine(redis, cfg, weights);
  // Apply recursive .strict() to all levels of the schema once at setup time
  const strictSchema = ensureStrict(schema);

  return async function hippocrates(req: NextRequest): Promise<NextResponse> {
    const ip = resolveClientIp(req.headers);
    const requestId = crypto.randomUUID();

    const violations: string[] = [];
    let score = 0;

    try {
      // ── L0: Pre-flight ─────────────────────────────────────────
      // If this IP already has a high score from previous requests,
      // skip all checks and honeypot immediately — save Redis I/O.
      score = await engine.getScore(ip);
      if (score >= cfg.threatScoreThreshold) {
        return serveHoneypot(
          req,
          decoyFn,
          ip,
          score,
          ["preflight_block"],
          cfg.debugMode
        );
      }

      // ── L1: Timing analysis ────────────────────────────────────
      const timing = await engine.analyzeRequestTiming(ip);
      if (timing.isAnomalous) {
        const tag = `timing(${timing.intervalMs}ms)`;
        violations.push(tag);
        score = await engine.addScore(ip, weights.impossibleTiming, tag);
      }

      // ── L2: Velocity (sliding window) ──────────────────────────
      const velocity = await engine.analyzeVelocity(ip);
      if (velocity.isExcessive) {
        const tag = `velocity(${velocity.requestCount}req/${cfg.velocityWindowMs}ms)`;
        violations.push(tag);
        score = await engine.addScore(ip, weights.velocityViolation, tag);
      }

      // ── L3: User-Agent fingerprinting ──────────────────────────
      const ua = engine.analyzeUserAgent(req.headers.get("user-agent"));
      if (ua.isSuspicious) {
        violations.push(`ua:${ua.reason}`);
        score = await engine.addScore(
          ip,
          weights.suspiciousUserAgent,
          `ua_${ua.reason}`
        );
      }

      // ── L6: Header anomaly detection ──────────────────────────
      const headerCheck = engine.analyzeHeaders(req.headers);
      if (headerCheck.isSuspicious) {
        const tag = `header:${headerCheck.signals.join(",")}`;
        violations.push(tag);
        score = await engine.addScore(ip, weights.suspiciousHeaders, tag);
      }

      // ── L4 + L5: Body parsing, obfuscation, Zod validation ─────
      // Only for HTTP methods that carry a body payload.
      let validatedBody: T | null = null;

      if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
        let rawText: string;
        try {
          rawText = await req.text();
        } catch {
          // Generic 400. No leakage.
          return NextResponse.json(
            { error: "Bad Request" },
            { status: 400 }
          );
        }

        let parsed: unknown = null;
        try {
          parsed = JSON.parse(rawText);
        } catch {
          violations.push("non_json_body");
          score = await engine.addScore(
            ip,
            weights.nonJsonBody,
            "non_json_body"
          );
        }

        if (parsed !== null && typeof parsed === "object") {
          // L4: Obfuscation scan
          const obf = engine.detectObfuscation(
            parsed as Record<string, unknown>
          );
          if (obf.detected) {
            const tag = `obfuscation(${obf.fields.join(",")})`;
            violations.push(tag);
            score = await engine.addScore(ip, weights.obfuscationDetected, tag);
          }

          // L5: Zero-Trust Zod validation
          // Skip if already over threshold — no point spending time validating
          if (score < cfg.threatScoreThreshold) {
            const result = validatePayload<T>(parsed, strictSchema);
            if (result.ok) {
              validatedBody = result.data;
            } else {
              violations.push(`schema:${result.error}`);
              score = await engine.addScore(
                ip,
                result.isSchemaViolation
                  ? weights.schemaViolation
                  : weights.nonJsonBody,
                "schema_violation"
              );
            }
          }
        }
      }

      // ── Honeypot decision gate ─────────────────────────────────
      // Final score check after all layers have run.
      if (score >= cfg.threatScoreThreshold) {
        return serveHoneypot(
          req,
          decoyFn,
          ip,
          score,
          violations,
          cfg.debugMode
        );
      }

      // ── PASS: forward clean request to the actual handler ──────
      // Attach threat context as headers for audit logging.
      const forwardHeaders = new Headers(req.headers);
      forwardHeaders.delete("content-length");
      forwardHeaders.set("x-request-id", requestId);
      forwardHeaders.set("x-hippocrates-score", score.toString());
      forwardHeaders.set("x-hippocrates-clean", "1");

      const cleanReq = new NextRequest(req.url, {
        method: req.method,
        headers: forwardHeaders,
        body: validatedBody !== null ? JSON.stringify(validatedBody) : null,
      });

      return await handler(cleanReq);
    } catch (err) {
      // Last-resort catch — never expose stack traces or internal details
      if (cfg.debugMode) {
        console.error("[hc:error] Unhandled middleware exception:", err);
      }
      return NextResponse.json(
        { error: "Internal Server Error" },
        { status: 500 }
      );
    }
  };
}

// ┌──────────────────────────────────────────────────────────────────┐
// │  § 8  PUBLIC RE-EXPORTS                                          │
// └──────────────────────────────────────────────────────────────────┘

// Re-export Zod so consumers import from a single package entry point
export { z } from "zod";
export type { ZodType as ZodSchema };

