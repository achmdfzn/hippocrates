/**
 * @file ML Engine AnalyzerPlugin — HTTP client to the Python sidecar.
 *
 * Sends request data to the ML detection engine for deep analysis
 * (prompt injection, advanced obfuscation, content risk scoring).
 *
 * Design:
 * - Non-blocking: runs as a post-body plugin, adds to existing score
 * - Graceful degradation: ML engine unreachable → score=0, no crash
 * - Circuit breaker: 3 consecutive failures → skip requests for 30s
 * - Retry with backoff: one retry (100ms, then 200ms) before degrading
 * - Body data is delivered via AnalysisContext.bodyRaw (populated by pipeline
 *   after body parsing, avoiding double-consumption of the request body stream)
 * - Configurable endpoint via env or plugin constructor
 */

import type { NextRequest } from "next/server";
import type {
  AnalyzerPlugin,
  AnalysisContext,
  AnalysisResult,
} from "../engine/types";

// ── Types ────────────────────────────────────────────────────────────

interface MlEngineRequestBody {
  request_id: string;
  ip: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body: Record<string, unknown> | unknown[] | string | null;
  body_raw: string | null;
}

interface MlEngineResponse {
  score: number;
  tags: string[];
  analyses: Record<string, { score: number; tags: string[]; confidence: number }>;
}

// ── Plugin Implementation ────────────────────────────────────────────

export interface MlEnginePluginOptions {
  /** Base URL of the ML engine (default: env var or http://localhost:8000) */
  baseUrl?: string;
  /** Request timeout in ms (default: 3000) */
  timeoutMs?: number;
  /** Minimum ML score to contribute to threat score (default: 10) */
  minScoreThreshold?: number;
  /** Maximum retries on failure (default: 1) */
  maxRetries?: number;
  /** Circuit breaker cooldown in ms after max consecutive failures (default: 30000) */
  circuitBreakerCooldownMs?: number;
  /** Max consecutive failures before circuit breaker trips (default: 3) */
  maxConsecutiveFailures?: number;
}

const DEFAULT_OPTIONS: Required<MlEnginePluginOptions> = {
  baseUrl: process.env.HIPPOCRATES_ML_URL ?? "http://localhost:8000",
  timeoutMs: 3_000,
  minScoreThreshold: 10,
  maxRetries: 1,
  circuitBreakerCooldownMs: 30_000,
  maxConsecutiveFailures: 3,
};

/**
 * Sleep helper for retry backoff.
 */
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Creates an AnalyzerPlugin that sends request data to the Python ML engine.
 *
 * The plugin runs in the post-body phase. The request body is delivered
 * via `context.bodyRaw` (populated by the pipeline after body parsing),
 * avoiding double-consumption of the request body stream.
 *
 * Features built-in retry with exponential backoff and a circuit breaker
 * that trips after `maxConsecutiveFailures` consecutive errors and
 * auto-recovers after `circuitBreakerCooldownMs`.
 *
 * @example
 * ```typescript
 * import { mlEnginePlugin } from "hippocrates";
 *
 * withHippocrates(handler, schema, redis, {
 *   plugins: [mlEnginePlugin({ baseUrl: "http://ml-engine:8000" })],
 * });
 * ```
 */
export function mlEnginePlugin(
  options?: MlEnginePluginOptions,
): AnalyzerPlugin {
  const opts: Required<MlEnginePluginOptions> = {
    ...DEFAULT_OPTIONS,
    ...options,
  };

  // ── Circuit breaker state (per plugin instance) ──────────────────
  let consecutiveFailures = 0;
  let circuitBreakerTrippedAt = 0;

  const isCircuitBreakerOpen = (): boolean => {
    if (consecutiveFailures < opts.maxConsecutiveFailures) return false;
    const elapsed = Date.now() - circuitBreakerTrippedAt;
    if (elapsed >= opts.circuitBreakerCooldownMs) {
      // Attempt recovery — reset on cooldown expiry
      consecutiveFailures = 0;
      circuitBreakerTrippedAt = 0;
      return false;
    }
    return true;
  };

  return {
    name: "ml-engine",
    phase: "post-body",
    priority: 50, // Run after built-in L4/L5 analyzers

    async analyze(
      req: NextRequest,
      context: AnalysisContext,
    ): Promise<AnalysisResult> {
      // ── Circuit breaker check ─────────────────────────────────
      if (isCircuitBreakerOpen()) {
        return { score: 0, tags: ["ml-engine-circuit-breaker"] };
      }

      // ── Build request body ────────────────────────────────────
      const headers: Record<string, string> = {};
      req.headers.forEach((value, key) => {
        headers[key] = value;
      });

      let parsedBody: Record<string, unknown> | unknown[] | string | null = null;
      if (context.bodyRaw) {
        try {
          parsedBody = JSON.parse(context.bodyRaw);
        } catch {
          parsedBody = context.bodyRaw;
        }
      }

      const mlBody: MlEngineRequestBody = {
        request_id: context.requestId,
        ip: context.ip,
        method: req.method,
        path: req.nextUrl?.pathname ?? req.url,
        headers,
        body: parsedBody,
        body_raw: context.bodyRaw ?? null,
      };

      // ── Attempt request with retries ──────────────────────────

      for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
        if (attempt > 0) {
          // Exponential backoff: 100ms, 200ms
          await sleep(100 * Math.pow(2, attempt - 1));
        }

        try {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), opts.timeoutMs);

          const response = await fetch(`${opts.baseUrl}/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(mlBody),
            signal: controller.signal,
          });

          clearTimeout(timer);

          if (!response.ok) {
            // Non-200 is not a transient error — don't retry
            consecutiveFailures = 0; // Reset, this is a valid response
            return { score: 0, tags: ["ml-engine-error"] };
          }

          const result: MlEngineResponse = await response.json();

          // Success — reset circuit breaker
          consecutiveFailures = 0;

          if (result.score < opts.minScoreThreshold) {
            return { score: 0, tags: [] };
          }

          return {
            score: result.score,
            tags: result.tags.map((t) => `ml:${t}`),
          };
          } catch {
          // Fall through to retry or degrade
        }
      }

      // ── All attempts failed — degrade gracefully ──────────────
      consecutiveFailures++;
      if (consecutiveFailures >= opts.maxConsecutiveFailures) {
        circuitBreakerTrippedAt = Date.now();
      }

      return { score: 0, tags: ["ml-engine-unreachable"] };
    },
  };
}
