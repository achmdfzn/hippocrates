/**
 * @package hippocrates
 * @description Enterprise-grade Next.js App Router security middleware.
 *
 * A "digital vaccine" implementing Strict Stateful Defense Architecture
 * to protect APIs from autonomous AI agents (LLM-based tooling, agentic
 * pipelines, headless browsers) and malicious automated scripts.
 *
 * v1.5 introduces:
 *   - AnalyzerPlugin system for custom detection logic
 *   - HippocratesHooks for security event monitoring
 *   - Modular engine + system architecture
 *
 * v1.6 introduces:
 *   - Redis graceful degradation (safe defaults on Redis failure)
 *   - IP allowlist (exact + CIDR match)
 *   - Request body size limits
 *   - Per-HTTP-method threat thresholds
 *   - Config presets (strict, moderate, relaxed)
 *   - Custom violation messages for honeypot
 *   - In-memory stats tracker
 *   - 2026 AI agent UA patterns
 *
 * Defense Layers (in execution order):
 *   L-1 — IP allowlist (skip all checks for trusted IPs)
 *   L0 — Pre-flight existing threat score check
 *   L1 — Sub-human request timing detection (< 50ms)
 *   L2 — Sliding-window velocity tracking
 *   L3 — User-Agent fingerprinting (HTTP libs, LLM SDKs, headless)
 *   L4 — Payload obfuscation detection (Base64, Hex, URL, Unicode)
 *   L5 — Zero-Trust Zod schema validation (.strict() enforced)
 *   L6 — Header anomaly detection
 *
 * @version 1.6.0
 * @license MIT
 */

// ── Engine exports ────────────────────────────────────────────────

export { ThreatScoreEngine } from "./engine/threat-score-engine";
export type {
  // Core types
  RedisClient,
  ThreatScoringWeights,
  HippocratesConfig,
  AppRouteHandler,
  ValidationResult,
  ThreatScoreEngineLike,
  // Plugin system (v1.5)
  AnalyzerPlugin,
  AnalyzerPhase,
  AnalysisContext,
  AnalysisResult,
  PhaseResult,
  // Event hooks (v1.5)
  HippocratesHooks,
  ViolationEvent,
  PassEvent,
  HoneypotEvent,
  // Pattern types
  ObfuscationPattern,
  HeaderAnomalyPattern,
  // v1.6 types
  AllowlistConfig,
  SecurityStats,
  SecurityPreset,
  BodyLimitConfig,
  StatsTracker,
} from "./engine/types";

export {
  DEFAULTS,
  DEFAULT_WEIGHTS,
  AGENT_UA_PATTERNS,
  OBFUSCATION_PATTERNS,
  HEADER_ANOMALY_PATTERNS,
  MIN_HUMAN_INTERVAL_MS,
  REDIS_NS,
  PRESETS,
  DEFAULT_BODY_LIMIT,
} from "./engine/constants";

export {
  timingAnalyzer,
  velocityAnalyzer,
  userAgentAnalyzer,
  obfuscationAnalyzer,
  schemaAnalyzer,
  headerAnalyzer,
  BUILT_IN_ANALYZERS,
} from "./engine/analyzers";

// ── System exports ─────────────────────────────────────────────────

export { generateDecoyResponse, serveHoneypot } from "./system/honeypot";
export { validatePayload, ensureStrict } from "./system/validator";
export { HippocratesPipeline } from "./system/pipeline";

// ── Utility exports ────────────────────────────────────────────────

export { normalizeIp, resolveClientIp } from "./utils/ip";

// ── Primary API: withHippocrates HOF ───────────────────────────────

import { NextRequest, NextResponse } from "next/server";
import { ZodType } from "zod";
import type { HippocratesConfig, RedisClient, AppRouteHandler, SecurityPreset } from "./engine/types";
import { PRESETS } from "./engine/constants";
import { HippocratesPipeline } from "./system/pipeline";

/**
 * Resolve configuration with preset support.
 * Applies preset defaults first, then merges user overrides on top.
 * For nested configs (scoring), deep-merge is performed.
 *
 * @since v1.6
 */
export function resolveConfig(config: HippocratesConfig): HippocratesConfig {
  if (!config.preset) return config;
  const preset = PRESETS[config.preset as SecurityPreset];
  if (!preset) return config;
  // Merge: preset defaults → user overrides
  return {
    ...preset,
    ...config,
    scoring: { ...preset.scoring, ...config.scoring },
    methodThresholds: { ...preset.methodThresholds, ...config.methodThresholds },
  };
}

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
 * | L-1   | IP allowlist (v1.6)       | 0 (skip all)      | Trusted IPs bypass all checks  |
 * | L0    | Existing score in Redis   | Instant honeypot   | Skips all checks               |
 * | L1    | Request interval < 50ms   | +25 pts            | Sub-human timing               |
 * | L2    | Velocity window exceeded  | +40 pts            | Burst pattern                  |
 * | L3    | Suspicious User-Agent     | +15 pts            | Soft signal, combine with L1/L2|
 * | L4    | Obfuscation in payload    | +100 pts (max)     | Immediate honeypot             |
 * | L5    | Zod .strict() failure     | +100 pts (max)     | Immediate honeypot             |
 * | L6    | Suspicious headers        | +15 pts            | Missing/wildcard Accept, etc.  |
 *
 * ### Plugin System (v1.5)
 * Register custom detection analyzers:
 * ```ts
 * const myAnalyzer: AnalyzerPlugin = {
 *   name: "custom_check",
 *   phase: "pre-body",
 *   priority: 50,
 *   analyze(req, ctx) {
 *     if (req.headers.get("x-custom") === "bad") {
 *       return { score: 30, tags: ["custom:bad"] };
 *     }
 *     return { score: 0, tags: [] };
 *   },
 * };
 *
 * export const POST = withHippocrates(handler, schema, redis, {
 *   plugins: [myAnalyzer],
 * });
 * ```
 *
 * ### Event Hooks (v1.5)
 * Monitor security events:
 * ```ts
 * export const POST = withHippocrates(handler, schema, redis, {
 *   hooks: {
 *     onViolation: (event) => sendAlert(event),
 *     onPass: (event) => logMetric(event),
 *     onHoneypot: (event) => incrementCounter(event),
 *   },
 * });
 * ```
 *
 * @param handler - The original Next.js App Router route handler
 * @param schema  - Zod schema. **Always use `.strict()`** for Zero-Trust.
 * @param redis   - Redis client (Upstash, ioredis, or redis npm compatible)
 * @param config  - Optional configuration overrides (v1.5: plugins, hooks; v1.6: presets, allowlist, bodyLimit, methodThresholds, violationMessages)
 *
 * @example
 * ```ts
 * const Schema = z.object({ id: z.string().uuid() }).strict();
 * export const POST = withHippocrates(myHandler, Schema, redisClient);
 * ```
 *
 * @example
 * ```ts
 * // With preset
 * export const POST = withHippocrates(handler, schema, redis, {
 *   preset: "strict",
 * });
 * ```
 *
 * @example
 * ```ts
 * // With custom violation messages
 * export const POST = withHippocrates(handler, schema, redis, {
 *   violationMessages: {
 *     obfuscation: () => ({ error: "invalid_format" }),
 *   },
 * });
 * ```
 */
export function withHippocrates<T extends Record<string, unknown>>(
  handler: AppRouteHandler,
  schema: ZodType<T>,
  redis: RedisClient,
  config: HippocratesConfig = {}
): AppRouteHandler {
  // Apply preset resolution before creating the pipeline
  const resolvedConfig = resolveConfig(config);

  // Create the pipeline once at setup time
  const pipeline = new HippocratesPipeline(
    handler,
    schema as ZodType<Record<string, unknown>>,
    redis,
    resolvedConfig
  );

  return async function hippocrates(req: NextRequest): Promise<NextResponse> {
    return pipeline.execute(req);
  };
}

// ── Re-exports ─────────────────────────────────────────────────────

// Re-export Zod so consumers import from a single package entry point
export { z } from "zod";
export type { ZodType as ZodSchema };
