/**
 * @file Engine & system type definitions for hippocrates.
 *
 * v1.5 introduces:
 *   - AnalyzerPlugin system for custom detection logic
 *   - HippocratesHooks for violation/pass/honeypot events
 *   - Pipeline orchestration with phased analyzer execution
 */

import type { NextRequest, NextResponse } from "next/server";

// ── Redis adapter ───────────────────────────────────────────────────

/**
 * Minimal Redis adapter interface designed for maximum portability.
 *
 * Compatible with:
 *   - @upstash/redis  → Recommended for Vercel / Next.js Edge deployments
 *   - ioredis         → Recommended for self-hosted Node.js servers
 *   - redis (npm)     → Node.js official Redis client
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

// ── Scoring weights ─────────────────────────────────────────────────

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

// ── Analyzer plugin system (NEW in v1.5) ────────────────────────────

/**
 * Detection phase for analyzer plugins.
 * - pre-body  → Runs before body parsing (timing, velocity, UA, headers).
 * - post-body → Runs after body parsing (obfuscation, schema, content checks).
 */
export type AnalyzerPhase = "pre-body" | "post-body";

export interface AnalysisContext {
  /** Resolved client IP address */
  ip: string;
  /** Unique request identifier */
  requestId: string;
  /** Reference to the ThreatScoreEngine for Redis state access */
  engine: ThreatScoreEngineLike;
  /** Resolved configuration (read-only) */
  config: Readonly<HippocratesConfig>;
  /** Resolved scoring weights (read-only) */
  weights: Readonly<ThreatScoringWeights>;
  /** Raw request body text, if available (populated in post-body phase) */
  bodyRaw?: string;
}

export interface AnalysisResult {
  /** Points to add to the threat score (0 = no violation) */
  score: number;
  /** Violation tags for audit logging */
  tags: string[];
}

/**
 * Plugin interface for custom detection analyzers.
 *
 * Register analyzers via withHippocrates() config:
 * `	s
 * withHippocrates(handler, schema, redis, {
 *   plugins: [myCustomAnalyzer],
 * })
 * `
 */
export interface AnalyzerPlugin {
  /** Unique analyzer name (appears in violation tags) */
  name: string;
  /**
   * Execution phase:
   * - pre-body  → Before body parsing (default)
   * - post-body → After body parsing
   * @default "pre-body"
   */
  phase?: AnalyzerPhase;
  /**
   * Execution priority. Lower values run first.
   * Built-in analyzers use: L1=10, L2=20, L3=30, L6=40, L4=10(post), L5=20(post)
   * @default 100
   */
  priority?: number;
  /**
   * The detection function. Return score=0 to indicate no violation.
   * Score is added to the cumulative threat score via engine.addScore().
   */
  analyze(
    req: NextRequest,
    context: AnalysisContext
  ): Promise<AnalysisResult> | AnalysisResult;

  /** @internal Used for stable sort — do not set manually */
  _registrationIndex?: number;
}

// ── Event hooks (NEW in v1.5) ───────────────────────────────────────

export interface ViolationEvent {
  ip: string;
  requestId: string;
  score: number;
  violations: string[];
  /** Name of the analyzer that triggered the violation */
  analyzerName: string;
}

export interface PassEvent {
  ip: string;
  requestId: string;
  score: number;
}

export interface HoneypotEvent {
  ip: string;
  requestId: string;
  score: number;
  violations: string[];
  /** The decoy response body sent to the attacker */
  decoyResponse: Record<string, unknown>;
}

export interface HippocratesHooks {
  /** Fired when any analyzer detects a violation (score > 0) */
  onViolation?: (event: ViolationEvent) => void;
  /** Fired when a request passes all checks and is forwarded to the handler */
  onPass?: (event: PassEvent) => void;
  /** Fired when a request is routed to the honeypot */
  onHoneypot?: (event: HoneypotEvent) => void;
}

// ── IP Allowlist ────────────────────────────────────────────────────

/** @since v1.6 */
export interface AllowlistConfig {
  /** IPs/CIDRs to skip all security checks */
  ips: string[];
  /** If true, also check x-forwarded-for header */
  checkProxied?: boolean;
}

// ── Security Stats ─────────────────────────────────────────────────

/** @since v1.6 */
export interface SecurityStats {
  totalRequests: number;
  blockedByPreflight: number;
  blockedByTiming: number;
  blockedByVelocity: number;
  blockedByObfuscation: number;
  blockedBySchema: number;
  passedToHandler: number;
  honeypotServed: number;
  redisErrors: number;
}

// ── Config Presets ─────────────────────────────────────────────────

/** @since v1.6 */
export type SecurityPreset = "strict" | "moderate" | "relaxed";

// ── Body Limit ─────────────────────────────────────────────────────

/** @since v1.6 */
export interface BodyLimitConfig {
  maxBytes: number;
  enabled: boolean;
}

// ── Stats Tracker ──────────────────────────────────────────────────

/** @since v1.6 */
export interface StatsTracker {
  increment(counter: keyof SecurityStats): void;
  getStats(): SecurityStats;
  reset(): void;
}

// ── Configuration ───────────────────────────────────────────────────

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
   * Exceeding this adds elocityViolation points to the threat score.
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

  /**
   * Custom analyzer plugins. Runs after built-in L1-L6 analyzers
   * in the specified phase (pre-body or post-body).
   * @since v1.5
   */
  plugins?: AnalyzerPlugin[];

  /**
   * Event hooks for monitoring violations, passes, and honeypot events.
   * @since v1.5
   */
  hooks?: HippocratesHooks;

  /** @since v1.6 */
  allowlist?: AllowlistConfig;

  /** @since v1.6 */
  bodyLimit?: BodyLimitConfig;

  /** @since v1.6 */
  methodThresholds?: Partial<Record<string, number>>;

  /** @since v1.6 */
  preset?: SecurityPreset;

  /** @since v1.6 */
  statsTracker?: StatsTracker;

  /** @since v1.6 */
  violationMessages?: Partial<
    Record<string, (violation: string) => Record<string, unknown>>
  >;
}

// ── Handler types ───────────────────────────────────────────────────

export type AppRouteHandler = (
  req: NextRequest
) => Promise<NextResponse> | NextResponse;

/**
 * Discriminated union (uses ok not success to avoid collision
 * with common API response shapes that return { success: true }).
 */
export type ValidationResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; isSchemaViolation: boolean };

// ── Engine interface (minimal surface for AnalysisContext) ──────────

/**
 * Minimal interface that AnalyzerPlugin sees of the ThreatScoreEngine.
 * Only exposes score operations — not internal analyzers.
 */
export interface ThreatScoreEngineLike {
  getScore(ip: string): Promise<number>;
  addScore(ip: string, points: number, tag: string): Promise<number>;
  /** @since v1.6 */
  getStats(): SecurityStats;
}

// ── Pattern types (for constants) ───────────────────────────────────

export interface ObfuscationPattern {
  name: string;
  pattern: RegExp;
}

export interface HeaderAnomalyPattern {
  name: string;
  check: (headers: Headers) => boolean;
}

// ── Plugin result accumulator ───────────────────────────────────────

/** @internal Aggregated result from running a set of analyzers */
export interface PhaseResult {
  score: number;
  violations: string[];
}
