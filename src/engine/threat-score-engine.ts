/* eslint-disable no-console -- debug logging controlled by debugMode flag */
/**
 * @file ThreatScoreEngine — Core Redis-backed scoring engine.
 *
 * Manages all Redis state operations:
 *   - Cumulative threat score CRUD (hc:s:{ip})
 *   - Request timing analysis (hc:l:{ip})
 *   - Velocity tracking (hc:t:{ip})
 *   - Built-in analyzer helpers (UA, headers, obfuscation)
 *
 * v1.5 adds:
 *   - Plugin registration via `use()`
 *   - Custom analyzer execution via `runAnalyzers()`
 *   - Event hooks integration
 *
 * v1.6 adds:
 *   - Redis graceful degradation (safe defaults on Redis failure)
 *   - In-memory stats tracker (incrementStats, getStats, resetStats)
 *
 * All state lives in Redis under the `hc:` namespace. Stats are in-memory.
 */

import type { NextRequest } from "next/server";
import type {
  RedisClient,
  HippocratesConfig,
  ThreatScoringWeights,
  AnalyzerPlugin,
  AnalyzerPhase,
  AnalysisContext,
  PhaseResult,
  ThreatScoreEngineLike,
  SecurityStats,
} from "./types";
import {
  DEFAULTS,
  REDIS_NS,
  MIN_HUMAN_INTERVAL_MS,
  AGENT_UA_PATTERNS,
  OBFUSCATION_PATTERNS,
  HEADER_ANOMALY_PATTERNS,
} from "./constants";
import { BUILT_IN_ANALYZERS } from "./analyzers";

/** @internal */
export class ThreatScoreEngine implements ThreatScoreEngineLike {
  private plugins: AnalyzerPlugin[] = [];
  private redisErrors = 0;
  private redisHealthy = true;
  private readonly MAX_REDIS_ERRORS = 3;
  private stats: SecurityStats = {
    totalRequests: 0,
    blockedByPreflight: 0,
    blockedByTiming: 0,
    blockedByVelocity: 0,
    blockedByObfuscation: 0,
    blockedBySchema: 0,
    passedToHandler: 0,
    honeypotServed: 0,
    redisErrors: 0,
  };

  constructor(
    private readonly redis: RedisClient,
    private readonly config: HippocratesConfig,
    private readonly weights: ThreatScoringWeights
  ) {
    // Register built-in analyzers first (with registration index for stable sort)
    let registrationIndex = 0;
    for (const plugin of BUILT_IN_ANALYZERS) {
      this.plugins.push({ ...plugin, _registrationIndex: registrationIndex++ });
    }
    // Register user-provided plugins from config
    if (config.plugins) {
      for (const plugin of config.plugins) {
        this.plugins.push({ ...plugin, _registrationIndex: registrationIndex++ });
      }
    }
    // Sort by priority (lower = runs first), then by registration order for stability
    this.plugins.sort((a, b) => {
      const priorityDiff = (a.priority ?? 100) - (b.priority ?? 100);
      if (priorityDiff !== 0) return priorityDiff;
      return (a._registrationIndex ?? 0) - (b._registrationIndex ?? 0);
    });
  }

  // ── Redis graceful degradation ───────────────────────────────────

  /** Timestamp (ms) when circuit breaker tripped — used for automatic recovery. */
  private circuitBreakerTrippedAt = 0;
  /** Cooldown in ms before attempting Redis recovery (30 seconds). */
  private readonly CIRCUIT_BREAKER_COOLDOWN_MS = 30_000;

  /**
   * Check if Redis is currently healthy.
   * If circuit breaker is tripped but cooldown has elapsed, attempt recovery
   * by running a lightweight Redis operation.
   */
  private async checkRedisHealth(): Promise<boolean> {
    if (this.redisHealthy) return true;

    const elapsed = Date.now() - this.circuitBreakerTrippedAt;
    if (elapsed < this.CIRCUIT_BREAKER_COOLDOWN_MS) {
      return false; // Still in cooldown
    }

    // Attempt recovery with a lightweight Redis ping
    try {
      // Use a no-op set with 1-second TTL to verify Redis is reachable
      await this.redis.set("hc:ping", "1", { ex: 1 });
      // Recovery successful — reset circuit breaker
      this.redisHealthy = true;
      this.redisErrors = 0;
      this.circuitBreakerTrippedAt = 0;
      if (this.config.debugMode) {
        console.log("[hc:redis] Circuit breaker reset — Redis is reachable again");
      }
      return true;
    } catch {
      // Still down — update timestamp so we don't retry every request
      this.circuitBreakerTrippedAt = Date.now();
      return false;
    }
  }

  private handleRedisError(context: string): void {
    // Don't double-count errors once circuit breaker is already open
    if (!this.redisHealthy) return;

    this.redisErrors++;
    this.stats.redisErrors++;
    if (this.redisErrors >= this.MAX_REDIS_ERRORS) {
      this.redisHealthy = false;
      this.circuitBreakerTrippedAt = Date.now();
      if (this.config.debugMode) {
        console.warn(`[hc:redis] Circuit breaker TRIPPED after ${this.MAX_REDIS_ERRORS} errors`);
      }
    }
    if (this.config.debugMode) {
      console.warn(`[hc:redis] Error in ${context} (${this.redisErrors}/${this.MAX_REDIS_ERRORS})`);
    }
  }

  // ── Redis key helpers ──────────────────────────────────────────

  private kScore(ip: string): string {
    return `${REDIS_NS}:s:${ip}`;
  }
  private kTimestamps(ip: string): string {
    return `${REDIS_NS}:t:${ip}`;
  }
  private kLastSeen(ip: string): string {
    return `${REDIS_NS}:l:${ip}`;
  }

  // ── Plugin registration ────────────────────────────────────────

  /**
   * Register a custom analyzer plugin.
   * Plugins run after built-in analyzers in their phase,
   * sorted by priority (ascending), then registration order for stability.
   *
   * @since v1.5
   */
  use(plugin: AnalyzerPlugin): void {
    const registrationIndex = this.plugins.length;
    this.plugins.push({ ...plugin, _registrationIndex: registrationIndex } as AnalyzerPlugin & { _registrationIndex: number });
    this.plugins.sort((a, b) => {
      const priorityDiff = (a.priority ?? 100) - (b.priority ?? 100);
      if (priorityDiff !== 0) return priorityDiff;
      return (a._registrationIndex ?? 0) - (b._registrationIndex ?? 0);
    });
  }

  /**
   * Run all registered analyzers for the given phase.
   * Returns accumulated score and violation tags.
   * Catches individual plugin errors so one bad plugin doesn't crash all.
   *
   * @since v1.5
   */
  async runAnalyzers(
    req: NextRequest,
    context: AnalysisContext,
    phase: AnalyzerPhase
  ): Promise<PhaseResult> {
    let score = 0;
    const violations: string[] = [];

    for (const plugin of this.plugins) {
      if ((plugin.phase ?? "pre-body") !== phase) continue;

      try {
        const result = await plugin.analyze(req, context);
        if (result.score > 0) {
          score += result.score;
          violations.push(...result.tags);

          // Fire hooks for violation events — only pass current plugin's tags
          if (this.config.hooks?.onViolation) {
            this.config.hooks.onViolation({
              ip: context.ip,
              requestId: context.requestId,
              score,
              violations: result.tags,
              analyzerName: plugin.name,
            });
          }
        }
      } catch (err) {
        if (this.config.debugMode) {
          console.warn(`[hc:plugin] Error in analyzer "${plugin.name}":`, err);
        }
      }
    }

    return { score, violations };
  }

  // ── Score operations ───────────────────────────────────────────

  async getScore(ip: string): Promise<number> {
    try {
      if (!await this.checkRedisHealth()) return 0;
      const raw = await this.redis.get(this.kScore(ip));
      return raw !== null ? Math.min(100, parseInt(raw, 10)) : 0;
    } catch {
      this.handleRedisError("getScore");
      return 0; // Safe default: treat as clean
    }
  }

  async addScore(ip: string, points: number, tag: string): Promise<number> {
    try {
      const current = await this.getScore(ip);
      const updated = Math.min(100, current + points);
      const ttl = this.config.threatTtlSeconds ?? DEFAULTS.threatTtlSeconds;

      await this.redis.set(this.kScore(ip), updated, { ex: ttl });

      if (this.config.debugMode) {
        console.log(
          `[hc:score] ip=${ip} +${points} (${tag}) → ${updated}/100`
        );
      }

      return updated;
    } catch {
      this.handleRedisError("addScore");
      return points; // Return the attempted points to not lose the violation
    }
  }

  // ── L1: Timing Analysis ────────────────────────────────────────

  async analyzeRequestTiming(ip: string): Promise<{
    isAnomalous: boolean;
    intervalMs: number;
  }> {
    if (!await this.checkRedisHealth()) {
      return { isAnomalous: false, intervalMs: Infinity };
    }
    try {
      const now = Date.now();
      const key = this.kLastSeen(ip);
      const lastRaw = await this.redis.get(key);

      await this.redis.set(key, now.toString(), { ex: 300 });

      if (lastRaw === null) {
        return { isAnomalous: false, intervalMs: Infinity };
      }

      const intervalMs = now - parseInt(lastRaw, 10);
      return {
        isAnomalous: intervalMs < MIN_HUMAN_INTERVAL_MS,
        intervalMs,
      };
    } catch {
      this.handleRedisError("analyzeRequestTiming");
      return { isAnomalous: false, intervalMs: Infinity };
    }
  }

  // ── L2: Velocity Analysis ──────────────────────────────────────

  async analyzeVelocity(ip: string): Promise<{
    isExcessive: boolean;
    requestCount: number;
  }> {
    if (!await this.checkRedisHealth()) {
      return { isExcessive: false, requestCount: 0 };
    }
    try {
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
    } catch {
      this.handleRedisError("analyzeVelocity");
      return { isExcessive: false, requestCount: 0 };
    }
  }

  // ── L3: User-Agent Analysis ────────────────────────────────────

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

  // ── L6: Header Anomaly Detection ───────────────────────────────

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

  // ── L4: Obfuscation Detection ──────────────────────────────────

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
            return;
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

  // ── Stats tracker (v1.6) ───────────────────────────────────────

  incrementStats(counter: keyof SecurityStats): void {
    this.stats[counter]++;
    // Also forward to consumer-provided StatsTracker if configured
    this.config.statsTracker?.increment(counter);
  }

  getStats(): SecurityStats {
    return { ...this.stats };
  }

  resetStats(): void {
    this.stats = {
      totalRequests: 0,
      blockedByPreflight: 0,
      blockedByTiming: 0,
      blockedByVelocity: 0,
      blockedByObfuscation: 0,
      blockedBySchema: 0,
      passedToHandler: 0,
      honeypotServed: 0,
      redisErrors: 0,
    };
  }
}
