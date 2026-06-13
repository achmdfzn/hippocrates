/* eslint-disable no-console -- debug logging controlled by debugMode flag */
/**
 * @file Pipeline orchestrator — runs the defense layers in order.
 *
 * The pipeline manages the full request lifecycle:
 *   L0 → Pre-body analyzers → Score gate → Body parsing → Post-body analyzers → Final gate
 *
 * Custom analyzers registered via config.plugins run alongside built-in
 * L1–L6 analyzers, sorted by priority within each phase.
 */
import { NextRequest, NextResponse } from "next/server";
import { ZodType } from "zod";
import type {
  HippocratesConfig,
  ThreatScoringWeights,
  RedisClient,
  AppRouteHandler,
  AnalysisContext,
  PhaseResult,
} from "../engine/types";
import { DEFAULTS, DEFAULT_WEIGHTS, DEFAULT_BODY_LIMIT } from "../engine/constants";
import { ThreatScoreEngine } from "../engine/threat-score-engine";
import { generateDecoyResponse, serveHoneypot } from "./honeypot";
import { validatePayload, ensureStrict } from "./validator";
import { resolveClientIp } from "../utils/ip";
// ── Pipeline class ─────────────────────────────────────────────────
/**
 * Request processing pipeline that orchestrates all security layers.
 *
 * Created once per `withHippocrates()` call and reused for all requests.
 */
export class HippocratesPipeline {
  private readonly cfg: HippocratesConfig;
  private readonly weights: ThreatScoringWeights;
  private readonly decoyFn: (req: NextRequest) => Record<string, unknown>;
  private readonly engine: ThreatScoreEngine;
  private readonly strictSchema: ZodType<Record<string, unknown>>;
  private readonly handler: AppRouteHandler;
  constructor(
    handler: AppRouteHandler,
    schema: ZodType<Record<string, unknown>>,
    redis: RedisClient,
    config: HippocratesConfig = {}
  ) {
    // Deep-merge config once at setup time — never per request
    // bodyLimit uses explicit deep merge so partial user overrides (e.g. { maxBytes })
    // still inherit defaults for unspecified fields (e.g. enabled).
    this.cfg = {
      ...DEFAULTS,
      ...config,
      bodyLimit: config.bodyLimit
        ? { ...DEFAULT_BODY_LIMIT, ...config.bodyLimit }
        : DEFAULT_BODY_LIMIT,
    };
    this.weights = { ...DEFAULT_WEIGHTS, ...(config.scoring ?? {}) };
    this.decoyFn = config.decoyGenerator ?? generateDecoyResponse;
    this.strictSchema = ensureStrict(schema) as ZodType<Record<string, unknown>>;
    this.handler = handler;
    // Create engine (registers built-in + custom plugins)
    this.engine = new ThreatScoreEngine(redis, this.cfg, this.weights);
  }
  // ── Main entry point ───────────────────────────────────────────
  async execute(req: NextRequest): Promise<NextResponse> {
    const ip = resolveClientIp(req.headers);
    const requestId = crypto.randomUUID();
    const violations: string[] = [];
    let score = 0;
    try {
      this.engine.incrementStats("totalRequests");

      // ── L-1: IP allowlist (v1.6) ──────────────────────────────
      if (this.cfg.allowlist && await this.isIpAllowed(ip)) {
        // Skip all security checks, forward directly to handler
        // Read body for non-GET requests so POST/PUT/PATCH body isn't lost
        let allowlistBody: Record<string, unknown> | null = null;
        if (!["GET", "HEAD", "OPTIONS"].includes(req.method)) {
          try {
            const text = await req.text();
            if (text) {
              const parsed = JSON.parse(text);
              if (typeof parsed === "object" && parsed !== null) {
                allowlistBody = parsed as Record<string, unknown>;
              }
            }
          } catch {
            // Body not available or not parseable — forward without body
          }
        }
        return await this.forwardToHandler(req, ip, 0, requestId, allowlistBody);
      }
      // ── L0: Pre-flight ───────────────────────────────────────
      score = await this.engine.getScore(ip);
      if (score >= this.getEffectiveThreshold(req.method)) {
        this.engine.incrementStats("blockedByPreflight");
        this.engine.incrementStats("honeypotServed");
        return this.sendToHoneypot(req, ip, score, ["preflight_block"], requestId);
      }
      // ── Pre-body analyzers (L1, L2, L3, L4 + custom) ─────────
      const preBodyResult = await this.runPreBodyAnalyzers(req, ip, requestId);
      score += preBodyResult.score;
      violations.push(...preBodyResult.violations);
      // ── Mid-flight score gate ─────────────────────────────────
      if (score >= this.getEffectiveThreshold(req.method)) {
        this.engine.incrementStats("honeypotServed");
        return this.sendToHoneypot(req, ip, score, violations, requestId);
      }
      // ── Body parsing + Post-body analyzers (L5, L6 + custom) ─
      const bodyResult = await this.processBody(req, ip, requestId);
      score += bodyResult.score;
      violations.push(...bodyResult.violations);
      // ── Final score gate ──────────────────────────────────────
      if (score >= this.getEffectiveThreshold(req.method)) {
        this.engine.incrementStats("honeypotServed");
        return this.sendToHoneypot(req, ip, score, violations, requestId);
      }
      // ── PASS: Forward to handler ──────────────────────────────
      this.engine.incrementStats("passedToHandler");
      return await this.forwardToHandler(req, ip, score, requestId, bodyResult.validatedBody);
    } catch (err) {
      if (this.cfg.debugMode) {
        console.error("[hc:error] Unhandled pipeline exception:", err);
      }
      return NextResponse.json(
        { error: "Internal Server Error" },
        { status: 500 }
      );
    }
  }
  // ── IP allowlist (v1.6) ─────────────────────────────────────────
  private async isIpAllowed(ip: string): Promise<boolean> {
    const allowlist = this.cfg.allowlist;
    if (!allowlist?.ips.length) return false;
    // Exact match first
    if (allowlist.ips.includes(ip)) return true;
    // CIDR prefix match using proper bitwise comparison
    for (const entry of allowlist.ips) {
      if (entry.includes("/")) {
        const parts = entry.split("/");
        const cidrIp = parts[0];
        const bits = parts[1];
        if (cidrIp && bits) {
          const maskLen = parseInt(bits, 10);
          if (!isNaN(maskLen) && maskLen >= 0 && maskLen <= 32 && this.isIpInCidr(ip, cidrIp, maskLen)) {
            return true;
          }
        }
      }
    }
    return false;
  }

  /** Convert dotted IPv4 string to 32-bit unsigned integer. */
  private ipToInt(ip: string): number | null {
    const parts = ip.split(".");
    if (parts.length !== 4) return null;
    let result = 0;
    for (const part of parts) {
      const octet = parseInt(part, 10);
      if (isNaN(octet) || octet < 0 || octet > 255) return null;
      result = (result << 8) + octet;
    }
    return result >>> 0;
  }

  /** Check if an IP falls within a CIDR range using bitwise mask comparison. */
  private isIpInCidr(ip: string, cidrIp: string, maskLen: number): boolean {
    const ipInt = this.ipToInt(ip);
    const cidrInt = this.ipToInt(cidrIp);
    if (ipInt === null || cidrInt === null) return false;
    const mask = ~(0xFFFFFFFF >>> maskLen) >>> 0;
    return (ipInt & mask) === (cidrInt & mask);
  }
  private getEffectiveThreshold(method: string): number {
    const base = this.cfg.threatScoreThreshold ?? DEFAULTS.threatScoreThreshold;
    const methodThresholds = this.cfg.methodThresholds;
    if (methodThresholds && methodThresholds[method] !== undefined) {
      return methodThresholds[method];
    }
    return base;
  }
  // ── Pre-body analyzers ─────────────────────────────────────────
  private async runPreBodyAnalyzers(
    req: NextRequest,
    ip: string,
    requestId: string
  ): Promise<PhaseResult> {
    let score = 0;
    const violations: string[] = [];
    // L1: Timing analysis (Redis state — runs directly on engine)
    const timing = await this.engine.analyzeRequestTiming(ip);
    if (timing.isAnomalous) {
      const tag = `timing(${timing.intervalMs}ms)`;
      violations.push(tag);
      score += this.weights.impossibleTiming;
      await this.engine.addScore(ip, this.weights.impossibleTiming, tag);
      this.engine.incrementStats("blockedByTiming");
    }
    // L2: Velocity analysis (Redis state — runs directly on engine)
    const velocity = await this.engine.analyzeVelocity(ip);
    if (velocity.isExcessive) {
      const tag = `velocity(${velocity.requestCount}req/${this.cfg.velocityWindowMs}ms)`;
      violations.push(tag);
      score += this.weights.velocityViolation;
      await this.engine.addScore(ip, this.weights.velocityViolation, tag);
      this.engine.incrementStats("blockedByVelocity");
    }
    // L3: User-Agent fingerprinting
    const ua = this.engine.analyzeUserAgent(req.headers.get("user-agent"));
    if (ua.isSuspicious) {
      violations.push(`ua:${ua.reason}`);
      score += this.weights.suspiciousUserAgent;
      await this.engine.addScore(ip, this.weights.suspiciousUserAgent, `ua_${ua.reason}`);
    }
    // L4: Header anomaly detection
    const headerCheck = this.engine.analyzeHeaders(req.headers);
    if (headerCheck.isSuspicious) {
      const tag = `header:${headerCheck.signals.join(",")}`;
      violations.push(tag);
      score += this.weights.suspiciousHeaders;
      await this.engine.addScore(ip, this.weights.suspiciousHeaders, tag);
    }
    // Custom pre-body analyzers from plugins
    const ctx = this.makeContext(ip, requestId);
    const pluginResult = await this.engine.runAnalyzers(req, ctx, "pre-body");
    score += pluginResult.score;
    violations.push(...pluginResult.violations);
    return { score, violations };
  }
  // ── Body processing + Post-body analyzers ─────────────────────
  private async processBody(
    req: NextRequest,
    ip: string,
    requestId: string
  ): Promise<PhaseResult & { validatedBody: Record<string, unknown> | null }> {
    let score = 0;
    const violations: string[] = [];
    let validatedBody: Record<string, unknown> | null = null;
    // Skip body parsing for GET, HEAD, OPTIONS
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      const ctx = this.makeContext(ip, requestId);
      const pluginResult = await this.engine.runAnalyzers(req, ctx, "post-body");
      return { score: pluginResult.score, violations: pluginResult.violations, validatedBody: null };
    }
    // Body size limit check (v1.6) — check content-length header first
    const bodyLimit = this.cfg.bodyLimit as { maxBytes: number; enabled: boolean };
    if (bodyLimit.enabled) {
      const contentLength = req.headers.get("content-length");
      if (contentLength && parseInt(contentLength, 10) > bodyLimit.maxBytes) {
        violations.push("body_too_large");
        score += 10; // Small penalty, not honeypot-level
        await this.engine.addScore(ip, 10, "body_too_large");
      }
    }
    // Parse body
    let rawText: string;
    try {
      rawText = await req.text();
    } catch {
      return { score, violations: [], validatedBody: null };
    }
    // Actual size check after reading body (v1.6)
    if (bodyLimit.enabled && rawText.length > bodyLimit.maxBytes) {
      violations.push("body_too_large_actual");
      score += 10;
      await this.engine.addScore(ip, 10, "body_too_large_actual");
    }
    let parsed: unknown = null;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      violations.push("non_json_body");
      score += this.weights.nonJsonBody;
      await this.engine.addScore(ip, this.weights.nonJsonBody, "non_json_body");
      // Still run post-body custom analyzers even without valid body
      const ctx = this.makeContext(ip, requestId, rawText);
      const pluginResult = await this.engine.runAnalyzers(req, ctx, "post-body");
      return {
        score: score + pluginResult.score,
        violations: [...violations, ...pluginResult.violations],
        validatedBody: null,
      };
    }
    if (parsed !== null && typeof parsed === "object") {
      // L5: Obfuscation scan
      const obf = this.engine.detectObfuscation(
        parsed as Record<string, unknown>
      );
      if (obf.detected) {
        const tag = `obfuscation(${obf.fields.join(",")})`;
        violations.push(tag);
        score += this.weights.obfuscationDetected;
        await this.engine.addScore(ip, this.weights.obfuscationDetected, tag);
        this.engine.incrementStats("blockedByObfuscation");
      }
      // L6: Zod validation (skip if already over threshold)
      const threshold = this.getEffectiveThreshold(req.method);
      if (score < threshold) {
        const result = validatePayload(parsed, this.strictSchema);
        if (result.ok) {
          validatedBody = result.data as unknown as Record<string, unknown>;
        } else {
          violations.push(`schema:${result.error}`);
          const pts = result.isSchemaViolation
            ? this.weights.schemaViolation
            : this.weights.nonJsonBody;
          score += pts;
          await this.engine.addScore(ip, pts, "schema_violation");
          if (result.isSchemaViolation) {
            this.engine.incrementStats("blockedBySchema");
          }
        }
      }
    }
    // Custom post-body analyzers from plugins
    const ctx = this.makeContext(ip, requestId, rawText);
    const pluginResult = await this.engine.runAnalyzers(req, ctx, "post-body");
    score += pluginResult.score;
    violations.push(...pluginResult.violations);
    return { score, violations, validatedBody };
  }
  // ── Honeypot routing ──────────────────────────────────────────
  private sendToHoneypot(
    req: NextRequest,
    ip: string,
    score: number,
    violations: string[],
    requestId: string
  ): NextResponse {
    const response = serveHoneypot(
      req,
      this.decoyFn,
      ip,
      score,
      violations,
      this.cfg.debugMode ?? false,
      this.cfg.violationMessages
    );
    if (this.cfg.hooks?.onHoneypot) {
      this.cfg.hooks.onHoneypot({
        ip,
        requestId,
        score,
        violations,
        decoyResponse: {}, // response body not easily accessible at this point
      });
    }
    return response;
  }
  // ── Forward to real handler ───────────────────────────────────
  private async forwardToHandler(
    req: NextRequest,
    ip: string,
    score: number,
    requestId: string,
    validatedBody: Record<string, unknown> | null
  ): Promise<NextResponse> {
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
    if (this.cfg.hooks?.onPass) {
      this.cfg.hooks.onPass({
        ip,
        requestId,
        score,
      });
    }
    return await this.handler(cleanReq);
  }
  // ── Context builder ───────────────────────────────────────────
  private makeContext(ip: string, requestId: string, bodyRaw?: string): AnalysisContext {
    return {
      ip,
      requestId,
      engine: this.engine,
      config: this.cfg,
      weights: this.weights,
      ...(bodyRaw !== undefined ? { bodyRaw } : {}),
    };
  }
}
