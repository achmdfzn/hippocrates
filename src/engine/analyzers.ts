/**
 * @file Built-in analyzer plugins (L1–L6) for the hippocrates engine.
 *
 * Each analyzer implements the AnalyzerPlugin interface and can be
 * registered with the ThreatScoreEngine. Users can provide custom
 * analyzers that run alongside these built-in ones.
 *
 * All built-in analyzers are **placeholders** — actual detection runs
 * directly in the pipeline (HippocratesPipeline) because:
 *   - L1/L2 require Redis state management (timestamp lists, velocity)
 *   - L3/L4/L5/L6 would double-count if both the plugin AND the
 *     pipeline performed the same checks
 *
 * The pipeline calls engine.analyzeRequestTiming(), analyzeVelocity(),
 * analyzeUserAgent(), analyzeHeaders(), and detectObfuscation() directly,
 * then runs validatePayload() for schema validation.
 *
 * Custom plugins registered via config.plugins run alongside these
 * placeholders in their respective phases.
 *
 * Priority order (built-in):
 *   Pre-body:  L1 timing(10) → L2 velocity(20) → L3 UA(30) → L6 headers(40)
 *   Post-body: L4 obfuscation(10) → L5 schema(20)
 */

import type {
  AnalyzerPlugin,
  AnalysisResult,
} from "./types";

// ── L1: Timing Analysis ────────────────────────────────────────────

/** Placeholder — runs via engine.analyzeRequestTiming() in the pipeline. */
export const timingAnalyzer: AnalyzerPlugin = {
  name: "L1_timing",
  phase: "pre-body",
  priority: 10,
  analyze(): AnalysisResult {
    return { score: 0, tags: [] };
  },
};

// ── L2: Velocity Analysis ──────────────────────────────────────────

/** Placeholder — runs via engine.analyzeVelocity() in the pipeline. */
export const velocityAnalyzer: AnalyzerPlugin = {
  name: "L2_velocity",
  phase: "pre-body",
  priority: 20,
  analyze(): AnalysisResult {
    return { score: 0, tags: [] };
  },
};

// ── L3: User-Agent Fingerprinting ──────────────────────────────────

/** Placeholder — runs via engine.analyzeUserAgent() in the pipeline. */
export const userAgentAnalyzer: AnalyzerPlugin = {
  name: "L3_user_agent",
  phase: "pre-body",
  priority: 30,
  analyze(): AnalysisResult {
    return { score: 0, tags: [] };
  },
};

// ── L4: Obfuscation Detection ──────────────────────────────────────

/** Placeholder — runs via engine.detectObfuscation() in the pipeline. */
export const obfuscationAnalyzer: AnalyzerPlugin = {
  name: "L4_obfuscation",
  phase: "post-body",
  priority: 10,
  analyze(): AnalysisResult {
    return { score: 0, tags: [] };
  },
};

// ── L5: Schema Validation (Zod .strict()) ──────────────────────────

/** Placeholder — runs via validatePayload() in the pipeline. */
export const schemaAnalyzer: AnalyzerPlugin = {
  name: "L5_schema",
  phase: "post-body",
  priority: 20,
  analyze(): AnalysisResult {
    return { score: 0, tags: [] };
  },
};

// ── L6: Header Anomaly Detection ───────────────────────────────────

/** Placeholder — runs via engine.analyzeHeaders() in the pipeline. */
export const headerAnalyzer: AnalyzerPlugin = {
  name: "L6_headers",
  phase: "pre-body",
  priority: 40,
  analyze(): AnalysisResult {
    return { score: 0, tags: [] };
  },
};

// ── Registry of all built-in analyzers ─────────────────────────────

export const BUILT_IN_ANALYZERS: ReadonlyArray<AnalyzerPlugin> = [
  timingAnalyzer,
  velocityAnalyzer,
  userAgentAnalyzer,
  headerAnalyzer,
  obfuscationAnalyzer,
  schemaAnalyzer,
];
