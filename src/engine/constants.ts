/**
 * @file Constants, defaults, and pattern definitions for hippocrates.
 *
 * Extracted from the original §2 in src/index.ts for cleaner modularity.
 * All values are Readonly — do not mutate at runtime.
 */

import type {
  ThreatScoringWeights,
  HeaderAnomalyPattern,
  ObfuscationPattern,
  BodyLimitConfig,
  SecurityPreset,
  HippocratesConfig,
} from "./types";

// ── Default configuration ──────────────────────────────────────────

export const DEFAULTS = {
  threatScoreThreshold: 65,
  velocityWindowMs: 10_000,
  velocityMaxRequests: 15,
  threatTtlSeconds: 3_600,
  debugMode: false,
} as const;

// ── Default scoring weights ────────────────────────────────────────

export const DEFAULT_WEIGHTS: Readonly<ThreatScoringWeights> = {
  suspiciousUserAgent: 15,
  schemaViolation: 100,
  obfuscationDetected: 100,
  velocityViolation: 40,
  impossibleTiming: 25,
  nonJsonBody: 10,
  suspiciousHeaders: 15,
};

// ── Redis key namespace ────────────────────────────────────────────

export const REDIS_NS = "hc";

// ── Human timing threshold ─────────────────────────────────────────

/**
 * Below this inter-request interval, behavior is classified as autonomous.
 * A human physically cannot consistently submit structured POST requests
 * under 50ms apart — this threshold is a strong autonomous signal.
 */
export const MIN_HUMAN_INTERVAL_MS = 50;

// ── Body limit defaults ─────────────────────────────────────────────

/** @since v1.6 */
export const DEFAULT_BODY_LIMIT: BodyLimitConfig = {
  maxBytes: 1_048_576, // 1MB
  enabled: true,
};

// ── User-Agent patterns (L3) ───────────────────────────────────────

/**
 * User-Agent patterns for autonomous or scripted HTTP clients.
 *
 * UA-based detection is a soft signal — combine it with behavioral
 * analysis (L1/L2) against evasive agents that spoof their UA.
 */
export const AGENT_UA_PATTERNS: ReadonlyArray<RegExp> = [
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
  /anthropic-sdk/i,
  /claude-[\d.]+/i,
  /openai-node/i,
  /openai-python/i,
  /google-gemini/i,
  /google-ai-generativelanguage/i,
  /langchain/i,
  /llamaindex/i,
  /autogen/i,
  /crewai/i,
  /smolagents/i,
  /llm-agent/i,
  /agentops/i,
  /cohere[\s/-]/i,
  /mistral[\s/-]/i,
  /together[\s/-]/i,
  /groq[\s/-]/i,
  /deepseek[\s/-]/i,
  /dspy[\s/-]/i,
  /semantic-kernel/i,
  /haystack/i,
  /copilot-github/i,
  /huggingface/i,
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
  // ── 2026 AI Agents ──────────────────────────────────────────
  /claudebot\/[\d.]+/i,
  /claude-user\/[\d.]+/i,
  /claude-searchbot\/[\d.]+/i,
  /claude-code\//i,
  /cursor\/[\d.]+/i,
  /cursoragent/i,
  /perplexitybot/i,
  /githubcopilot/i,
  /opencode/i,
  /windsurf/i,
];

// ── Obfuscation patterns (L4) ──────────────────────────────────────

/**
 * Payload string patterns that indicate encoding-based obfuscation.
 *
 * Autonomous agents encode injection payloads (prompt injections, SQLi,
 * path traversal) to bypass keyword filters. Scans all string values
 * recursively.
 */
export const OBFUSCATION_PATTERNS: ReadonlyArray<ObfuscationPattern> = [
  {
    name: "base64",
    pattern:
      /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/,
  },
  {
    name: "hex",
    pattern: /^(?:0x)?[0-9a-fA-F]{16,}$/,
  },
  {
    name: "url_encoding",
    pattern: /(?:%[0-9a-fA-F]{2}){5,}/,
  },
  {
    name: "unicode_escape",
    pattern: /\\u[0-9a-fA-F]{4}/,
  },
  {
    name: "html_entity",
    pattern: /&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]{2,8});/,
  },
];

// ── Header anomaly patterns (L4) ───────────────────────────────────

export const HEADER_ANOMALY_PATTERNS: ReadonlyArray<HeaderAnomalyPattern> = [
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

// ── Config presets ─────────────────────────────────────────────────

/** @since v1.6 */
export const PRESETS: Record<SecurityPreset, Partial<HippocratesConfig>> = {
  strict: {
    threatScoreThreshold: 40,
    velocityMaxRequests: 10,
    velocityWindowMs: 10_000,
    scoring: {
      impossibleTiming: 35,
      velocityViolation: 50,
      suspiciousUserAgent: 25,
    },
  },
  moderate: {
    threatScoreThreshold: 65,
    velocityMaxRequests: 15,
    velocityWindowMs: 10_000,
  },
  relaxed: {
    threatScoreThreshold: 80,
    velocityMaxRequests: 30,
    velocityWindowMs: 30_000,
    scoring: {
      impossibleTiming: 10,
      suspiciousUserAgent: 5,
      suspiciousHeaders: 5,
    },
  },
};
