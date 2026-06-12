/**
 * Tests for in-memory stats tracker (v1.6)
 */
import { describe, it, expect, vi } from "vitest";

vi.mock("next/server", () => ({
  NextRequest: class MockNextRequest {},
  NextResponse: {
    json: vi.fn((body, init) => ({
      status: init?.status ?? 200,
      headers: new Map<string, string>(),
      json: async () => body,
    })),
  },
}));

import { ThreatScoreEngine } from "../index";
import { createMockRedis } from "./helpers";

function createEngine(): ThreatScoreEngine {
  const { client } = createMockRedis();
  return new ThreatScoreEngine(
    client,
    { threatScoreThreshold: 65, velocityWindowMs: 10000, velocityMaxRequests: 15, threatTtlSeconds: 3600, debugMode: false },
    { suspiciousUserAgent: 15, schemaViolation: 100, obfuscationDetected: 100, velocityViolation: 40, impossibleTiming: 25, nonJsonBody: 10, suspiciousHeaders: 15 }
  );
}

describe("Stats tracker (v1.6)", () => {
  it("starts with all zeros", () => {
    const engine = createEngine();
    const stats = engine.getStats();
    expect(stats.totalRequests).toBe(0);
    expect(stats.blockedByPreflight).toBe(0);
    expect(stats.blockedByTiming).toBe(0);
    expect(stats.blockedByVelocity).toBe(0);
    expect(stats.blockedByObfuscation).toBe(0);
    expect(stats.blockedBySchema).toBe(0);
    expect(stats.passedToHandler).toBe(0);
    expect(stats.honeypotServed).toBe(0);
    expect(stats.redisErrors).toBe(0);
  });

  it("incrementStats increases counters", () => {
    const engine = createEngine();
    engine.incrementStats("totalRequests");
    engine.incrementStats("blockedByPreflight");
    engine.incrementStats("honeypotServed");
    const stats = engine.getStats();
    expect(stats.totalRequests).toBe(1);
    expect(stats.blockedByPreflight).toBe(1);
    expect(stats.honeypotServed).toBe(1);
  });

  it("getStats returns a copy (not reference)", () => {
    const engine = createEngine();
    const stats = engine.getStats();
    stats.totalRequests = 999;
    expect(engine.getStats().totalRequests).toBe(0);
  });

  it("resetStats zeros everything", () => {
    const engine = createEngine();
    engine.incrementStats("totalRequests");
    engine.incrementStats("blockedByTiming");
    expect(engine.getStats().totalRequests).toBe(1);
    engine.resetStats();
    const stats = engine.getStats();
    expect(stats.totalRequests).toBe(0);
    expect(stats.blockedByTiming).toBe(0);
  });

  it("incrementStats works for all counter types", () => {
    const engine = createEngine();
    const counters = [
      "totalRequests", "blockedByPreflight", "blockedByTiming",
      "blockedByVelocity", "blockedByObfuscation", "blockedBySchema",
      "passedToHandler", "honeypotServed", "redisErrors",
    ] as const;
    for (const c of counters) {
      engine.incrementStats(c);
    }
    const stats = engine.getStats();
    for (const c of counters) {
      expect(stats[c]).toBe(1);
    }
  });
});
