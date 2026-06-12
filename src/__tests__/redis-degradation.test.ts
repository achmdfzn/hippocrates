/**
 * Tests for Redis graceful degradation (v1.6)
 *
 * Verifies that Redis failures return safe defaults instead of crashing.
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
import type { RedisClient } from "../index";

// ── Helpers ──────────────────────────────────────────────────────────

function createBrokenRedis(): RedisClient {
  return {
    get: vi.fn(async () => { throw new Error("Redis down"); }),
    set: vi.fn(async () => { throw new Error("Redis down"); }),
    lpush: vi.fn(async () => { throw new Error("Redis down"); }),
    ltrim: vi.fn(async () => { throw new Error("Redis down"); }),
    lrange: vi.fn(async () => { throw new Error("Redis down"); }),
    expire: vi.fn(async () => { throw new Error("Redis down"); }),
  };
}

function createEngine(redis?: RedisClient): ThreatScoreEngine {
  const r = redis ?? createBrokenRedis();
  return new ThreatScoreEngine(
    r,
    { threatScoreThreshold: 65, velocityWindowMs: 10000, velocityMaxRequests: 15, threatTtlSeconds: 3600, debugMode: false },
    { suspiciousUserAgent: 15, schemaViolation: 100, obfuscationDetected: 100, velocityViolation: 40, impossibleTiming: 25, nonJsonBody: 10, suspiciousHeaders: 15 }
  );
}

// ── Tests ────────────────────────────────────────────────────────────

describe("Redis graceful degradation (v1.6)", () => {
  it("returns 0 for getScore when Redis fails", async () => {
    const engine = createEngine();
    const score = await engine.getScore("1.2.3.4");
    expect(score).toBe(0);
  });

  it("returns points for addScore when Redis fails", async () => {
    const engine = createEngine();
    const score = await engine.addScore("1.2.3.4", 30, "test");
    expect(score).toBe(30); // Returns attempted points
  });

  it("returns non-anomalous timing when Redis fails", async () => {
    const engine = createEngine();
    const result = await engine.analyzeRequestTiming("1.2.3.4");
    expect(result.isAnomalous).toBe(false);
    expect(result.intervalMs).toBe(Infinity);
  });

  it("returns non-excessive velocity when Redis fails", async () => {
    const engine = createEngine();
    const result = await engine.analyzeVelocity("1.2.3.4");
    expect(result.isExcessive).toBe(false);
    expect(result.requestCount).toBe(0);
  });

  it("tracks redis errors in stats", async () => {
    const engine = createEngine();
    await engine.getScore("1.2.3.4");
    await engine.addScore("1.2.3.4", 10, "test");
    const stats = engine.getStats();
    expect(stats.redisErrors).toBeGreaterThanOrEqual(2);
  });

  it("recovers after Redis becomes healthy again", async () => {
    const broken: RedisClient = createBrokenRedis();
    const engine = createEngine(broken);

    // First call fails
    await engine.getScore("1.2.3.4");

    // Fix Redis mid-flight
    broken.get = vi.fn(async () => "50");

    const score = await engine.getScore("1.2.3.4");
    expect(score).toBe(50);
  });
});
