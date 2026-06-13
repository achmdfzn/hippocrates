/**
 * Integration tests verifying stats tracking across all pipeline defense layers.
 *
 * Spies on ThreatScoreEngine.prototype.incrementStats to confirm each
 * security gate correctly increments the right counter.
 * Also tests the consumer-facing StatsTracker config wiring.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

vi.mock("next/server", () => ({
  NextRequest: class MockNextRequest {
    public url: string;
    public method: string;
    readonly _headers: Map<string, string> = new Map();
    private _body: string | null;

    constructor(url: string, init?: { method?: string; headers?: HeadersInit; body?: string | null }) {
      this.url = url;
      this.method = init?.method ?? "GET";
      this._body = init?.body ?? null;
      if (init?.headers) {
        if (typeof (init.headers as Headers).forEach === "function") {
          (init.headers as Headers).forEach((v: string, k: string) => {
            this._headers.set(k.toLowerCase(), v);
          });
        } else if (typeof init.headers === "object") {
          for (const [k, v] of Object.entries(init.headers)) {
            if (typeof v === "string") this._headers.set(k.toLowerCase(), v);
          }
        }
      }
    }

    get headers() { return this._headers; }
    async json() { return this._body ? JSON.parse(this._body) : {}; }
    async text() { return this._body ?? ""; }
    get nextUrl() { return { pathname: new URL(this.url).pathname }; }
  },
  NextResponse: {
    json: vi.fn((body: unknown, init?: { status?: number }) => ({
      status: init?.status ?? 200,
      json: async () => body,
    })),
  },
}));

import { withHippocrates, ThreatScoreEngine } from "../index";
import { createMockRedis, TestSchema } from "./helpers";
import type { NextRequest } from "next/server";
import type { SecurityStats, StatsTracker } from "../engine/types";

// ── Spy on incrementStats (call-through, preserves original impl) ────

let incrementStatsSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  incrementStatsSpy = vi.spyOn(ThreatScoreEngine.prototype, "incrementStats");
});

afterEach(() => {
  incrementStatsSpy.mockRestore();
});

// ── Helpers ──────────────────────────────────────────────────────────

function mockRequest(overrides?: {
  method?: string;
  body?: string | null;
  headers?: Record<string, string>;
  ip?: string;
}) {
  const headerMap: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": "Mozilla/5.0 (test-agent)",
    ...(overrides?.headers ?? {}),
  };
  if (overrides?.ip) headerMap["x-forwarded-for"] = overrides.ip ?? "1.2.3.4";
  const headers = new Headers(headerMap);
  let bodyConsumed = false;

  return {
    method: overrides?.method ?? "POST",
    url: "http://localhost:3000/api/data",
    headers,
    text: async () => {
      if (bodyConsumed) throw new Error("Body already consumed");
      bodyConsumed = true;
      return overrides?.body ?? '{"userId":"550e8400-e29b-41d4-a716-446655440000","action":"read"}';
    },
    json: async () => {
      if (bodyConsumed) throw new Error("Body already consumed");
      bodyConsumed = true;
      const raw = overrides?.body ?? '{"userId":"550e8400-e29b-41d4-a716-446655440000","action":"read"}';
      return raw ? JSON.parse(raw) : {};
    },
  } as unknown as NextRequest;
}

function createHandler(config?: Record<string, unknown>) {
  const { client } = createMockRedis();
  const innerHandler = vi.fn(async (_req: NextRequest) => ({
    status: 200,
    body: { success: true },
  }));
  const wrapped = withHippocrates(innerHandler, TestSchema, client, {
    threatScoreThreshold: 65,
    ...config,
  });
  return { wrapped, innerHandler, redis: client };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("Stats integration — totalRequests", () => {
  it("increments totalRequests for every request", async () => {
    const { wrapped } = createHandler();
    await wrapped(mockRequest());
    expect(incrementStatsSpy).toHaveBeenCalledWith("totalRequests");
  });

  it("increments totalRequests exactly once per request", async () => {
    const { wrapped } = createHandler();
    await wrapped(mockRequest());
    const calls = incrementStatsSpy.mock.calls.filter(([c]) => c === "totalRequests");
    expect(calls).toHaveLength(1);
  });
});

describe("Stats integration — blockedByPreflight", () => {
  it("increments blockedByPreflight and honeypotServed when L0 catches high score", async () => {
    const { client, store } = createMockRedis();
    store.set("hc:s:9.9.9.9", "80");

    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    await wrapped(mockRequest({ ip: "9.9.9.9" }));
    expect(incrementStatsSpy).toHaveBeenCalledWith("blockedByPreflight");
    expect(incrementStatsSpy).toHaveBeenCalledWith("honeypotServed");
    expect(incrementStatsSpy).not.toHaveBeenCalledWith("passedToHandler");
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

describe("Stats integration — blockedByTiming", () => {
  it("increments blockedByTiming when timing anomaly detected", async () => {
    const { client, store } = createMockRedis();
    store.set("hc:s:4.5.6.7", "0");
    store.set("hc:l:4.5.6.7", String(Date.now() - 10)); // 10ms ago (< 50ms)

    const innerHandler = vi.fn(async (_r) => ({ status: 200, body: { success: true } }));
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      scoring: { impossibleTiming: 25 },
    });

    await wrapped(mockRequest({ ip: "4.5.6.7" }));
    expect(incrementStatsSpy).toHaveBeenCalledWith("blockedByTiming");
  });
});

describe("Stats integration — blockedByVelocity", () => {
  it("increments blockedByVelocity when velocity exceeded", async () => {
    const { client, store } = createMockRedis();
    const recentTss = Array.from({ length: 20 }, () =>
      String(Date.now() - Math.floor(Math.random() * 1000))
    );
    store.set("hc:t:9.9.9.9", JSON.stringify(recentTss));

    const innerHandler = vi.fn(async (_r) => ({ status: 200, body: { success: true } }));
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      velocityMaxRequests: 5,
      velocityWindowMs: 60000,
      scoring: { velocityViolation: 40 },
    });

    await wrapped(mockRequest({ ip: "9.9.9.9" }));
    expect(incrementStatsSpy).toHaveBeenCalledWith("blockedByVelocity");
  });
});

describe("Stats integration — blockedByObfuscation", () => {
  it("increments blockedByObfuscation when base64 detected", async () => {
    const { wrapped, innerHandler } = createHandler();
    await wrapped(mockRequest({
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        data: "SGVsbG8gV29ybGQgVGhpcyBpcyBhIEJhc2U2NCBlbmNvZGVkIHN0cmluZw==",
      }),
    }));

    expect(incrementStatsSpy).toHaveBeenCalledWith("blockedByObfuscation");
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

describe("Stats integration — blockedBySchema", () => {
  it("increments blockedBySchema when extra field detected", async () => {
    const { wrapped, innerHandler } = createHandler();
    await wrapped(mockRequest({
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        admin: true,
      }),
    }));

    expect(incrementStatsSpy).toHaveBeenCalledWith("blockedBySchema");
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

describe("Stats integration — honeypotServed", () => {
  it("increments honeypotServed when request is routed to honeypot (L0 path)", async () => {
    const { client, store } = createMockRedis();
    store.set("hc:s:2.2.2.2", "80");

    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    await wrapped(mockRequest({ ip: "2.2.2.2" }));
    expect(incrementStatsSpy).toHaveBeenCalledWith("honeypotServed");
    expect(incrementStatsSpy).not.toHaveBeenCalledWith("passedToHandler");
  });

  it("increments honeypotServed when L5 schema violation triggers honeypot", async () => {
    const { wrapped, innerHandler } = createHandler();
    await wrapped(mockRequest({
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        extraField: "triggers-schema-violation",
      }),
    }));

    expect(incrementStatsSpy).toHaveBeenCalledWith("honeypotServed");
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

describe("Stats integration — passedToHandler", () => {
  it("increments passedToHandler for clean requests", async () => {
    const { wrapped } = createHandler();
    await wrapped(mockRequest());

    expect(incrementStatsSpy).toHaveBeenCalledWith("totalRequests");
    expect(incrementStatsSpy).toHaveBeenCalledWith("passedToHandler");
    expect(incrementStatsSpy).not.toHaveBeenCalledWith("honeypotServed");
  });

  it("increments passedToHandler even with minor penalties below threshold", async () => {
    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_r) => ({ status: 200, body: { success: true } }));
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      bodyLimit: { maxBytes: 10, enabled: true },
    });

    await wrapped(mockRequest({
      headers: { "content-length": "100" },
      body: JSON.stringify({ userId: "550e8400-e29b-41d4-a716-446655440000", action: "read" }),
    }));

    expect(incrementStatsSpy).toHaveBeenCalledWith("passedToHandler");
    expect(innerHandler).toHaveBeenCalled();
  });
});

describe("Stats integration — StatsTracker config wiring", () => {
  it("forwards increment calls to consumer StatsTracker", async () => {
    const trackerCalls: string[] = [];
    const statsTracker: StatsTracker = {
      increment: (counter: keyof SecurityStats) => { trackerCalls.push(counter); },
      getStats: () => ({ totalRequests: 0, blockedByPreflight: 0, blockedByTiming: 0, blockedByVelocity: 0, blockedByObfuscation: 0, blockedBySchema: 0, passedToHandler: 0, honeypotServed: 0, redisErrors: 0 }),
      reset: () => {},
    };

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_r) => ({ status: 200, body: { success: true } }));
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      statsTracker,
    });

    await wrapped(mockRequest({ ip: "10.0.0.1" }));

    // Both engine stats AND StatsTracker should be called
    expect(trackerCalls).toContain("totalRequests");
    expect(trackerCalls).toContain("passedToHandler");
    expect(incrementStatsSpy).toHaveBeenCalledWith("totalRequests");
  });

  it("StatsTracker receives blockedByPreflight for L0 blocks", async () => {
    const trackerCalls: string[] = [];
    const statsTracker: StatsTracker = {
      increment: (counter: keyof SecurityStats) => { trackerCalls.push(counter); },
      getStats: () => ({ totalRequests: 0, blockedByPreflight: 0, blockedByTiming: 0, blockedByVelocity: 0, blockedByObfuscation: 0, blockedBySchema: 0, passedToHandler: 0, honeypotServed: 0, redisErrors: 0 }),
      reset: () => {},
    };

    const { client, store } = createMockRedis();
    store.set("hc:s:5.5.5.5", "90");

    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      statsTracker,
    });

    await wrapped(mockRequest({ ip: "5.5.5.5" }));
    expect(trackerCalls).toContain("blockedByPreflight");
    expect(trackerCalls).toContain("honeypotServed");
    expect(trackerCalls).not.toContain("passedToHandler");
  });
});
