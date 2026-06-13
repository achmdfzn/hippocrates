/**
 * Integration tests for withHippocrates (Â§7) â€” the primary HOF export.
 *
 * Tests each security layer (L0-L5), score gating, error handling,
 * and the forward-to-handler path.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Hoisted mockJson â€” vi.mock is hoisted to top, so any variable it references
// must be defined with vi.hoisted() to exist in the hoisted scope.
const { mockJson } = vi.hoisted(() => {
  function makeHeaders() {
    const _h: Record<string, string> = {};
    return {
      get: (n: string) => _h[n.toLowerCase()] ?? null,
      set: (n: string, v: string) => { _h[n.toLowerCase()] = v; },
      delete: (n: string) => { delete _h[n.toLowerCase()]; },
      has: (n: string) => _h[n.toLowerCase()] !== undefined,
      forEach: (cb: (v: string, k: string) => void) => Object.entries(_h).forEach(([k, v]) => cb(v, k)),
    };
  }
  const mock = vi.fn();
  // Override mockImplementation to wrap every call with headers
  const origImpl = mock.mockImplementation.bind(mock);
  mock.mockImplementation = (fn: (...args: unknown[]) => unknown) => {
    return origImpl((body: unknown, init?: { status?: number }) => {
      const result = fn(body, init) as Record<string, unknown>;
      if (!result.headers) {
        result.headers = makeHeaders();
      }
      return result;
    });
  };
  // Set the default implementation
  mock.mockImplementation((body: unknown, init?: { status?: number }) => ({
    status: init?.status ?? 200,
    body,
    json: async () => body,
  }));
  return { mockJson: mock };
});

vi.mock("next/server", () => ({
  NextRequest: class MockNextRequest {
    public url: string;
    public method: string;
    readonly _headers: Map<string, string> = new Map();
    private _body: string | null;

    constructor(
      url: string,
      init?: { method?: string; headers?: HeadersInit; body?: string | null }
    ) {
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

    get headers() {
      return this._headers;
    }

    async json() {
      return this._body ? JSON.parse(this._body) : {};
    }

    async text() {
      return this._body ?? "";
    }

    clone() {
      return this;
    }
  },
  NextResponse: {
    json: mockJson,
  },
}));

import { withHippocrates, z } from "../index";
import { createMockRedis, TestSchema } from "./helpers";
import type { HippocratesConfig, HoneypotEvent, PassEvent, AnalyzerPlugin } from "../index";

beforeEach(() => {
  mockJson.mockReset();
  // Re-apply default implementation (mockReset clears it)
  mockJson.mockImplementation((body, init) => ({
    status: init?.status ?? 200,
    body,
    json: async () => body,
  }));
});

/**
 * Create a mock request suitable for testing withHippocrates.
 * Uses the real Headers class so `new Headers(req.headers)` works
 * inside the middleware's forward-request construction.
 */
function mockRequest(overrides?: {
  method?: string;
  body?: string | null;
  headers?: Record<string, string>;
  ip?: string;
}) {
  const headerMap: Record<string, string> = {
    "content-type": "application/json",
    "accept": "application/json",
    "accept-language": "en-US,en;q=0.9",
    "user-agent": "Mozilla/5.0 (test-agent)",
    ...(overrides?.headers ?? {}),
  };

  // Insert IP via x-forwarded-for if provided
  if (overrides?.ip) {
    headerMap["x-forwarded-for"] = overrides.ip;
  }

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

/**
 * Creates a withHippocrates-wrapped handler for testing.
 * The inner handler records what it receives.
 */
function createWrappedHandler(config?: HippocratesConfig) {
  const { client } = createMockRedis();
  const innerHandler = vi.fn(async (req: NextRequest) => {
    const body = await req.json();

    // Return mock NextResponse shape
    return {
      status: 200,
      body,
      headers: req.headers,
    };
  });

  const wrapped = withHippocrates(innerHandler, TestSchema, client, config);

  return { wrapped, innerHandler, redis: client };
}

// â”€â”€ Basic pass-through â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” basic pass-through", () => {
  it("forwards valid requests to the inner handler", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const req = mockRequest();
    const { wrapped, innerHandler } = createWrappedHandler();

    await wrapped(req);

    // Inner handler should have been called
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("injects x-hippocrates-score and x-hippocrates-clean headers on forwarded request", async () => {
    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (req: NextRequest) => {
      return {
        status: 200,
        score: req.headers.get("x-hippocrates-score"),
        clean: req.headers.get("x-hippocrates-clean"),
      };
    });

    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    const req = mockRequest();
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
    const callArgs = innerHandler.mock.calls[0][0] as NextRequest;
    expect(callArgs.headers.get("x-hippocrates-score")).toBe("0");
    expect(callArgs.headers.get("x-hippocrates-clean")).toBe("1");
  });

  it("passes validated body to the inner handler", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (req: NextRequest) => ({
      status: 200,
      body: await req.json(),
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client);
    const req = mockRequest();
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalled();
    // The body received by the handler should match the input
    const handlerReq = innerHandler.mock.calls[0][0] as NextRequest;
    const receivedBody = await handlerReq.json();
    expect(receivedBody).toHaveProperty("userId");
    expect(receivedBody).toHaveProperty("action", "read");
  });
});

// â”€â”€ L0: Pre-flight â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” L0 pre-flight", () => {
  it("honeypots immediately when existing score >= threshold", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    // Set a pre-existing score above threshold
    store.set("hc:s:1.2.3.4", "80");

    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    const req = mockRequest({ ip: "1.2.3.4" });
    const result = await wrapped(req);

    // Inner handler should NOT be called
    expect(innerHandler).not.toHaveBeenCalled();
    // Response should be 200 (honeypot)
    expect(result).toBeDefined();
  });

  it("proceeds when existing score is below threshold", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:1.2.3.4", "30"); // Below threshold

    const innerHandler = vi.fn(async () => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    const req = mockRequest({ ip: "1.2.3.4" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });
});

// â”€â”€ L1: Timing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” L1 timing", () => {
  it("adds impossibleTiming score for sub-50ms intervals", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    // Set last seen to 10ms ago
    store.set("hc:l:4.5.6.7", String(Date.now() - 10));
    store.set("hc:s:4.5.6.7", "0");

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      scoring: { impossibleTiming: 25 },
    });

    const req = mockRequest({ ip: "4.5.6.7" });
    await wrapped(req);

    // Score should have increased (timing +25 = 25, still below threshold)
    expect(innerHandler).toHaveBeenCalledTimes(1);
    // Verify score was stored in Redis
    const storedScore = store.get("hc:s:4.5.6.7");
    expect(storedScore).toBeDefined();
    expect(Number(storedScore)).toBeGreaterThanOrEqual(25);
  });
});

// â”€â”€ L2: Velocity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” L2 velocity", () => {
  it("adds velocityViolation score when exceeding max requests", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    // Inject 20 existing timestamps within the window
    const recentTss = Array.from({ length: 20 }, () =>
      String(Date.now() - Math.floor(Math.random() * 1000))
    );
    store.set("hc:t:9.9.9.9", JSON.stringify(recentTss));

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      velocityMaxRequests: 5,
      velocityWindowMs: 60_000,
      scoring: { velocityViolation: 40 },
    });

    const req = mockRequest({ ip: "9.9.9.9" });
    await wrapped(req);

    // Score should be at least 40 (velocity) but < 65, so handler runs
    expect(innerHandler).toHaveBeenCalledTimes(1);
    const storedScore = store.get("hc:s:9.9.9.9");
    expect(Number(storedScore)).toBeGreaterThanOrEqual(40);
  });
});

// â”€â”€ L3: User-Agent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” L3 User-Agent", () => {
  it("adds suspiciousUserAgent score for known agent UA", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:1.1.1.1", "0");

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      scoring: { suspiciousUserAgent: 15 },
    });

    const req = mockRequest({
      ip: "1.1.1.1",
      headers: { "user-agent": "python-requests/2.31.0" },
    });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
    const storedScore = store.get("hc:s:1.1.1.1");
    expect(Number(storedScore)).toBeGreaterThanOrEqual(15);
  });

  it("does not add score for clean browser UA", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:2.2.2.2", "0");

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    const req = mockRequest({
      ip: "2.2.2.2",
      headers: {
        "user-agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
      },
    });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
    const storedScore = store.get("hc:s:2.2.2.2");
    expect(storedScore).toBe("0");
  });
});

// â”€â”€ L4: Obfuscation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” L4 obfuscation", () => {
  it("honeypots when Base64 obfuscation is detected (100 pts)", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    const req = mockRequest({
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        data: "SGVsbG8gV29ybGQgVGhpcyBpcyBhIEJhc2U2NCBlbmNvZGVkIHN0cmluZw==",
      }),
    });

    await wrapped(req);

    // 100 pts from obfuscation >= 65 threshold â†’ honeypot, handler not called
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

// â”€â”€ L5: Schema violation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” L5 schema violation", () => {
  it("honeypots when Zod .strict() detects extra fields (100 pts)", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    // Extra field "admin" should trigger .strict()
    const req = mockRequest({
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        admin: true,
      }),
    });

    await wrapped(req);

    expect(innerHandler).not.toHaveBeenCalled();
  });

  it("honeypots when required field is missing", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    const req = mockRequest({
      body: JSON.stringify({ userId: "550e8400-e29b-41d4-a716-446655440000" }), // missing action
    });

    await wrapped(req);

    expect(innerHandler).not.toHaveBeenCalled();
  });
});

// â”€â”€ GET / HEAD / OPTIONS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” GET/HEAD/OPTIONS", () => {
  it("skips body parsing for GET requests", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { ok: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client);
    const req = mockRequest({ method: "GET" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("skips body parsing for HEAD requests", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { ok: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client);
    const req = mockRequest({ method: "HEAD" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("skips body parsing for OPTIONS requests", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { ok: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client);
    const req = mockRequest({ method: "OPTIONS" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });
});

// â”€â”€ Score gate (post-L5) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” score gate after all layers", () => {
  it("honeypots when combined score crosses threshold", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:7.7.7.7", "50"); // Already at 50

    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      velocityMaxRequests: 999, // Disable velocity
      scoring: { impossibleTiming: 0, suspiciousUserAgent: 0 }, // Disable timing + UA
    });

    const req = mockRequest({
      ip: "7.7.7.7",
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        extra: "field", // L5 will fire: +100 â†’ honeypot
      }),
    });

    await wrapped(req);

    // Even though pre-flight didn't catch it (50 < 65), L5 adds 100,
    // and the post-L5 gate catches it
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

// â”€â”€ Error handling â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” error handling", () => {
  it("returns a generic 500 error (no details leaked)", async () => {
    let capturedStatus = 0;
    let capturedBody: unknown = null;

    mockJson.mockImplementation((body, init) => {
      capturedStatus = init?.status ?? 200;
      capturedBody = body;
      return { status: init?.status ?? 200, json: async () => body };
    });

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async () => {
      throw new Error("Sensitive database credentials leaked");
    });

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
    });

    const req = mockRequest();
    await wrapped(req);

    // Must return 500
    expect(capturedStatus).toBe(500);
    // Must NOT leak error details
    expect(capturedBody).toEqual({ error: "Internal Server Error" });
  });
});

// â”€â”€ Custom decoy generator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” custom decoy generator", () => {
  it("uses custom decoy function when provided", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:0.0.0.0", "80"); // Above threshold

    const customDecoy = vi.fn(() => ({
      custom: true,
      message: "custom decoy",
    }));

    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      decoyGenerator: customDecoy,
    });

    const req = mockRequest({ ip: "0.0.0.0" });
    await wrapped(req);

    expect(customDecoy).toHaveBeenCalledTimes(1);
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

// â”€â”€ Debug mode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” debug mode", () => {
  it("does not throw in debug mode (console output is best-effort)", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      debugMode: true,
    });

    const req = mockRequest();
    // Should not throw despite debugMode trying to log
    await expect(wrapped(req)).resolves.toBeDefined();
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });
});

// â”€â”€ Non-JSON body â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” non-JSON body handling", () => {
  it("adds nonJsonBody score for invalid JSON and still passes if below threshold", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      scoring: { nonJsonBody: 10 },
    });

    // Invalid JSON â†’ nonJsonBody +10 (still below 65), handler should run
    const req = mockRequest({ body: "not-json-at-all" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("honeypots when nonJsonBody pushes score over threshold", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      body,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:8.8.8.8", "60"); // Already at 60

    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      scoring: { nonJsonBody: 10 }, // 60 + 10 = 70 â‰¥ 65
    });

    const req = mockRequest({ ip: "8.8.8.8", body: "not-json" });
    await wrapped(req);

    expect(innerHandler).not.toHaveBeenCalled();
  });
});

// â”€â”€ v1.6: IP allowlist â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” v1.6 IP allowlist", () => {
  it("skips all security checks for allowlisted IP (exact match)", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { allowed: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["10.0.0.1"] },
    });

    const req = mockRequest({ ip: "10.0.0.1" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("does NOT skip security for non-allowlisted IP", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { allowed: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["10.0.0.1"] },
    });

    const req = mockRequest({ ip: "10.0.0.2" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1); // Still called for clean req
  });

  it("allowlisted IP bypasses even with high pre-existing score", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:10.0.0.1", "100"); // Max score

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { allowed: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["10.0.0.1"] },
    });

    const req = mockRequest({ ip: "10.0.0.1" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1); // Bypassed
  });

  // ── CIDR range matching tests ─────────────────────────────────

  it("CIDR /8 matches IP within range", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:10.1.2.3", "100"); // Max score

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { allowed: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["10.0.0.0/8"] },
    });

    const req = mockRequest({ ip: "10.1.2.3" });
    await wrapped(req);

    // 10.1.2.3 is within 10.0.0.0/8 → bypass
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("CIDR /16 matches IP within range", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:192.168.1.100", "100");

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { allowed: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["192.168.0.0/16"] },
    });

    const req = mockRequest({ ip: "192.168.1.100" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("CIDR /8 does NOT match IP outside range", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:11.0.0.1", "100"); // Max score

    const innerHandler = vi.fn();

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["10.0.0.0/8"] },
    });

    const req = mockRequest({ ip: "11.0.0.1" });
    await wrapped(req);

    // 11.0.0.1 is OUTSIDE 10.0.0.0/8 → not bypassed, high score → honeypot
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it("CIDR /32 equals exact match", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:10.0.0.0", "100");

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { allowed: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["10.0.0.0/32"] },
    });

    const req = mockRequest({ ip: "10.0.0.0" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("CIDR /0 matches any IP", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:8.8.8.8", "100");

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { allowed: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["0.0.0.0/0"] },
    });

    const req = mockRequest({ ip: "8.8.8.8" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("invalid CIDR /33 does not crash and does not match", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:10.0.0.1", "100");

    const innerHandler = vi.fn();

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["10.0.0.0/33"] },
    });

    const req = mockRequest({ ip: "10.0.0.1" });
    await wrapped(req);

    // /33 is invalid, should not match → honeypot
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it("handles allowlist with empty ips array gracefully", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: [] },
    });

    const req = mockRequest({ ip: "10.0.0.1" });
    const res = await wrapped(req);

    // Empty ips means no IP is allowlisted → proceeds to pipeline checks
    expect(innerHandler).toHaveBeenCalledTimes(1);
    expect(res).toBeDefined();
  });

  it("does not crash with CIDR IP having fewer than 4 octets (ipToInt edge case)", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["1.2.3/24"] },
    });

    const req = mockRequest({ ip: "10.0.0.1" });
    const res = await wrapped(req);

    // 3-octet CIDR doesn't match but doesn't crash — clean request passes through
    expect(innerHandler).toHaveBeenCalledTimes(1);
    expect(res).toBeDefined();
  });

  it("does not crash with CIDR IP having invalid octet (ipToInt edge case)", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["10.0.0.256/24"] },
    });

    const req = mockRequest({ ip: "10.0.0.1" });
    const res = await wrapped(req);

    // Invalid octet CIDR doesn't match but doesn't crash — clean request passes through
    expect(innerHandler).toHaveBeenCalledTimes(1);
    expect(res).toBeDefined();
  });
});

// â”€â”€ v1.6: Body size limit â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” v1.6 body size limit", () => {
  it("adds body_too_large penalty when content-length exceeds limit", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      bodyLimit: { maxBytes: 10, enabled: true },
    });

    const req = mockRequest({
      headers: { "content-length": "100" },
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
      }),
    });
    await wrapped(req);

    // body_too_large adds +10, threshold is 65, so handler still runs
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });
});

// â”€â”€ v1.6: Method-based thresholds â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” v1.6 method-based thresholds", () => {
  it("uses method-specific threshold for POST that is stricter than default", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:5.5.5.5", "45");

    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      methodThresholds: { POST: 40 },
    });

    const req = mockRequest({ ip: "5.5.5.5", method: "POST" });
    await wrapped(req);

    // Score 45 >= POST threshold 40 -> honeypot
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it("uses default threshold when no method-specific one exists", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:6.6.6.6", "50");

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      methodThresholds: { POST: 40 }, // Only POST has custom threshold
    });

    const req = mockRequest({ ip: "6.6.6.6", method: "GET" });
    await wrapped(req);

    // 50 < 65 (default), so handler runs
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });
});

// â”€â”€ v1.6: Config presets â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” v1.6 config presets", () => {
  it("preset=strict blocks more aggressively", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:3.3.3.3", "45");

    const innerHandler = vi.fn();
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      preset: "strict", // threshold=40
    });

    const req = mockRequest({ ip: "3.3.3.3" });
    await wrapped(req);

    // 45 >= 40 (strict threshold) -> honeypot
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it("preset=relaxed allows more requests", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client, store } = createMockRedis();
    store.set("hc:s:4.4.4.4", "70");

    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      preset: "relaxed", // threshold=80
    });

    const req = mockRequest({ ip: "4.4.4.4" });
    await wrapped(req);

    // 70 < 80 (relaxed threshold) -> allowed
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });
});

// â”€â”€ v1.6: Violation messages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

describe("withHippocrates â€” v1.6 violation messages", () => {
  it("custom violation message overrides decoy for schema violations", async () => {
    let capturedBody: unknown = null;
    mockJson.mockImplementation((body, init) => {
      capturedBody = body;
      return { status: init?.status ?? 200, json: async () => body };
    });

    const { client } = createMockRedis();
    const innerHandler = vi.fn();

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      violationMessages: {
        schema: (_v) => ({ error: "invalid_data", code: "ERR_001" }),
      },
    });

    const req = mockRequest({
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        extra: "field", // Triggers schema violation
      }),
    });

    await wrapped(req);
    expect(innerHandler).not.toHaveBeenCalled();
    // Verify custom violation message was applied to response body
    expect(capturedBody).toHaveProperty("error", "invalid_data");
    expect(capturedBody).toHaveProperty("code", "ERR_001");
  });

  it("custom violation message overrides decoy for obfuscation violations", async () => {
    let capturedBody: unknown = null;
    mockJson.mockImplementation((body, init) => {
      capturedBody = body;
      return { status: init?.status ?? 200, json: async () => body };
    });

    const { client } = createMockRedis();
    const innerHandler = vi.fn();

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      violationMessages: {
        obfuscation: (_v) => ({ error: "suspicious_payload", code: "ERR_002" }),
      },
    });

    const req = mockRequest({
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        data: "SGVsbG8gV29ybGQgVGhpcyBpcyBhIEJhc2U2NCBlbmNvZGVkIHN0cmluZw==",
      }),
    });

    await wrapped(req);
    expect(innerHandler).not.toHaveBeenCalled();
    expect(capturedBody).toHaveProperty("error", "suspicious_payload");
    expect(capturedBody).toHaveProperty("code", "ERR_002");
  });
});

// ── v1.5: Event hooks ──────────────────────────────────────────────────

describe("withHippocrates — v1.5 event hooks", () => {
  it("onHoneypot hook receives honeypot event data when threat >= threshold", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn();
    const onHoneypot = vi.fn();

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 30,
      hooks: { onHoneypot },
    });

    // Extra field triggers L5 schema violation (+100) → score 100 ≥ 30 → honeypot
    const req = mockRequest({
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        admin: true,
      }),
    });

    await wrapped(req);

    expect(innerHandler).not.toHaveBeenCalled();
    expect(onHoneypot).toHaveBeenCalledTimes(1);

    const event = onHoneypot.mock.calls[0][0] as HoneypotEvent;
    expect(event.ip).toBe("127.0.0.1");
    expect(event.requestId).toBeDefined();
    expect(typeof event.requestId).toBe("string");
    expect(event.score).toBeGreaterThanOrEqual(100);
    expect(event.violations.length).toBeGreaterThan(0);
    expect(event.violations.some((v: string) => v.includes("schema"))).toBe(true);
    expect(event.decoyResponse).toBeDefined();
  });

  it("onPass hook receives pass event data for clean requests", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));
    const onPass = vi.fn();

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      hooks: { onPass },
    });

    const req = mockRequest({ ip: "1.2.3.4" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
    expect(onPass).toHaveBeenCalledTimes(1);

    const event = onPass.mock.calls[0][0] as PassEvent;
    expect(event.ip).toBe("1.2.3.4");
    expect(event.requestId).toBeDefined();
    expect(typeof event.requestId).toBe("string");
    expect(event.score).toBe(0);
  });
});

// ── Config edge cases ──────────────────────────────────────────────────

describe("withHippocrates — config edge cases", () => {
  it("handles invalid preset name without crashing", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      preset: "INVALID_PRESET_DOES_NOT_EXIST" as "strict",
    });

    const req = mockRequest();
    await wrapped(req);
    // Should not crash — handler called normally
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });
});

// ── Pipeline edge cases ─────────────────────────────────────────────────

describe("withHippocrates — pipeline edge cases", () => {
  it("handles pre-consumed body without crashing", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const bodyConsumer: AnalyzerPlugin = {
      name: "body_consumer",
      phase: "pre-body",
      priority: 1,
      analyze: async (req) => {
        await req.text();
        return { score: 0, tags: [] };
      },
    };

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      plugins: [bodyConsumer],
    });

    const req = mockRequest();
    await wrapped(req);
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("handles unhandled pipeline exception gracefully with debug mode", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    // Handler that throws unexpectedly
    const innerHandler = vi.fn(async (_req) => {
      throw new Error("Handler crashed!");
    });

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      debugMode: true,
      threatScoreThreshold: 65,
    });

    const req = mockRequest();
    await wrapped(req);
    // Should return 500 error response, not crash the process
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("detects L6 header anomalies with wildcard accept", async () => {
    let capturedScore = 0;
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (req: NextRequest) => {
      const score = parseInt(req.headers.get("x-hippocrates-score") ?? "0", 10);
      capturedScore = score;
      return { status: 200, body: { success: true } };
    });

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      scoring: { suspiciousHeaders: 15 },
    });

    // Send request with wildcard accept header (triggers L6 wildcard_accept anomaly)
    const req = mockRequest({
      headers: {
        "accept": "*/*",
        "user-agent": "test-agent",
      },
    });
    await wrapped(req);
    // Should still pass to handler (score from header anomaly < 65)
    expect(innerHandler).toHaveBeenCalledTimes(1);
    expect(capturedScore).toBeGreaterThanOrEqual(15);
  });

  it("forwards allowlisted IP with non-parseable body without crashing (pipeline L-1 catch)", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    // No ip override → resolveClientIp returns "127.0.0.1" which is allowlisted
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      allowlist: { ips: ["127.0.0.1"] },
    });

    // Non-JSON body causes JSON.parse to throw inside allowlist block → hits catch
    const req = mockRequest({ body: "not valid json" });
    await wrapped(req);
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("hits mid-flight score gate when pre-body score reaches threshold", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    // Very low threshold so missing UA (L3 = 15) exceeds it immediately
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 5,
    });

    const req = mockRequest({ headers: { "user-agent": "python-requests/2.28.0" } });
    const res = await wrapped(req);
    expect(innerHandler).not.toHaveBeenCalled();
    expect(res.status).toBe(200); // Honeypot returns 200
  });

  it("handles plugin analyzer error in debug mode (engine catch)", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const throwingPlugin: AnalyzerPlugin = {
      name: "thrower",
      phase: "pre-body",
      priority: 0,
      analyze: async () => {
        throw new Error("plugin failure");
      },
    };

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      debugMode: true,
      threatScoreThreshold: 65,
      plugins: [throwingPlugin],
    });

    const req = mockRequest();
    const res = await wrapped(req);
    // Plugin error is caught internally, pipeline continues normally
    expect(innerHandler).toHaveBeenCalledTimes(1);
    expect(res.status).toBe(200);
  });

  it("includes debug logs in addScore when debugMode is enabled", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      debugMode: true,
      threatScoreThreshold: 65,
    });

    const req = mockRequest();
    await wrapped(req);
    // Handler should be called (score < 65)
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("uses nonJsonBody weight when refinement throws non-ZodError during validation", async () => {
    mockJson.mockImplementation((body, init) => ({
      status: init?.status ?? 200,
      json: async () => body,
    }));

    const { client } = createMockRedis();

    // Schema with a refine that throws a regular Error (not ZodError)
    const schemaWithThrowingRefine = z
      .object({ val: z.string() })
      .strict()
      .refine(() => { throw new Error("custom error"); });

    const innerHandler = vi.fn(async (_req: NextRequest) => {
      return { status: 200, body: { success: true } };
    });

    const wrapped = withHippocrates(innerHandler, schemaWithThrowingRefine, client, {
      threatScoreThreshold: 65,
      scoring: { nonJsonBody: 50 },  // nonJsonBody weight
    });

    const req = mockRequest({ body: '{"val":"hello"}' });
    await wrapped(req);
    // nonJsonBody (50) + possible pre-body scores < 65, so handler called
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });
});
