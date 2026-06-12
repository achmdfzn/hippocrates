/**
 * Integration tests for withHippocrates (§7) — the primary HOF export.
 *
 * Tests each security layer (L0-L5), score gating, error handling,
 * and the forward-to-handler path.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Hoisted mockJson — vi.mock is hoisted to top, so any variable it references
// must be defined with vi.hoisted() to exist in the hoisted scope.
const { mockJson } = vi.hoisted(() => ({
  mockJson: vi.fn(),
}));

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

import { withHippocrates } from "../index";
import { createMockRedis, TestSchema } from "./helpers";
import type { HippocratesConfig } from "../index";

beforeEach(() => {
  mockJson.mockReset();
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

// ── Basic pass-through ───────────────────────────────────────────────

describe("withHippocrates — basic pass-through", () => {
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

// ── L0: Pre-flight ───────────────────────────────────────────────────

describe("withHippocrates — L0 pre-flight", () => {
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

// ── L1: Timing ───────────────────────────────────────────────────────

describe("withHippocrates — L1 timing", () => {
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

// ── L2: Velocity ─────────────────────────────────────────────────────

describe("withHippocrates — L2 velocity", () => {
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

// ── L3: User-Agent ───────────────────────────────────────────────────

describe("withHippocrates — L3 User-Agent", () => {
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

// ── L4: Obfuscation ──────────────────────────────────────────────────

describe("withHippocrates — L4 obfuscation", () => {
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

    // 100 pts from obfuscation >= 65 threshold → honeypot, handler not called
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

// ── L5: Schema violation ─────────────────────────────────────────────

describe("withHippocrates — L5 schema violation", () => {
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

// ── GET / HEAD / OPTIONS ─────────────────────────────────────────────

describe("withHippocrates — GET/HEAD/OPTIONS", () => {
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

// ── Score gate (post-L5) ─────────────────────────────────────────────

describe("withHippocrates — score gate after all layers", () => {
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
        extra: "field", // L5 will fire: +100 → honeypot
      }),
    });

    await wrapped(req);

    // Even though pre-flight didn't catch it (50 < 65), L5 adds 100,
    // and the post-L5 gate catches it
    expect(innerHandler).not.toHaveBeenCalled();
  });
});

// ── Error handling ───────────────────────────────────────────────────

describe("withHippocrates — error handling", () => {
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

// ── Custom decoy generator ───────────────────────────────────────────

describe("withHippocrates — custom decoy generator", () => {
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

// ── Debug mode ───────────────────────────────────────────────────────

describe("withHippocrates — debug mode", () => {
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

// ── Non-JSON body ────────────────────────────────────────────────────

describe("withHippocrates — non-JSON body handling", () => {
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

    // Invalid JSON → nonJsonBody +10 (still below 65), handler should run
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
      scoring: { nonJsonBody: 10 }, // 60 + 10 = 70 ≥ 65
    });

    const req = mockRequest({ ip: "8.8.8.8", body: "not-json" });
    await wrapped(req);

    expect(innerHandler).not.toHaveBeenCalled();
  });
});
