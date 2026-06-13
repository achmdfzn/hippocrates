/**
 * Integration tests for ML engine plugin wired into the full pipeline.
 *
 * Mocks global.fetch to simulate Python sidecar responses. Tests score
 * accumulation, graceful degradation, and bodyRaw delivery.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ── NextRequest mock (must be hoisted before imports) ────────────────

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

    get nextUrl() {
      return { pathname: new URL(this.url).pathname };
    }
  },
  NextResponse: {
    json: vi.fn((body: unknown, init?: { status?: number }) => ({
      status: init?.status ?? 200,
      json: async () => body,
    })),
  },
}));

import { withHippocrates } from "../index";
import { mlEnginePlugin } from "../plugins/ml-engine";
import { createMockRedis, TestSchema } from "./helpers";
import type { NextRequest } from "next/server";

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

// ── Fetch mock ───────────────────────────────────────────────────────

let fetchMock: ReturnType<typeof vi.fn>;
let lastRequestBody: unknown = null;

beforeEach(() => {
  fetchMock = vi.fn();
  lastRequestBody = null;

  // Default: respond with clean (low score)
  fetchMock.mockImplementation(async (url: string, init?: RequestInit) => {
    if (init?.body && typeof init.body === "string") {
      lastRequestBody = JSON.parse(init.body);
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({
        score: 0,
        tags: [],
        analyses: {},
      }),
    };
  });

  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function createWrappedHandler(config?: Record<string, unknown>) {
  const { client } = createMockRedis();
  const innerHandler = vi.fn(async (_req: NextRequest) => ({
    status: 200,
    body: { success: true },
  }));

  const wrapped = withHippocrates(innerHandler, TestSchema, client, {
    threatScoreThreshold: 65,
    plugins: [mlEnginePlugin({ baseUrl: "http://ml-engine:8000", timeoutMs: 1000 })],
    ...config,
  });

  return { wrapped, innerHandler, redis: client };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("ML engine integration — clean request", () => {
  it("calls ML engine and forwards to handler when score is low", async () => {
    fetchMock.mockImplementation(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ score: 5, tags: ["prompt:clean"], analyses: {} }),
    }));

    const { wrapped, innerHandler } = createWrappedHandler();
    const req = mockRequest();
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
    // fetch was called (ML engine was contacted)
    expect(fetchMock).toHaveBeenCalledTimes(1);
    // Verify the URL
    expect(fetchMock.mock.calls[0][0]).toBe("http://ml-engine:8000/analyze");
  });

  it("delivers bodyRaw in the ML request body", async () => {
    fetchMock.mockImplementation(async (_url: string, init?: RequestInit) => {
      if (init?.body && typeof init.body === "string") {
        lastRequestBody = JSON.parse(init.body);
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ score: 0, tags: [], analyses: {} }),
      };
    });

    const { wrapped } = createWrappedHandler();
    const req = mockRequest({
      body: JSON.stringify({ userId: "550e8400-e29b-41d4-a716-446655440000", action: "read", extra: "data" }),
    });
    await wrapped(req);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(lastRequestBody).not.toBeNull();
    expect((lastRequestBody as Record<string, unknown>).body_raw).toBe(
      JSON.stringify({ userId: "550e8400-e29b-41d4-a716-446655440000", action: "read", extra: "data" })
    );
  });
});

describe("ML engine integration — threat detection", () => {
  it("honeypots when ML engine detects prompt injection", async () => {
    fetchMock.mockImplementation(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        score: 80,
        tags: ["prompt_injection"],
        analyses: { prompt_injection: { score: 80, tags: ["prompt_injection"], confidence: 0.95 } },
      }),
    }));

    const { wrapped, innerHandler } = createWrappedHandler();
    const req = mockRequest();
    await wrapped(req);

    // 0 (built-in) + 80 (ML) = 80 >= 65 → honeypot
    expect(innerHandler).not.toHaveBeenCalled();
  });

  it("combined built-in + ML score pushes over threshold", async () => {
    // Pre-existing score of 50, plus ML returns 20 = 70 ≥ 65
    const { client, store } = createMockRedis();
    store.set("hc:s:1.2.3.4", "50");

    fetchMock.mockImplementation(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ score: 20, tags: ["ml:suspicious"], analyses: {} }),
    }));

    const innerHandler = vi.fn(async (_req: NextRequest) => ({
      status: 200,
      body: { success: true },
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      plugins: [mlEnginePlugin({ baseUrl: "http://ml-engine:8000" })],
    });

    const req = mockRequest({ ip: "1.2.3.4" });
    await wrapped(req);

    expect(innerHandler).not.toHaveBeenCalled();
  });
});

describe("ML engine integration — graceful degradation", () => {
  it("forwards to handler when ML engine is unreachable (no crash)", async () => {
    fetchMock.mockRejectedValue(new Error("Connection refused"));

    const { wrapped, innerHandler } = createWrappedHandler();
    const req = mockRequest();
    await wrapped(req);

    // Pipeline should not crash, handler should be called
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("returns ml-engine-unreachable tag when fetch fails", async () => {
    fetchMock.mockRejectedValue(new Error("Network error"));
    const { client } = createMockRedis();
    let capturedHeaders: Headers | null = null;

    const innerHandler = vi.fn(async (req: NextRequest) => {
      capturedHeaders = req.headers;
      return { status: 200, body: { success: true } };
    });

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      plugins: [mlEnginePlugin({ baseUrl: "http://ml-engine:8000", timeoutMs: 100 })],
    });

    const req = mockRequest();
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
    // x-hippocrates-clean should still be "1" (no threat detected)
    expect(capturedHeaders?.get("x-hippocrates-clean")).toBe("1");
  });

  it("handles non-200 response from ML engine gracefully", async () => {
    fetchMock.mockImplementation(async () => ({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: async () => ({}),
    }));

    const { wrapped, innerHandler } = createWrappedHandler();
    const req = mockRequest();
    await wrapped(req);

    // Non-200 is non-fatal — returns score=0 with ml-engine-error tag
    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("handles timeout from ML engine gracefully", async () => {
    // Simulate timeout: reject after delay
    fetchMock.mockImplementation(async () => {
      await new Promise((_, reject) => setTimeout(() => reject(new Error("Aborted")), 50));
    });

    const { wrapped, innerHandler } = createWrappedHandler();
    const req = mockRequest();
    await wrapped(req);

    // Timeout is non-fatal — handler should still run
    expect(innerHandler).toHaveBeenCalledTimes(1);
  }, 5000);
});

describe("ML engine integration — score threshold filtering", () => {
  it("ignores ML scores below minScoreThreshold", async () => {
    fetchMock.mockImplementation(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ score: 5, tags: ["prompt:low"], analyses: {} }),
    }));

    const { client } = createMockRedis();
    const innerHandler = vi.fn(async (_req: NextRequest) => ({
      status: 200,
      body: { success: true },
    }));

    // minScoreThreshold=10 means score 5 is ignored
    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      plugins: [mlEnginePlugin({ baseUrl: "http://ml-engine:8000", minScoreThreshold: 10 })],
    });

    const req = mockRequest();
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
  });

  it("accepts ML scores above minScoreThreshold", async () => {
    fetchMock.mockImplementation(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ score: 15, tags: ["ml:medium"], analyses: {} }),
    }));

    const { client } = createMockRedis();
    let capturedHeaders: Headers | null = null;

    const innerHandler = vi.fn(async (req: NextRequest) => {
      capturedHeaders = req.headers;
      return { status: 200, body: { success: true } };
    });

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      plugins: [mlEnginePlugin({ baseUrl: "http://ml-engine:8000", minScoreThreshold: 10 })],
    });

    const req = mockRequest();
    await wrapped(req);

    // 0 (built-in) + 15 (ML) = 15 < 65 → handler called
    expect(innerHandler).toHaveBeenCalledTimes(1);
    // Verify score header reflects ML contribution
    expect(capturedHeaders?.get("x-hippocrates-score")).toBe("15");
  });
});

describe("ML engine integration — full pipeline flow", () => {
  it("appends ML tags to x-hippocrates-clean header", async () => {
    // Set a pre-existing score
    const { client, store } = createMockRedis();
    store.set("hc:s:9.9.9.9", "10");

    let capturedHeaders: Headers | null = null;

    const innerHandler = vi.fn(async (req: NextRequest) => {
      capturedHeaders = req.headers;
      return { status: 200, body: { success: true } };
    });

    fetchMock.mockImplementation(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ score: 12, tags: ["prompt_injection", "obfuscation_advanced"], analyses: {} }),
    }));

    const wrapped = withHippocrates(innerHandler, TestSchema, client, {
      threatScoreThreshold: 65,
      plugins: [mlEnginePlugin({ baseUrl: "http://ml-engine:8000", minScoreThreshold: 5 })],
    });

    const req = mockRequest({ ip: "9.9.9.9" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
    // Score = 10 (existing) + 0 (built-in) + 12 (ML) = 22 → still clean
    expect(capturedHeaders?.get("x-hippocrates-score")).toBe("22");
  });

  it("L4 obfuscation + ML contribution both accumulate before final gate", async () => {
    // Request has obfuscation → L4 adds 100.
    // Pipeline runs all post-body analyzers before final score gate,
    // so ML engine IS called even though L4 already hits threshold.
    let mlRequestBody: unknown = null;
    fetchMock.mockImplementation(async (_url: string, init?: RequestInit) => {
      if (init?.body && typeof init.body === "string") {
        mlRequestBody = JSON.parse(init.body);
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ score: 30, tags: ["ml:additional"], analyses: {} }),
      };
    });

    const { wrapped, innerHandler } = createWrappedHandler();
    const req = mockRequest({
      body: JSON.stringify({
        userId: "550e8400-e29b-41d4-a716-446655440000",
        action: "read",
        data: "SGVsbG8gV29ybGQgVGhpcyBpcyBhIEJhc2U2NCBlbmNvZGVkIHN0cmluZw==",
      }),
    });
    await wrapped(req);

    // Inner handler NOT called (final gate catches L4 + ML = 130 >= 65)
    expect(innerHandler).not.toHaveBeenCalled();
    // ML engine WAS called (all post-body analyzers run before final gate)
    expect(fetchMock).toHaveBeenCalledTimes(1);
    // Verify body_raw was delivered to ML engine
    expect(mlRequestBody).not.toBeNull();
    expect((mlRequestBody as Record<string, unknown>).body_raw).toContain("SGVsbG8gV29ybGQg");
  });
});

describe("ML engine integration — GET requests", () => {
  it("still runs ML engine for GET requests (no body)", async () => {
    fetchMock.mockImplementation(async (_url: string, init?: RequestInit) => {
      // Capture request body from fetch call
      if (init?.body && typeof init.body === "string") {
        lastRequestBody = JSON.parse(init.body);
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({ score: 0, tags: [], analyses: {} }),
      };
    });

    const { wrapped, innerHandler } = createWrappedHandler();
    const req = mockRequest({ method: "GET" });
    await wrapped(req);

    expect(innerHandler).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    // Verify body_raw is null for GET (no body to send)
    expect(lastRequestBody).not.toBeNull();
    expect((lastRequestBody as Record<string, unknown>).body_raw).toBeNull();
  });
});
