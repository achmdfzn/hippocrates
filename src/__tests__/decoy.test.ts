/**
 * Unit tests for decoy response generation (§4) and honeypot serving (§5).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("next/server", () => ({
  NextRequest: class MockNextRequest {},
  NextResponse: {
    json: vi.fn((body, init) => {
      const headers = new Map<string, string>();
      return {
        status: init?.status ?? 200,
        headers: {
          get: (name: string) => headers.get(name.toLowerCase()) ?? null,
          set: (name: string, value: string) =>
            headers.set(name.toLowerCase(), value),
          delete: (name: string) => headers.delete(name.toLowerCase()),
        },
        json: async () => body,
      };
    }),
  },
}));

import { generateDecoyResponse, serveHoneypot } from "../index";
import { createMockRequest } from "./helpers";

// ── generateDecoyResponse ────────────────────────────────────────────

describe("generateDecoyResponse", () => {
  it("returns an object with success: true", () => {
    const req = createMockRequest();
    const result = generateDecoyResponse(req);
    expect(result).toHaveProperty("success", true);
  });

  it("returns at least 3 different shapes over multiple calls", () => {
    const req = createMockRequest();
    const shapes = new Set<string>();
    for (let i = 0; i < 30; i++) {
      const result = generateDecoyResponse(req);
      if ("data" in result) shapes.add("template_a");
      if ("accessToken" in result) shapes.add("template_b");
      if ("items" in result) shapes.add("template_c");
    }
    // With 30 calls, we should have seen at least 2 of 3 templates
    expect(shapes.size).toBeGreaterThanOrEqual(2);
  });

  it("Template A (data shape) has expected fields when returned", () => {
    const req = createMockRequest();
    let foundA = false;
    for (let i = 0; i < 50; i++) {
      const result = generateDecoyResponse(req);
      if ("data" in result && "requestId" in result) {
        foundA = true;
        expect(result).toHaveProperty("success", true);
        expect(typeof result.requestId).toBe("string");
        expect(result).toHaveProperty("timestamp");
        expect(result.data).toHaveProperty("id");
        expect(result.data).toHaveProperty("status", "active");
        break;
      }
    }
    expect(foundA).toBe(true);
  });

  it("Template B (auth shape) has accessToken as a string", () => {
    const req = createMockRequest();
    for (let i = 0; i < 20; i++) {
      const result = generateDecoyResponse(req);
      if ("accessToken" in result) {
        expect(typeof result.accessToken).toBe("string");
        expect(result.accessToken).toBeTruthy();
        expect(result).toHaveProperty("tokenType", "Bearer");
        expect(result).toHaveProperty("expiresIn", 3600);
        expect(result).toHaveProperty("scope");
        expect(result).toHaveProperty("issuedAt");
        break;
      }
    }
  });

  it("Template C (list shape) has items array and pagination", () => {
    const req = createMockRequest();
    for (let i = 0; i < 20; i++) {
      const result = generateDecoyResponse(req);
      if ("items" in result) {
        expect(Array.isArray(result.items)).toBe(true);
        expect(result.items.length).toBeGreaterThanOrEqual(3);
        expect(result).toHaveProperty("pagination");
        expect(result.pagination).toHaveProperty("hasNext", true);
        break;
      }
    }
  });
});

// ── serveHoneypot ────────────────────────────────────────────────────

describe("serveHoneypot", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns a response with status 200", () => {
    const req = createMockRequest();
    const decoyFn = () => ({ success: true, fake: true });
    const res = serveHoneypot(req, decoyFn, "1.2.3.4", 80, ["test"], false);

    expect(res.status).toBe(200);
  });

  it("sets honeypot headers (x-request-id, x-processing-time)", () => {
    const req = createMockRequest();
    const decoyFn = () => ({ success: true });
    const res = serveHoneypot(req, decoyFn, "1.2.3.4", 80, ["test"], false);

    expect(res.headers.get("x-request-id")).toBeTruthy();
    expect(res.headers.get("x-processing-time")).toMatch(/^\d+\.\d+ms$/);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("removes server info headers (x-powered-by, server)", () => {
    const req = createMockRequest();
    const decoyFn = () => ({ success: true });
    const res = serveHoneypot(req, decoyFn, "1.2.3.4", 80, ["test"], true);

    expect(res.headers.get("x-powered-by")).toBeNull();
    expect(res.headers.get("server")).toBeNull();
  });

  it("invokes the decoy function to produce the response body", () => {
    const req = createMockRequest();
    const decoyFn = vi.fn(() => ({ custom: true, data: "fake" }));
    serveHoneypot(req, decoyFn, "1.2.3.4", 80, ["test"], false);

    expect(decoyFn).toHaveBeenCalledTimes(1);
    expect(decoyFn).toHaveBeenCalledWith(req);
  });

  it("uses violationMessages fallback when violationType key is missing but primaryViolation key exists", async () => {
    const req = createMockRequest();
    const decoyFn = () => ({ base: true });
    const violationMessages = {
      // Key matches full violation string (not the type prefix)
      "obfuscation:base64": () => ({ custom: "fallback_worked" }),
    };
    const res = serveHoneypot(req, decoyFn, "1.2.3.4", 100, ["obfuscation:base64"], false, violationMessages);
    const data = await res.json();
    expect(data).toHaveProperty("custom", "fallback_worked");
    expect(data).toHaveProperty("base", true);
  });

  it("falls back to primaryViolation when violationType is empty after split", async () => {
    const req = createMockRequest();
    const decoyFn = () => ({ base: true });
    const violationMessages = {
      ":empty_type_prefix": () => ({ custom: "empty_type_fallback" }),
    };
    const res = serveHoneypot(req, decoyFn, "1.2.3.4", 80, [":empty_type_prefix"], false, violationMessages);
    const data = await res.json();
    expect(data).toHaveProperty("custom", "empty_type_fallback");
    expect(data).toHaveProperty("base", true);
  });
});
