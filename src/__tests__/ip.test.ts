/**
 * Unit tests for IP address normalization utilities (src/utils/ip.ts).
 *
 * Covers normalizeIp() and resolveClientIp() with edge cases for:
 *   - IPv4, IPv6, IPv4-mapped IPv6
 *   - Loopback normalization
 *   - Bracket wrapping and zone IDs
 *   - Header resolution chain
 *   - Fail-open behavior for unparseable input
 */
import { describe, it, expect } from "vitest";
import { normalizeIp, resolveClientIp } from "../utils/ip";

// ── normalizeIp ──────────────────────────────────────────────────────

describe("normalizeIp", () => {
  // Null / empty / whitespace
  it("returns 127.0.0.1 for null input", () => {
    expect(normalizeIp(null)).toBe("127.0.0.1");
  });

  it("returns 127.0.0.1 for empty string", () => {
    expect(normalizeIp("")).toBe("127.0.0.1");
  });

  it("returns 127.0.0.1 for whitespace-only string", () => {
    expect(normalizeIp("   ")).toBe("127.0.0.1");
  });

  // Standard IPv4
  it("returns standard IPv4 addresses as-is", () => {
    expect(normalizeIp("192.168.1.1")).toBe("192.168.1.1");
    expect(normalizeIp("10.0.0.1")).toBe("10.0.0.1");
    expect(normalizeIp("172.16.0.5")).toBe("172.16.0.5");
    expect(normalizeIp("8.8.8.8")).toBe("8.8.8.8");
  });

  it("trims whitespace from IPv4 addresses", () => {
    expect(normalizeIp("  10.0.0.1  ")).toBe("10.0.0.1");
  });

  // IPv4-mapped IPv6
  it("extracts IPv4 from ::ffff: prefixed addresses", () => {
    expect(normalizeIp("::ffff:192.168.1.1")).toBe("192.168.1.1");
    expect(normalizeIp("::ffff:10.0.0.1")).toBe("10.0.0.1");
  });

  it("handles mixed-case ::ffff: prefix", () => {
    expect(normalizeIp("::FFFF:192.168.1.1")).toBe("192.168.1.1");
    expect(normalizeIp("::FfFf:172.16.0.5")).toBe("172.16.0.5");
  });

  it("does not extract if mapped portion is not valid IPv4", () => {
    const result = normalizeIp("::ffff:xyz");
    // Returns lowercased stripped string since it has colons
    expect(result).not.toBe("xyz");
  });

  // IPv6 loopback
  it("normalizes ::1 (IPv6 loopback) to 127.0.0.1", () => {
    expect(normalizeIp("::1")).toBe("127.0.0.1");
  });

  it("normalizes expanded IPv6 loopback to 127.0.0.1", () => {
    expect(normalizeIp("0:0:0:0:0:0:0:1")).toBe("127.0.0.1");
  });

  it("normalizes mixed-case ::1 to 127.0.0.1", () => {
    expect(normalizeIp("::1")).toBe("127.0.0.1");
  });

  // Bracket-wrapped IPv6
  it("strips surrounding brackets from IPv6 addresses", () => {
    expect(normalizeIp("[::1]")).toBe("127.0.0.1");
    expect(normalizeIp("[::ffff:192.168.1.1]")).toBe("192.168.1.1");
    expect(normalizeIp("[2001:db8::1]")).toBe("2001:db8::1");
  });

  // Zone IDs
  it("strips zone ID from IPv6 addresses", () => {
    expect(normalizeIp("fe80::1%eth0")).toBe("fe80::1");
    expect(normalizeIp("fe80::aabb:ccdd%en0")).toBe("fe80::aabb:ccdd");
  });

  it("strips zone ID from bracket-wrapped IPv6", () => {
    expect(normalizeIp("[fe80::1%eth0]")).toBe("fe80::1");
  });

  // General IPv6
  it("lowercases and returns general IPv6 addresses", () => {
    expect(normalizeIp("2001:DB8::1")).toBe("2001:db8::1");
    expect(normalizeIp("FE80::")).toBe("fe80::");
    expect(normalizeIp("2001:0DB8:0000:0000:0000:0000:0000:0001")).toBe(
      "2001:0db8:0000:0000:0000:0000:0000:0001"
    );
  });

  // Fail-open for unparseable input
  it("returns the original string for non-IP inputs (fail-open)", () => {
    expect(normalizeIp("not-an-ip")).toBe("not-an-ip");
    expect(normalizeIp("localhost")).toBe("localhost");
    expect(normalizeIp("some-random-hostname.local")).toBe(
      "some-random-hostname.local"
    );
  });

  it("does not confuse IPv4-like strings in non-standard format", () => {
    // A string with dots but not a valid IPv4 is returned as-is
    expect(normalizeIp("256.256.256.256")).toBe("256.256.256.256");
  });

  it("returns as-is for strings with single colon (not IPv6)", () => {
    // Single colon means it doesn't have enough colons for IPv6
    expect(normalizeIp("host:port")).toBe("host:port");
  });
});

// ── resolveClientIp ──────────────────────────────────────────────────

describe("resolveClientIp", () => {
  // Simple mock headers helper
  function mockHeaders(
    entries: Record<string, string | null>
  ): { get(name: string): string | null } {
    return {
      get: (name: string) => entries[name.toLowerCase()] ?? null,
    };
  }

  // x-forwarded-for
  it("uses x-forwarded-for header as primary source", () => {
    const headers = mockHeaders({ "x-forwarded-for": "203.0.113.5" });
    expect(resolveClientIp(headers)).toBe("203.0.113.5");
  });

  it("takes the first IP from comma-separated x-forwarded-for", () => {
    const headers = mockHeaders({
      "x-forwarded-for": "203.0.113.5, 198.51.100.2, 192.0.2.1",
    });
    expect(resolveClientIp(headers)).toBe("203.0.113.5");
  });

  it("trims whitespace from x-forwarded-for entries", () => {
    const headers = mockHeaders({ "x-forwarded-for": "  203.0.113.5  " });
    expect(resolveClientIp(headers)).toBe("203.0.113.5");
  });

  // x-real-ip fallback
  it("falls back to x-real-ip when x-forwarded-for is absent", () => {
    const headers = mockHeaders({ "x-real-ip": "198.51.100.10" });
    expect(resolveClientIp(headers)).toBe("198.51.100.10");
  });

  // cf-connecting-ip fallback
  it("falls back to cf-connecting-ip when x-forwarded-for and x-real-ip are absent", () => {
    const headers = mockHeaders({ "cf-connecting-ip": "192.0.2.99" });
    expect(resolveClientIp(headers)).toBe("192.0.2.99");
  });

  // header priority chain
  it("prioritizes x-forwarded-for over x-real-ip and cf-connecting-ip", () => {
    const headers = mockHeaders({
      "x-forwarded-for": "10.0.0.1",
      "x-real-ip": "10.0.0.2",
      "cf-connecting-ip": "10.0.0.3",
    });
    expect(resolveClientIp(headers)).toBe("10.0.0.1");
  });

  it("falls back to x-real-ip when cf-connecting-ip but x-forwarded-for absent", () => {
    const headers = mockHeaders({
      "x-real-ip": "10.0.0.2",
      "cf-connecting-ip": "10.0.0.3",
    });
    expect(resolveClientIp(headers)).toBe("10.0.0.2");
  });

  // fallback to 127.0.0.1
  it("returns 127.0.0.1 when no headers are present", () => {
    const headers = mockHeaders({});
    expect(resolveClientIp(headers)).toBe("127.0.0.1");
  });

  it("returns 127.0.0.1 when all header values are null", () => {
    const headers = mockHeaders({
      "x-forwarded-for": null,
      "x-real-ip": null,
      "cf-connecting-ip": null,
    });
    expect(resolveClientIp(headers)).toBe("127.0.0.1");
  });

  // normalization is applied to resolved IP
  it("normalizes IPv6 loopback via x-forwarded-for to 127.0.0.1", () => {
    const headers = mockHeaders({ "x-forwarded-for": "::1" });
    expect(resolveClientIp(headers)).toBe("127.0.0.1");
  });

  it("normalizes IPv4-mapped IPv6 via x-real-ip", () => {
    const headers = mockHeaders({ "x-real-ip": "::ffff:10.0.0.1" });
    expect(resolveClientIp(headers)).toBe("10.0.0.1");
  });

  it("normalizes bracket-wrapped IPv6 via cf-connecting-ip", () => {
    const headers = mockHeaders({ "cf-connecting-ip": "[::1]" });
    expect(resolveClientIp(headers)).toBe("127.0.0.1");
  });
});
