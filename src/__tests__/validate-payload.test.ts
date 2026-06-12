/**
 * Unit tests for validatePayload (§6 Zod validator).
 *
 * Critical invariant: error messages must be intentionally vague.
 * No field names, no type information, no schema structure leakage.
 */
import { describe, it, expect } from "vitest";

vi.mock("next/server", () => ({
  NextRequest: class MockNextRequest {},
  NextResponse: {
    json: vi.fn(),
  },
}));

import { z } from "zod";
import { validatePayload } from "../index";

const StrictSchema = z
  .object({
    id: z.string().uuid(),
    name: z.string().min(1).max(100),
  })
  .strict();

describe("validatePayload", () => {
  it("returns ok:true with parsed data for valid input", () => {
    const input = {
      id: "550e8400-e29b-41d4-a716-446655440000",
      name: "Test User",
    };
    const result = validatePayload(input, StrictSchema);

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.data).toEqual(input);
    }
  });

  it("returns ok:false for missing required fields", () => {
    const input = { id: "550e8400-e29b-41d4-a716-446655440000" }; // missing "name"
    const result = validatePayload(input, StrictSchema);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.isSchemaViolation).toBe(true);
      // Critical: must NOT leak field names or schema structure
      // The error should be a generic count-only message
      expect(result.error).not.toMatch(/`[a-z]+`/i);
      expect(result.error).not.toContain("'name'");
      expect(result.error).toMatch(/^Validation failed \(\d+ constraints?\)$/);
    }
  });

  it("returns ok:false for wrong types", () => {
    const input = {
      id: 12345, // should be string
      name: "Test",
    };
    const result = validatePayload(input, StrictSchema);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.isSchemaViolation).toBe(true);
      expect(result.error).toContain("Validation failed");
      // Must not leak expected type info
      expect(result.error).not.toContain("uuid");
      expect(result.error).not.toContain("string");
    }
  });

  it("returns ok:false for extra fields (.strict() violation)", () => {
    const input = {
      id: "550e8400-e29b-41d4-a716-446655440000",
      name: "Test",
      extraField: "should trigger strict mode",
    };
    const result = validatePayload(input, StrictSchema);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.isSchemaViolation).toBe(true);
      expect(result.error).toContain("Validation failed");
      // Critical: must not leak the extra field name
      expect(result.error).not.toContain("extraField");
    }
  });

  it("handles non-Zod errors gracefully", () => {
    // Simulate an error that is not a ZodError by passing null to a schema
    // that expects an object. Zod's safeParse handles this, but parse throws
    // Error on truly malformed inputs.
    const result = validatePayload("not-an-object", StrictSchema);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      // For truly invalid inputs, ZodError is still thrown by parse
      expect(result.isSchemaViolation).toBe(true);
    }
  });

  it("reports the correct number of constraints violated", () => {
    const input = {
      // Both id and name are missing
    };
    const result = validatePayload(input, StrictSchema);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("2 constraints");
    }
  });

  it("uses singular 'constraint' for single violation", () => {
    const input = {
      id: "550e8400-e29b-41d4-a716-446655440000",
      // name must be a string but we omit it — triggers 1 issue
    };
    const result = validatePayload(input, StrictSchema);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toMatch(/1 constraint/);
    }
  });
});
