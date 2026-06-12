/**
 * Tests for ensureStrict (§6 nested .strict() utility).
 *
 * ensureStrict recursively walks a Zod schema tree and applies
 * .strict() to every ZodObject found at any depth.
 */
import { describe, it, expect } from "vitest";
import { z } from "zod";
import { ensureStrict } from "../index";

describe("ensureStrict", () => {
  it("applies .strict() to a top-level object", () => {
    const schema = z.object({ id: z.string() });
    const strict = ensureStrict(schema);

    const result = strict.safeParse({ id: "abc", extra: 1 });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.code === "unrecognized_keys")).toBe(true);
    }
  });

  it("applies .strict() to a nested object", () => {
    const schema = z.object({
      id: z.string(),
      meta: z.object({ tag: z.string() }),
    });
    const strict = ensureStrict(schema);

    const result = strict.safeParse({
      id: "abc",
      meta: { tag: "hello", extra: true },
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.code === "unrecognized_keys")).toBe(true);
    }
  });

  it("applies .strict() to objects inside arrays", () => {
    const schema = z.object({
      items: z.array(z.object({ id: z.string() })),
    });
    const strict = ensureStrict(schema);

    const result = strict.safeParse({
      items: [{ id: "a", extra: true }],
    });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((i) => i.code === "unrecognized_keys")).toBe(true);
    }
  });

  it("applies .strict() to objects inside unions", () => {
    const schema = z.union([
      z.object({ type: z.literal("a"), val: z.string() }),
      z.object({ type: z.literal("b"), val: z.number() }),
    ]);
    const strict = ensureStrict(schema);

    const result = strict.safeParse({ type: "a", val: "ok", extra: 1 });
    expect(result.success).toBe(false);
  });

  it("applies .strict() to objects inside intersections", () => {
    const schema = z.intersection(
      z.object({ a: z.string() }),
      z.object({ b: z.number() })
    );
    const strict = ensureStrict(schema);

    const result = strict.safeParse({ a: "x", b: 1, extra: true });
    expect(result.success).toBe(false);
  });

  it("applies .strict() to optional nested objects", () => {
    const schema = z.object({
      meta: z.object({ tag: z.string() }).optional(),
    });
    const strict = ensureStrict(schema);

    const ok = strict.safeParse({});
    expect(ok.success).toBe(true);

    const fail = strict.safeParse({ meta: { tag: "x", extra: true } });
    expect(fail.success).toBe(false);
  });

  it("applies .strict() to nullable nested objects", () => {
    const schema = z.object({
      meta: z.object({ tag: z.string() }).nullable(),
    });
    const strict = ensureStrict(schema);

    const ok = strict.safeParse({ meta: null });
    expect(ok.success).toBe(true);

    const fail = strict.safeParse({ meta: { tag: "x", extra: true } });
    expect(fail.success).toBe(false);
  });

  it("preserves valid data through the strict schema", () => {
    const schema = z.object({
      id: z.string(),
      nested: z.object({ val: z.number() }),
    });
    const strict = ensureStrict(schema);

    const result = strict.safeParse({
      id: "abc",
      nested: { val: 42 },
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toEqual({ id: "abc", nested: { val: 42 } });
    }
  });

  it("handles deeply nested objects", () => {
    const schema = z.object({
      level1: z.object({
        level2: z.object({
          level3: z.object({ value: z.string() }),
        }),
      }),
    });
    const strict = ensureStrict(schema);

    const result = strict.safeParse({
      level1: {
        level2: {
          level3: { value: "ok", extra: true },
        },
      },
    });
    expect(result.success).toBe(false);
  });

  it("passes through primitive-only schemas unchanged", () => {
    const schema = z.string();
    const strict = ensureStrict(schema);

    expect(strict.safeParse("hello").success).toBe(true);
    expect(strict.safeParse(123).success).toBe(false);
  });

  it("handles ZodRecord with object values", () => {
    const schema = z.record(z.object({ val: z.string() }));
    const strict = ensureStrict(schema);

    const result = strict.safeParse({ key: { val: "ok", extra: true } });
    expect(result.success).toBe(false);
  });

  it("preserves existing .strict() on the top level", () => {
    const schema = z.object({ id: z.string() }).strict();
    const strict = ensureStrict(schema);

    const result = strict.safeParse({ id: "abc", extra: true });
    expect(result.success).toBe(false);
  });

  it("handles ZodDefault with inner object", () => {
    const schema = z.object({
      meta: z.object({ tag: z.string() }).default({ tag: "default" }),
    });
    const strict = ensureStrict(schema);

    const noExtra = strict.safeParse({ meta: { tag: "x" } });
    expect(noExtra.success).toBe(true);

    const withExtra = strict.safeParse({ meta: { tag: "x", extra: true } });
    expect(withExtra.success).toBe(false);
  });

  it("handles ZodReadonly wrapping an object", () => {
    const schema = z.object({
      meta: z.object({ tag: z.string() }).readonly(),
    });
    const strict = ensureStrict(schema);

    const result = strict.safeParse({ meta: { tag: "x", extra: true } });
    expect(result.success).toBe(false);
  });

  // ── ZodEffects preservation ──────────────────────────────────────────

  it("preserves .refine() validation after ensureStrict", () => {
    const schema = z
      .object({
        password: z.string().min(3),
        confirm: z.string().min(3),
      })
      .refine((data) => data.password === data.confirm, {
        message: "Passwords must match",
      });

    const strict = ensureStrict(schema);

    // Refinement should still fire (passwords don't match)
    const fail = strict.safeParse({
      password: "abc",
      confirm: "xyz",
    });
    expect(fail.success).toBe(false);

    // Refinement should pass + strict should still reject extra fields
    const ok = strict.safeParse({
      password: "abc",
      confirm: "abc",
    });
    expect(ok.success).toBe(true);

    // Strict should still reject extra fields despite refinement passing
    const strictFail = strict.safeParse({
      password: "abc",
      confirm: "abc",
      extra: true,
    });
    expect(strictFail.success).toBe(false);
  });

  it("preserves .transform() after ensureStrict", () => {
    const schema = z
      .object({
        val: z.string(),
      })
      .transform((data) => ({
        val: parseInt(data.val, 10),
      }));

    const strict = ensureStrict(schema);

    // Transform should convert string to number
    const result = strict.safeParse({ val: "42" });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.val).toBe(42); // number, not string
    }
  });

  it("preserves z.preprocess() after ensureStrict", () => {
    const schema = z.preprocess(
      (val) => {
        if (typeof val === "string") {
          try {
            return JSON.parse(val);
          } catch {
            return val;
          }
        }
        return val;
      },
      z.object({
        name: z.string(),
      })
    );

    const strict = ensureStrict(schema);

    // Preprocess should still parse JSON string input
    const result = strict.safeParse('{"name":"hello"}');
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.name).toBe("hello");
    }

    // Strict should still reject extra fields
    const strictFail = strict.safeParse('{"name":"hello","extra":true}');
    expect(strictFail.success).toBe(false);
  });

  // ── ZodDiscriminatedUnion ────────────────────────────────────────────

  it("applies .strict() to objects inside discriminated unions", () => {
    const schema = z.discriminatedUnion("type", [
      z.object({ type: z.literal("a"), val: z.string() }),
      z.object({ type: z.literal("b"), val: z.number() }),
    ]);
    const strict = ensureStrict(schema);

    // Extra field should be rejected
    const result = strict.safeParse({ type: "a", val: "ok", extra: 1 });
    expect(result.success).toBe(false);

    // Valid data passes
    const ok = strict.safeParse({ type: "a", val: "ok" });
    expect(ok.success).toBe(true);
  });

  // ── ZodTuple ─────────────────────────────────────────────────────────

  it("applies .strict() to objects inside tuples", () => {
    const schema = z.object({
      data: z.tuple([
        z.object({ id: z.string() }),
        z.object({ val: z.number() }),
      ]),
    });
    const strict = ensureStrict(schema);

    // Extra field in tuple element should be rejected
    const result = strict.safeParse({
      data: [{ id: "abc", extra: true }, { val: 42 }],
    });
    expect(result.success).toBe(false);

    // Valid data passes
    const ok = strict.safeParse({
      data: [{ id: "abc" }, { val: 42 }],
    });
    expect(ok.success).toBe(true);
  });

  it("applies .strict() to tuple rest schema", () => {
    const schema = z.object({
      items: z.tuple([z.object({ id: z.string() })]).rest(z.object({ val: z.number() })),
    });
    const strict = ensureStrict(schema);

    // Extra field in rest element should be rejected
    const result = strict.safeParse({
      items: [{ id: "first" }, { val: 1, extra: true }],
    });
    expect(result.success).toBe(false);

    // Valid data passes
    const ok = strict.safeParse({
      items: [{ id: "first" }, { val: 1 }],
    });
    expect(ok.success).toBe(true);
  });

  // ── ZodBranded ───────────────────────────────────────────────────────

  it("applies .strict() to objects inside branded types", () => {
    const schema = z.object({
      data: z.object({ id: z.string() }).brand<"MyBrand">(),
    });
    const strict = ensureStrict(schema);

    // Extra field should be rejected (strict propagates through brand)
    const result = strict.safeParse({ data: { id: "abc", extra: true } });
    expect(result.success).toBe(false);

    // Valid data passes
    const ok = strict.safeParse({ data: { id: "abc" } });
    expect(ok.success).toBe(true);
  });

  it("applies .strict() to nested objects inside .refine()", () => {
    const schema = z
      .object({
        items: z.array(
          z.object({
            id: z.string(),
            meta: z.object({ tag: z.string() }),
          })
        ),
      })
      .refine((data) => data.items.length > 0, {
        message: "At least one item required",
      });

    const strict = ensureStrict(schema);

    // Refinement works
    const emptyFail = strict.safeParse({ items: [] });
    expect(emptyFail.success).toBe(false);

    // Nested strict works
    const nestedFail = strict.safeParse({
      items: [{ id: "a", meta: { tag: "x", extra: true } }],
    });
    expect(nestedFail.success).toBe(false);

    // Valid data passes
    const ok = strict.safeParse({
      items: [{ id: "a", meta: { tag: "x" } }],
    });
    expect(ok.success).toBe(true);
  });
});
