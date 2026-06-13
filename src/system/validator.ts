/**
 * @file Zero-Trust Zod validation system.
 *
 * Provides:
 *   - validatePayload — Zod wrapper with vague error messages
 *   - ensureStrict    — Recursive .strict() for nested schemas
 *
 * Extracted from §6 of the original src/index.ts.
 */

import { z, ZodType, ZodError } from "zod";
import type { ValidationResult } from "../engine/types";

// ── Payload validator ─────────────────────────────────────────────

/**
 * Validates raw parsed JSON against the Zod schema.
 *
 * Error messages are INTENTIONALLY vague. Detailed errors expose
 * the schema structure — an attacker who sees "field 'userId' must
 * be a UUID" can infer the schema and craft payloads that survive
 * validation. We report only constraint count.
 */
export function validatePayload<T>(
  raw: unknown,
  schema: ZodType<T>
): ValidationResult<T> {
  try {
    return { ok: true, data: schema.parse(raw) };
  } catch (err) {
    if (err instanceof ZodError) {
      return {
        ok: false,
        error: `Validation failed (${err.issues.length} constraint${err.issues.length !== 1 ? "s" : ""})`,
        isSchemaViolation: true,
      };
    }
    return {
      ok: false,
      error: "Invalid request format",
      isSchemaViolation: false,
    };
  }
}

// ── Recursive .strict() enforcer ──────────────────────────────────

/**
 * Recursively applies `.strict()` to all nested ZodObject schemas.
 *
 * Zod's `.strict()` only affects the immediate object it's called on.
 * Nested objects within the shape remain in their default `strip` mode,
 * silently discarding extra fields at those levels.
 *
 * This function walks the schema tree and applies `.strict()` to every
 * ZodObject it finds, ensuring zero-extra-field enforcement at all depths.
 *
 * Handles: objects, arrays, unions, intersections, effects (refine/transform),
 * optional, nullable, records, defaults, readonly, discriminated unions,
 * tuples, and branded types.
 */
export function ensureStrict<T>(schema: ZodType<T>): ZodType<T> {
  const def = (schema as unknown as Record<string, unknown>)._def as Record<
    string,
    unknown
  >;
  const typeName = def.typeName as string;

  switch (typeName) {
    case "ZodObject": {
      const obj = schema as unknown as z.AnyZodObject;
      const shape: Record<string, z.ZodTypeAny> = {};
      for (const [key, fieldSchema] of Object.entries(obj.shape)) {
        shape[key] = ensureStrict(fieldSchema as z.ZodTypeAny);
      }
      return z.object(shape).strict() as unknown as ZodType<T>;
    }

    case "ZodArray": {
      const arr = schema as unknown as z.ZodArray<z.ZodTypeAny>;
      return z.array(ensureStrict(arr.element)) as unknown as ZodType<T>;
    }

    case "ZodEffects": {
      const innerSchema = def.schema as z.ZodTypeAny | undefined;
      if (!innerSchema) return schema;

      const strictInner = ensureStrict(innerSchema);
      const eff = def.effect as {
        type: string;
        refinement?: (...args: unknown[]) => unknown;
        transform?: (...args: unknown[]) => unknown;
      };

      if (eff.type === "refinement" && eff.refinement) {
        return strictInner._refinement(
          eff.refinement as z.RefinementEffect<T>["refinement"]
        ) as unknown as ZodType<T>;
      }
      if (eff.type === "transform" && eff.transform) {
        return strictInner.transform(eff.transform) as unknown as ZodType<T>;
      }
      if (eff.type === "preprocess" && eff.transform) {
        return z.preprocess(eff.transform, strictInner) as unknown as ZodType<T>;
      }

      return strictInner as unknown as ZodType<T>;
    }

    case "ZodOptional": {
      const inner = (
        schema as unknown as z.ZodOptional<z.ZodTypeAny>
      ).unwrap();
      return ensureStrict(inner).optional() as unknown as ZodType<T>;
    }

    case "ZodNullable": {
      const inner = (
        schema as unknown as z.ZodNullable<z.ZodTypeAny>
      ).unwrap();
      return ensureStrict(inner).nullable() as unknown as ZodType<T>;
    }

    case "ZodUnion": {
      const options = (def.options ?? []) as z.ZodTypeAny[];
      return z.union(
        options.map((o) => ensureStrict(o)) as [
          z.ZodTypeAny,
          z.ZodTypeAny,
          ...z.ZodTypeAny[],
        ]
      ) as unknown as ZodType<T>;
    }

    case "ZodIntersection": {
      return z.intersection(
        ensureStrict(def.left as z.ZodTypeAny),
        ensureStrict(def.right as z.ZodTypeAny)
      ) as unknown as ZodType<T>;
    }

    case "ZodRecord": {
      const rec = schema as unknown as z.ZodRecord;
      return z.record(
        ensureStrict(rec._def.valueType as z.ZodTypeAny)
      ) as unknown as ZodType<T>;
    }

    case "ZodDefault": {
      const inner = ensureStrict(def.innerType as z.ZodTypeAny);
      const dv = def.defaultValue as () => unknown;
      return inner.default(dv) as unknown as ZodType<T>;
    }

    case "ZodReadonly": {
      return ensureStrict(def.innerType as z.ZodTypeAny)
        .readonly() as unknown as ZodType<T>;
    }

    case "ZodDiscriminatedUnion": {
      const discriminator = def.discriminator as string;
      const opts = (def.options ?? []) as z.ZodTypeAny[];
      return z.discriminatedUnion(
        discriminator,
        opts.map((o) => ensureStrict(o)) as [
          z.ZodDiscriminatedUnionOption<string>,
          ...z.ZodDiscriminatedUnionOption<string>[],
        ]
      ) as unknown as ZodType<T>;
    }

    case "ZodTuple": {
      const tupleItems = def.items as z.ZodTypeAny[] | undefined;
      if (!tupleItems) return schema;
      const strictItems = tupleItems.map(
        (i) => ensureStrict(i)
      ) as unknown as [z.ZodTypeAny, ...z.ZodTypeAny[]];
      const rest = def.rest as z.ZodTypeAny | null;
      return (
        rest
          ? z.tuple(strictItems).rest(ensureStrict(rest))
          : z.tuple(strictItems)
      ) as unknown as ZodType<T>;
    }

    case "ZodBranded": {
      const inner = (
        schema as unknown as z.ZodBranded<z.ZodTypeAny, string>
      ).unwrap() as z.ZodTypeAny;
      return ensureStrict(inner).brand<string>() as unknown as ZodType<T>;
    }

    case "ZodMap": {
      const mapSchema = schema as unknown as z.ZodMap<z.ZodTypeAny, z.ZodTypeAny>;
      const valueType = mapSchema._def.valueType as z.ZodTypeAny;
      return z.map(z.unknown(), ensureStrict(valueType)) as unknown as ZodType<T>;
    }

    case "ZodSet": {
      const setSchema = schema as unknown as z.ZodSet<z.ZodTypeAny>;
      const valueType = setSchema._def.valueType as z.ZodTypeAny;
      return z.set(ensureStrict(valueType)) as unknown as ZodType<T>;
    }

    default:
      return schema;
  }
}
