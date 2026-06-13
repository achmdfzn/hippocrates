/**
 * @file Example Next.js App Router route using hippocrates.
 *
 * Usage:
 *   curl -X POST http://localhost:3000/api/data \
 *     -H "Content-Type: application/json" \
 *     -d '{"userId":"550e8400-e29b-41d4-a716-446655440000","action":"read"}'
 *
 * Body stream note:
 *   hippocrates calls `req.text()` internally to validate the body against
 *   the Zod schema. The handler receives a *new* Request with only the
 *   validated, sanitized body. Calling `await req.json()` inside the
 *   handler works because the middleware re-serializes the validated data
 *   into the forwarded request.
 *
 *   Two internal headers are injected on the forwarded request:
 *     - x-hippocrates-score : threat score at time of passing
 *     - x-hippocrates-clean : "1" (signals the request passed all checks)
 */

import { NextRequest, NextResponse } from "next/server";
import { Redis } from "@upstash/redis";
import { withHippocrates, z } from "hippocrates-middleware";

/* ------------------------------------------------------------------ */
/*  Redis client — configure via environment variables                */
/* ------------------------------------------------------------------ */
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

/* ------------------------------------------------------------------ */
/*  Zod schema — .strict() is mandatory for Zero-Trust validation     */
/*  Any extra field in the request body triggers L5 → instant honeypot */
/* ------------------------------------------------------------------ */
export const DataSchema = z
  .object({
    userId: z.string().uuid(),
    action: z.enum(["read", "write", "delete"]),
    payload: z
      .object({
        documentId: z.string().uuid().optional(),
        content: z.string().max(10_000).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export type DataInput = z.infer<typeof DataSchema>;

/* ------------------------------------------------------------------ */
/*  Route handler — receive pre-validated body via req.json()         */
/*  Guaranteed at this point: schema matched, no obfuscation,         */
/*  threat score is below threshold.                                  */
/* ------------------------------------------------------------------ */
async function handler(req: NextRequest): Promise<NextResponse> {
  // req.body is a new body stream created by the middleware —
  // safe to call .json() even though middleware already parsed it.
  const body: DataInput = await req.json();

  // Audit headers injected by hippocrates
  const score = req.headers.get("x-hippocrates-score") ?? "0";
  const clean = req.headers.get("x-hippocrates-clean");

  console.log(
    `[example:handler] userId=${body.userId} action=${body.action} score=${score}`
  );

  return NextResponse.json({
    success: true,
    processed: {
      userId: body.userId,
      action: body.action,
      documentId: body.payload?.documentId ?? null,
      contentLength: body.payload?.content?.length ?? 0,
    },
    audit: {
      hippocratesScore: Number(score),
      hippocratesClean: clean === "1",
    },
  });
}

/* ------------------------------------------------------------------ */
/*  Export wrapped handler — Next.js App Router route convention      */
/* ------------------------------------------------------------------ */
export const POST = withHippocrates(handler, DataSchema, redis, {
  // Optional: tune per-endpoint sensitivity
  threatScoreThreshold: 65,
  debugMode: process.env.NODE_ENV !== "production",
});

// Also protect GET endpoints with velocity/timing layers (no body parsing)
export const GET = withHippocrates(
  async (req) => {
    const score = req.headers.get("x-hippocrates-score") ?? "0";
    return NextResponse.json({
      success: true,
      message: "Health check passed",
      score: Number(score),
    });
  },
  // GET has no body — pass a trivial schema; body validation is skipped
  // for GET/HEAD/OPTIONS inside the middleware.
  z.object({}).strict(),
  redis,
  { threatScoreThreshold: 65, debugMode: process.env.NODE_ENV !== "production" }
);
