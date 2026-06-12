/**
 * @file Decoy data generator and honeypot response builder.
 *
 * The honeypot is the core of the "silent defense" pattern:
 * detected attackers always receive a convincing 200 OK with
 * synthetic data — never a 403 or 429 that would signal detection.
 *
 * Extracted from §4 and §5 of the original src/index.ts.
 *
 * v1.6 adds:
 *   - Custom violation messages (violationMessages config)
 */
import { NextRequest, NextResponse } from "next/server";
// ── Decoy data generator ───────────────────────────────────────────
/** @internal */
export function generateDecoyResponse(
  _req: NextRequest
): Record<string, unknown> {
  const id = crypto.randomUUID();
  const pastTs = new Date(
    Date.now() - Math.floor(Math.random() * 7_200_000)
  ).toISOString();
  const slot = Math.floor(Math.random() * 4);
  // Template A: Generic resource/data endpoint
  if (slot === 0) {
    return {
      success: true,
      requestId: crypto.randomUUID(),
      timestamp: pastTs,
      data: {
        id,
        status: "active",
        metadata: {
          version: `${Math.floor(Math.random() * 3) + 1}.${Math.floor(Math.random() * 9)}.0`,
          region: ["us-east-1", "eu-west-1", "ap-southeast-1"][
            Math.floor(Math.random() * 3)
          ],
          latencyMs: parseFloat((Math.random() * 80 + 15).toFixed(2)),
        },
      },
    };
  }
  // Template B: Auth/token endpoint
  if (slot === 1) {
    return {
      success: true,
      accessToken: btoa(
        `${crypto.randomUUID()}:${Date.now()}:${crypto.randomUUID()}`
      ),
      tokenType: "Bearer",
      expiresIn: 3600,
      scope: "read:self",
      issuedAt: pastTs,
    };
  }
  // Template D: Analytics/dashboard endpoint (slot 3)
  if (slot === 3) {
    const metricCount = Math.floor(Math.random() * 4) + 4;
    const metrics = Array.from({ length: metricCount }, (_, i) => ({
      id: crypto.randomUUID(),
      name: [
        "active_users",
        "api_requests",
        "error_rate",
        "avg_latency",
        "throughput",
        "concurrent_sessions",
        "cache_hit_ratio",
        "cpu_utilization",
      ][i % 8],
      value: parseFloat((Math.random() * 1000).toFixed(2)),
      unit: ["count", "req/s", "%", "ms", "req/s", "count", "%", "%"][i % 8],
      trend: ["up", "down", "stable"][Math.floor(Math.random() * 3)],
      timestamp: new Date(
        Date.now() - Math.floor(Math.random() * 3_600_000)
      ).toISOString(),
    }));
    return {
      success: true,
      requestId: crypto.randomUUID(),
      dashboard: {
        period: {
          start: new Date(Date.now() - 86_400_000).toISOString(),
          end: new Date().toISOString(),
        },
        metrics,
        summary: {
          totalRequests: Math.floor(Math.random() * 1_000_000) + 100_000,
          avgResponseTime: parseFloat((Math.random() * 200 + 30).toFixed(2)),
          errorBudgetRemaining: parseFloat((Math.random() * 100).toFixed(1)),
        },
      },
    };
  }
  // Template C: Paginated list endpoint (default / slot 2)
  const count = Math.floor(Math.random() * 7) + 3;
  return {
    success: true,
    items: Array.from({ length: count }, (_, i) => ({
      id: crypto.randomUUID(),
      rank: i + 1,
      createdAt: new Date(Date.now() - i * 86_400_000).toISOString(),
      score: parseFloat((Math.random() * 100).toFixed(4)),
      label: `entry_${Math.floor(Math.random() * 90_000) + 10_000}`,
    })),
    pagination: {
      total: Math.floor(Math.random() * 300) + count,
      page: 1,
      pageSize: 20,
      hasNext: true,
    },
  };
}
// ── Honeypot response builder ─────────────────────────────────────
/** @internal */
export function serveHoneypot(
  req: NextRequest,
  decoyFn: (r: NextRequest) => Record<string, unknown>,
  ip: string,
  score: number,
  violations: string[],
  debug: boolean,
  violationMessages?: Partial<
    Record<string, (violation: string) => Record<string, unknown>>
  >
): NextResponse {
  if (debug) {
    console.warn(
      `[hc:honeypot] ip=${ip} score=${score}/100 violations=[${violations.join(" | ")}]`
    );
  }
  let body = decoyFn(req);
  // Apply custom violation message handler for the primary violation
  if (violationMessages && violations.length > 0) {
            const primaryViolation = violations[0] as string;
    const violationType = primaryViolation.split("(")[0] ?? primaryViolation;
    const customHandler = violationMessages[violationType]
      ?? violationMessages[primaryViolation];
    if (customHandler) {
      body = { ...customHandler(primaryViolation), ...body };
    }
  }
  const fakeLatency = (Math.random() * 120 + 30).toFixed(2);
  const res = NextResponse.json(body, { status: 200 });
  res.headers.set("x-request-id", crypto.randomUUID());
  res.headers.set("x-processing-time", `${fakeLatency}ms`);
  res.headers.set("cache-control", "no-store");
  // Remove any header that might hint at the honeypot infrastructure
  res.headers.delete("x-powered-by");
  res.headers.delete("server");
  return res;
}
