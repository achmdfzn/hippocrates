/**
 * Shared test helpers for hippocrates test suite.
 *
 * Provides mock implementations of NextRequest, NextResponse, and Redis
 * that are sufficient to exercise the entire library surface.
 *
 * NOTE: TypeScript type errors from vitest globals (vi, describe, it, expect)
 * in these test files are expected — they only resolve when running under
 * vitest (globals: true). The source code (src/index.ts) typechecks clean.
 */

import { vi } from "vitest";
import type { RedisClient } from "../index";

// ── Mock Redis client ────────────────────────────────────────────────

export function createMockRedis(): {
  client: RedisClient;
  store: Map<string, string>;
} {
  const store = new Map<string, string>();

  const client: RedisClient = {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    set: vi.fn(
      async (
        key: string,
        value: string | number,
        _options?: { ex?: number }
      ) => {
        store.set(key, String(value));
      }
    ),
    lpush: vi.fn(async (key: string, ...values: string[]) => {
      const existing = store.get(key);
      const list = existing ? JSON.parse(existing) : [];
      list.unshift(...values);
      store.set(key, JSON.stringify(list));
      return list.length;
    }),
    ltrim: vi.fn(async (key: string, start: number, stop: number) => {
      const existing = store.get(key);
      if (existing) {
        const list = JSON.parse(existing);
        store.set(key, JSON.stringify(list.slice(start, stop + 1)));
      }
    }),
    lrange: vi.fn(async (key: string, _start: number, _stop: number) => {
      const existing = store.get(key);
      return existing ? JSON.parse(existing) : [];
    }),
    expire: vi.fn(async (_key: string, _seconds: number) => {}),
  };

  return { client, store };
}

// ── Mock NextRequest ─────────────────────────────────────────────────

export interface MockRequestInit {
  method?: string;
  url?: string;
  body?: string | null;
  headers?: Record<string, string>;
  ip?: string;
}

export function createMockRequest(
  init: MockRequestInit = {}
): NextRequest {
  const {
    method = "POST",
    url = "http://localhost:3000/api/data",
    body = '{"userId":"550e8400-e29b-41d4-a716-446655440000","action":"read"}',
    headers: extraHeaders = {},
    ip,
  } = init;

  const headersMap = new Map<string, string>(
    Object.entries({
      "content-type": "application/json",
      "accept": "application/json",
      "accept-language": "en-US,en;q=0.9",
      "user-agent": "Mozilla/5.0 (test-agent)",
      ...(ip ? { "x-forwarded-for": ip } : {}),
      ...extraHeaders,
    })
  );

  let bodyConsumed = false;

  return {
    method,
    url,
    headers: {
      get: (name: string) => headersMap.get(name.toLowerCase()) ?? null,
      forEach: (
        cb: (value: string, key: string) => void
      ) => headersMap.forEach((v, k) => cb(v, k)),
      delete: (name: string) => headersMap.delete(name.toLowerCase()),
      set: (name: string, value: string) =>
        headersMap.set(name.toLowerCase(), value),
    },
    text: async () => {
      if (bodyConsumed) {
        throw new Error("Body already consumed");
      }
      bodyConsumed = true;
      return body ?? "";
    },
    json: async () => {
      if (bodyConsumed) {
        throw new Error("Body already consumed");
      }
      bodyConsumed = true;
      return body ? JSON.parse(body) : {};
    },
  } as unknown as NextRequest;
}

// ── Mock NextResponse ────────────────────────────────────────────────

export interface MockResponseSnapshot {
  status: number;
  body: unknown;
  headers: Record<string, string>;
}

export function createMockNextResponse(): {
  NextResponse: typeof NextResponse;
  snapshots: MockResponseSnapshot[];
} {
  const snapshots: MockResponseSnapshot[] = [];

  const mockJson = vi.fn(
    (body: unknown, init?: { status?: number; headers?: Record<string, string> }) => {
      const headers: Record<string, string> = {};
      const snapshot: MockResponseSnapshot = {
        status: init?.status ?? 200,
        body,
        headers,
      };
      snapshots.push(snapshot);

      return {
        status: init?.status ?? 200,
        headers: {
          get: (name: string) => headers[name.toLowerCase()] ?? null,
          set: (name: string, value: string) => {
            headers[name.toLowerCase()] = value;
          },
          delete: (name: string) => {
            delete headers[name.toLowerCase()];
          },
          forEach: (cb: (value: string, key: string) => void) => {
            Object.entries(headers).forEach(([k, v]) => cb(v, k));
          },
        },
        json: async () => body,
      };
    }
  );

  return {
    NextResponse: { json: mockJson } as unknown as typeof NextResponse,
    snapshots,
  };
}

// ── Zod schema helpers ───────────────────────────────────────────────

import { z } from "zod";

export const TestSchema = z
  .object({
    userId: z.string().uuid(),
    action: z.enum(["read", "write"]),
  })
  .strict();
