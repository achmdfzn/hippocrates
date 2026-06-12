/**
 * @file IP address normalization utilities.
 *
 * Hippocrates uses IP addresses as Redis keys (`hc:s:{ip}`, `hc:t:{ip}`, etc.).
 * IPv6 addresses like `::1` (loopback) and `127.0.0.1` must map to the same key
 * for consistent threat scoring across network families.
 *
 * This module handles:
 *   - IPv4-mapped IPv6 → IPv4 extraction (`::ffff:192.168.1.1` → `192.168.1.1`)
 *   - IPv6 loopback normalization (`::1` → `127.0.0.1`)
 *   - IPv6 full normalization (lowercased, compressed)
 *   - Zone ID stripping (`fe80::1%eth0` → `fe80::1`)
 */

const IPV4_PATTERN = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
const IPV4_MAPPED_PREFIX = "::ffff:";
const IPV6_LOOPBACK = "::1";
const IPV6_LOOPBACK_EXPANDED = "0:0:0:0:0:0:0:1";

/**
 * Normalize an IP address string for consistent Redis key usage.
 *
 * Rules:
 * 1. IPv4 addresses are returned as-is (already canonical).
 * 2. IPv4-mapped IPv6 (`::ffff:x.x.x.x`) extracts the IPv4 portion.
 * 3. IPv6 loopback (`::1`) normalizes to `127.0.0.1`.
 * 4. Other IPv6 addresses are lowercased and zone IDs stripped.
 * 5. If the address cannot be parsed, it is returned as-is (fail-open).
 *
 * @param ip - Raw IP address string from request headers
 * @returns Normalized IP string suitable for use as a Redis key
 */
export function normalizeIp(ip: string | null): string {
  if (!ip || ip.trim().length === 0) {
    return "127.0.0.1";
  }

  const trimmed = ip.trim();

  if (IPV4_PATTERN.test(trimmed)) {
    return trimmed;
  }

  // Strip surrounding brackets: [::1] → ::1
  let cleaned = trimmed;
  if (cleaned.startsWith("[") && cleaned.endsWith("]")) {
    cleaned = cleaned.slice(1, -1);
  }

  // IPv4-mapped IPv6: ::ffff:192.168.1.1 → 192.168.1.1
  if (cleaned.toLowerCase().startsWith(IPV4_MAPPED_PREFIX)) {
    const extracted = cleaned.slice(IPV4_MAPPED_PREFIX.length);
    if (IPV4_PATTERN.test(extracted)) {
      return extracted;
    }
  }

  // IPv6 loopback normalization: ::1 or 0:0:0:0:0:0:0:1 → 127.0.0.1
  const lower = cleaned.toLowerCase();
  if (lower === IPV6_LOOPBACK || lower === IPV6_LOOPBACK_EXPANDED) {
    return "127.0.0.1";
  }

  // Strip zone ID (e.g., fe80::1%eth0 → fe80::1)
  const zoneIdx = lower.indexOf("%");
  const stripped = zoneIdx !== -1 ? lower.slice(0, zoneIdx) : lower;

  if (stripped.includes(":")) {
    const colonCount = (stripped.match(/:/g) ?? []).length;
    if (colonCount >= 2) {
      return stripped;
    }
  }

  return trimmed;
}

/**
 * Resolve the client IP address from a collection of request headers.
 *
 * Checks headers in order of specificity:
 *   1. `x-forwarded-for` (comma-separated, takes the first)
 *   2. `x-real-ip`
 *   3. `cf-connecting-ip` (Cloudflare)
 *   4. Falls back to `127.0.0.1`
 *
 * The result is normalized via {@link normalizeIp}.
 *
 * @param headers - A headers-like object with a `get(name)` method
 * @returns Normalized client IP string
 */
export function resolveClientIp(
  headers: { get(name: string): string | null }
): string {
  const raw =
    headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    headers.get("x-real-ip") ??
    headers.get("cf-connecting-ip") ??
    "127.0.0.1";

  return normalizeIp(raw);
}
