/**
 * Fixed-window rate limiter, in memory.
 *
 * On Vercel this is per serverless instance, so it is a speed bump rather than
 * a guarantee — enough to stop the embedded form being used as a scan amplifier
 * by one browser tab. Put Upstash (or any shared store) behind this interface
 * before advertising the service widely.
 */

import { config } from './config';

interface Window {
  count: number;
  resetAt: number;
}

const windows = new Map<string, Window>();

/** Keep the map from growing without bound on a long-lived instance. */
function sweep(now: number): void {
  if (windows.size < 1000) return;
  for (const [key, window] of windows) {
    if (window.resetAt <= now) windows.delete(key);
  }
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;
  retryAfterSeconds: number;
}

export function checkRateLimit(key: string): RateLimitResult {
  if (!config.rateLimit.enabled) {
    return { allowed: true, remaining: config.rateLimit.max, resetAt: 0, retryAfterSeconds: 0 };
  }

  const now = Date.now();
  sweep(now);

  const existing = windows.get(key);
  if (!existing || existing.resetAt <= now) {
    const resetAt = now + config.rateLimit.windowMs;
    windows.set(key, { count: 1, resetAt });
    return {
      allowed: true,
      remaining: config.rateLimit.max - 1,
      resetAt,
      retryAfterSeconds: 0,
    };
  }

  existing.count += 1;
  const allowed = existing.count <= config.rateLimit.max;
  return {
    allowed,
    remaining: Math.max(0, config.rateLimit.max - existing.count),
    resetAt: existing.resetAt,
    retryAfterSeconds: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)),
  };
}

/**
 * Best-effort client identity. Vercel sets x-forwarded-for; the leftmost entry
 * is the client, the rest are proxies.
 *
 * With no proxy header at all every caller collapses into one "unknown"
 * bucket. That is only reachable on direct access (a deployment behind Vercel
 * always sets the header), and rate limiting is disabled outside production
 * anyway — but it is why the fallback must never be the common path.
 */
export function clientKey(headers: Headers): string {
  const forwarded = headers.get('x-forwarded-for');
  if (forwarded) {
    const first = forwarded.split(',')[0]?.trim();
    if (first) return first;
  }
  return headers.get('x-real-ip') ?? headers.get('cf-connecting-ip') ?? 'unknown';
}

/** Exposed for tests. */
export function resetRateLimits(): void {
  windows.clear();
}
