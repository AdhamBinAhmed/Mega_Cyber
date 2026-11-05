/**
 * Rate limiting. The regression this guards against: the default limit fired
 * after 8 scans in 10 minutes, and a direct localhost request carries no
 * x-forwarded-for, so every local caller shared one bucket. Anyone testing the
 * scanner locked themselves out of their own tool within a minute, and the UI
 * showed it as a generic error.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import { checkRateLimit, clientKey, resetRateLimits } from '../ratelimit';

afterEach(() => {
  resetRateLimits();
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('checkRateLimit', () => {
  it('does not throttle outside production', () => {
    // Tests run with NODE_ENV=test, so this is the development path.
    for (let i = 0; i < 50; i += 1) {
      expect(checkRateLimit('same-key').allowed, `call ${i + 1}`).toBe(true);
    }
  });

  it('throttles in production once the window is exhausted', async () => {
    vi.resetModules();
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('RATE_LIMIT_MAX', '3');

    const { checkRateLimit: limited } = await import('../ratelimit');
    expect(limited('ip-a').allowed).toBe(true);
    expect(limited('ip-a').allowed).toBe(true);
    expect(limited('ip-a').allowed).toBe(true);

    const blocked = limited('ip-a');
    expect(blocked.allowed).toBe(false);
    // The UI needs a real number to count down from.
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);

    // Buckets are per client.
    expect(limited('ip-b').allowed).toBe(true);
  });

  it('can be switched off in production with RATE_LIMIT_MAX=0', async () => {
    vi.resetModules();
    vi.stubEnv('NODE_ENV', 'production');
    vi.stubEnv('RATE_LIMIT_MAX', '0');

    const { checkRateLimit: unlimited } = await import('../ratelimit');
    for (let i = 0; i < 20; i += 1) {
      expect(unlimited('ip-c').allowed).toBe(true);
    }
  });
});

describe('clientKey', () => {
  it('takes the leftmost x-forwarded-for entry', () => {
    const headers = new Headers({ 'x-forwarded-for': '203.0.113.9, 70.41.3.18, 150.172.238.178' });
    expect(clientKey(headers)).toBe('203.0.113.9');
  });

  it('falls back through the other proxy headers', () => {
    expect(clientKey(new Headers({ 'x-real-ip': '198.51.100.7' }))).toBe('198.51.100.7');
    expect(clientKey(new Headers({ 'cf-connecting-ip': '198.51.100.8' }))).toBe('198.51.100.8');
  });

  it('collapses to one bucket with no proxy headers at all', () => {
    // This is the localhost case that caused the lockout. It is acceptable
    // only because throttling is disabled outside production.
    expect(clientKey(new Headers())).toBe('unknown');
  });
});
