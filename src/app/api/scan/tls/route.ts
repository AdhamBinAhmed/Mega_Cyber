/**
 * GET /api/scan/tls?host=example.com
 *
 * Re-runs the TLS section on its own. The dashboard polls this after an
 * initial scan returns a pending SSL Labs result, then merges the fresh
 * section into the report it already has and re-grades locally.
 */

import { NextResponse } from 'next/server';

import type { ApiError } from '@/lib/types';
import { runTlsCheck } from '@/lib/checks/tls';
import { parseTarget, resolveTarget } from '@/lib/target';
import { checkRateLimit, clientKey } from '@/lib/ratelimit';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

export async function GET(request: Request) {
  const params = new URL(request.url).searchParams;
  const host = params.get('host');

  if (!host) {
    const body: ApiError = { error: 'Provide a host to re-check.', code: 'invalid_url' };
    return NextResponse.json(body, { status: 400 });
  }

  const parsed = parseTarget(host);
  if (!parsed.ok) {
    const body: ApiError = { error: parsed.message, code: parsed.code };
    return NextResponse.json(body, { status: 400 });
  }

  // Polling is cheap but not free; keep it under the same budget.
  const limit = checkRateLimit(`tls:${clientKey(request.headers)}`);
  if (!limit.allowed) {
    const body: ApiError = {
      error: 'Polling too quickly.',
      code: 'rate_limited',
      detail: `Try again in ${limit.retryAfterSeconds} seconds.`,
      retryAfterSeconds: limit.retryAfterSeconds,
    };
    return NextResponse.json(body, {
      status: 429,
      headers: { 'retry-after': String(limit.retryAfterSeconds) },
    });
  }

  const resolution = await resolveTarget(parsed.hostname);
  if (!resolution.ok) {
    const body: ApiError = { error: resolution.message, code: resolution.code };
    return NextResponse.json(body, { status: resolution.code === 'unreachable' ? 502 : 400 });
  }

  try {
    const port = parsed.url.protocol === 'https:' ? Number(parsed.url.port || 443) : 443;
    const section = await runTlsCheck(parsed.hostname, port, { sslLabsTimeoutMs: 20_000 });
    return NextResponse.json(section, { headers: { 'cache-control': 'no-store' } });
  } catch (err) {
    const body: ApiError = {
      error: 'The TLS re-check failed.',
      code: 'internal',
      detail: (err as Error)?.message,
    };
    return NextResponse.json(body, { status: 500 });
  }
}
