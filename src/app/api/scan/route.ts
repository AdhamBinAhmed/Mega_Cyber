/**
 * POST /api/scan   { url: string, consent: true }
 * GET  /api/scan?url=...&consent=1
 *
 * Returns a complete ScanReport, or an ApiError with a 4xx status.
 */

import { NextResponse } from 'next/server';

import type { ApiError } from '@/lib/types';
import { ScanError, runScan } from '@/lib/scan';
import { checkRateLimit, clientKey } from '@/lib/ratelimit';
import { parseTarget } from '@/lib/target';
import { config } from '@/lib/config';

// node:dns and node:tls are not available on the edge runtime.
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export const maxDuration = 60;

const STATUS_FOR: Record<ApiError['code'], number> = {
  invalid_url: 400,
  blocked_target: 400,
  consent_required: 403,
  rate_limited: 429,
  unreachable: 502,
  internal: 500,
};

function fail(
  code: ApiError['code'],
  error: string,
  detail?: string,
  extra?: { headers?: HeadersInit; retryAfterSeconds?: number },
) {
  const body: ApiError = {
    error,
    code,
    ...(detail ? { detail } : {}),
    ...(extra?.retryAfterSeconds ? { retryAfterSeconds: extra.retryAfterSeconds } : {}),
  };
  return NextResponse.json(body, { status: STATUS_FOR[code], headers: extra?.headers });
}

async function handle(url: string | null, consent: boolean, headers: Headers) {
  if (!url) {
    return fail('invalid_url', 'Provide a URL to scan.');
  }

  if (!consent) {
    return fail(
      'consent_required',
      'Confirm you own this site or have permission to scan it.',
      'Send consent: true with the request.',
    );
  }

  // Validate before metering, so a typo or a blocked target does not cost the
  // visitor one of their scans. runScan re-parses; it is pure and cheap.
  const parsed = parseTarget(url);
  if (!parsed.ok) {
    return fail(parsed.code, parsed.message);
  }

  const limit = checkRateLimit(clientKey(headers));
  if (!limit.allowed) {
    return fail(
      'rate_limited',
      `Scan limit reached — ${config.rateLimit.max} scans per ${Math.round(config.rateLimit.windowMs / 60000)} minutes.`,
      `Try again in ${limit.retryAfterSeconds} second${limit.retryAfterSeconds === 1 ? '' : 's'}.`,
      {
        headers: { 'retry-after': String(limit.retryAfterSeconds) },
        retryAfterSeconds: limit.retryAfterSeconds,
      },
    );
  }

  try {
    const report = await runScan(url);
    return NextResponse.json(report, {
      headers: {
        'cache-control': 'no-store',
        'x-ratelimit-remaining': String(limit.remaining),
      },
    });
  } catch (err) {
    if (err instanceof ScanError) {
      return fail(err.code, err.message, err.detail);
    }
    console.error('[scan] unexpected failure', err);
    return fail('internal', 'The scan failed unexpectedly.', (err as Error)?.message);
  }
}

export async function POST(request: Request) {
  let payload: { url?: unknown; consent?: unknown };
  try {
    payload = (await request.json()) as typeof payload;
  } catch {
    return fail('invalid_url', 'Request body must be JSON.');
  }

  const url = typeof payload.url === 'string' ? payload.url : null;
  return handle(url, payload.consent === true, request.headers);
}

export async function GET(request: Request) {
  const params = new URL(request.url).searchParams;
  const consent = ['1', 'true', 'yes'].includes((params.get('consent') ?? '').toLowerCase());
  return handle(params.get('url'), consent, request.headers);
}
