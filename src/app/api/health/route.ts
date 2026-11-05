import { NextResponse } from 'next/server';

import { SCANNER_NAME, SCANNER_VERSION, config } from '@/lib/config';
import { SCHEMA_VERSION } from '@/lib/types';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export function GET() {
  return NextResponse.json({
    ok: true,
    scanner: SCANNER_NAME,
    version: SCANNER_VERSION,
    schemaVersion: SCHEMA_VERSION,
    passive: true,
    sslLabs: { enabled: config.sslLabs.enabled, api: config.sslLabs.version },
    tlsLocalProbe: config.tlsLocalProbe,
    // Surfaced because a silent 429 is indistinguishable from a broken scanner.
    rateLimit: {
      enabled: config.rateLimit.enabled,
      max: config.rateLimit.max,
      windowSeconds: Math.round(config.rateLimit.windowMs / 1000),
    },
    allowPrivateTargets: config.allowPrivateTargets,
  });
}
