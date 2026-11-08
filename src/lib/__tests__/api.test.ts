/**
 * API surface leakage.
 *
 * The expensive mistakes in this check are both directions of wrong:
 * reporting a Supabase anon key as a critical leak (it is published on
 * purpose) teaches clients to ignore the report, and staying quiet about a
 * service_role key in the same shape misses the worst finding the scanner can
 * produce. So the JWT tests pin the classification, not just the detection.
 *
 * The token payloads below are built and signed with nothing — the signature
 * segment is filler, because the scanner never verifies it.
 */

import { describe, expect, it } from 'vitest';

import { analyseApiSurface, classifyHost, describeJwt } from '../checks/api';
import { runContentCheck } from '../checks/content';
import { API_PATHS } from '../data/api-paths';
import { EXPOSURE_PATHS } from '../data/exposure-paths';
import type { RawResponse } from '../http';

const BASE = new URL('https://target.test/');
const NOW = Date.UTC(2026, 0, 1);

function b64url(value: object): string {
  return Buffer.from(JSON.stringify(value))
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** A JWT with the given claims and a filler signature. */
function jwt(payload: Record<string, unknown>, header: Record<string, unknown> = { alg: 'HS256', typ: 'JWT' }): string {
  return `${b64url(header)}.${b64url(payload)}.c2lnbmF0dXJlLWZpbGxlcg`;
}

const SECONDS = 1000;
const nowSec = Math.floor(NOW / SECONDS);

function run(html: string, headers: Record<string, string> = {}, base = BASE) {
  return analyseApiSurface(html, base, headers, NOW);
}

function ids(html: string, headers: Record<string, string> = {}): string[] {
  return run(html, headers).findings.map((finding) => finding.id);
}

function finding(html: string, id: string, headers: Record<string, string> = {}) {
  return run(html, headers).findings.find((entry) => entry.id === id);
}

/* ------------------------------ host classing ----------------------------- */

describe('classifyHost', () => {
  it('recognises hosts that should not be publicly reachable', () => {
    expect(classifyHost('localhost')).toBe('internal');
    expect(classifyHost('api.service.internal')).toBe('internal');
    expect(classifyHost('db.corp')).toBe('internal');
    expect(classifyHost('127.0.0.1')).toBe('internal');
    expect(classifyHost('10.0.4.17')).toBe('internal');
    expect(classifyHost('192.168.1.10')).toBe('internal');
  });

  it('separates non-production hosts from production ones', () => {
    expect(classifyHost('staging.target.test')).toBe('non-production');
    expect(classifyHost('uat-api.target.test')).toBe('non-production');
    expect(classifyHost('api.target.test')).toBe('public');
    expect(classifyHost('93.184.216.34')).toBe('public');
  });

  it('does not mistake a production host for staging on a substring', () => {
    // "devices" starts with "dev" but is not a dev environment.
    expect(classifyHost('devices.target.test')).toBe('public');
    expect(classifyHost('teston.target.test')).toBe('public');
  });
});

/* --------------------------------- CORS ----------------------------------- */

describe('CORS policy', () => {
  it('flags a wildcard combined with credentials', () => {
    const entry = finding('<p>hi</p>', 'api.cors.wildcard-with-credentials', {
      'access-control-allow-origin': '*',
      'access-control-allow-credentials': 'true',
    });
    expect(entry?.severity).toBe('medium');
    expect(entry?.status).toBe('fail');
  });

  it('flags the null origin', () => {
    expect(
      finding('<p>hi</p>', 'api.cors.null-origin', {
        'access-control-allow-origin': 'null',
      })?.severity,
    ).toBe('medium');
  });

  it('treats a bare wildcard on a public page as information, not a fault', () => {
    const entry = finding('<p>hi</p>', 'api.cors.wildcard', {
      'access-control-allow-origin': '*',
    });
    expect(entry?.severity).toBe('info');
    expect(entry?.scoreImpact).toBe(0);
    expect(entry?.detail).toContain('only sees the page it fetched');
  });

  it('says nothing when no CORS headers are present', () => {
    expect(ids('<p>hi</p>').filter((id) => id.startsWith('api.cors'))).toHaveLength(0);
  });

  it('records the raw policy in the data payload', () => {
    const { data } = run('<p>hi</p>', {
      'access-control-allow-origin': 'https://app.target.test',
      'access-control-allow-credentials': 'TRUE',
      'access-control-allow-methods': 'GET,POST',
    });
    expect(data.cors.allowOrigin).toBe('https://app.target.test');
    expect(data.cors.allowCredentials).toBe(true);
    expect(data.cors.allowMethods).toBe('GET,POST');
  });
});

/* --------------------------- credentials in URLs -------------------------- */

describe('credentials in URLs', () => {
  it('flags a token in a query string and masks it', () => {
    const secret = 'a1b2c3d4e5f6g7h8i9j0klmnop';
    const entry = finding(
      `<img src="https://api.target.test/v1/track?api_key=${secret}">`,
      'api.credentials-in-url',
    );
    expect(entry?.severity).toBe('high');
    expect(entry?.evidence).not.toContain(secret);
    expect(entry?.evidence).toContain('api_key=');
  });

  it('finds credentials in URLs passed to fetch()', () => {
    expect(
      ids('<script>fetch("/api/v1/me?access_token=zzzzyyyyxxxxwwwwvvvv");</script>'),
    ).toContain('api.credentials-in-url');
  });

  it('ignores placeholders and ordinary parameters', () => {
    expect(ids('<img src="https://api.target.test/v1/x?api_key=YOUR_API_KEY_HERE">')).not.toContain(
      'api.credentials-in-url',
    );
    expect(ids('<img src="https://api.target.test/v1/x?api_key=${apiKey}">')).not.toContain(
      'api.credentials-in-url',
    );
    expect(ids('<a href="https://api.target.test/v1/search?query=something">x</a>')).not.toContain(
      'api.credentials-in-url',
    );
  });

  it('ignores a short value that cannot be a credential', () => {
    expect(ids('<img src="https://api.target.test/v1/x?key=ab12">')).not.toContain(
      'api.credentials-in-url',
    );
  });
});

/* ------------------------------ internal hosts ---------------------------- */

describe('internal and metadata endpoints', () => {
  it('flags localhost and private-network API references', () => {
    const entry = finding(
      '<script>fetch("http://localhost:8080/api/v1/orders");' +
        'fetch("http://10.0.0.5/internal/api/sync");</script>',
      'api.internal-endpoint',
    );
    expect(entry?.severity).toBe('medium');
    expect(entry?.evidence).toContain('localhost:8080');
    expect(entry?.evidence).toContain('10.0.0.5');
  });

  it('flags a staging host as non-production', () => {
    const { data } = run('<script>fetch("https://staging-api.target.test/api/v1/me");</script>');
    expect(data.internalEndpoints).toContain('https://staging-api.target.test/api/v1/me');
  });

  it('flags a cloud metadata reference as high severity', () => {
    const entry = finding(
      '<script>var meta = "http://169.254.169.254/latest/meta-data/";</script>',
      'api.cloud-metadata-reference',
    );
    expect(entry?.severity).toBe('high');
  });

  it('does not count the site\'s own public API as internal', () => {
    const { data } = run('<script>fetch("https://api.target.test/v1/me");</script>');
    expect(data.internalEndpoints).toHaveLength(0);
    expect(data.endpoints.map((endpoint) => endpoint.url)).toContain(
      'https://api.target.test/v1/me',
    );
  });
});

/* ---------------------------------- JWTs ---------------------------------- */

describe('describeJwt', () => {
  it('reads the claims without verifying the signature', () => {
    const token = jwt({ role: 'authenticated', iss: 'supabase', exp: nowSec + 3600, iat: nowSec });
    const described = describeJwt(token, 4, NOW)!;
    expect(described.alg).toBe('HS256');
    expect(described.role).toBe('authenticated');
    expect(described.issuer).toBe('supabase');
    expect(described.expired).toBe(false);
    expect(described.longLived).toBe(false);
    expect(described.line).toBe(4);
    expect(described.masked).not.toBe(token);
  });

  it('marks a token with no expiry as long-lived', () => {
    expect(describeJwt(jwt({ sub: 'svc' }), 1, NOW)!.longLived).toBe(true);
  });

  it('marks an elapsed expiry as expired', () => {
    const described = describeJwt(jwt({ exp: nowSec - 60, iat: nowSec - 3600 }), 1, NOW)!;
    expect(described.expired).toBe(true);
  });

  it('returns null for a value that merely looks like a token', () => {
    expect(describeJwt('eyJub3QtanNvbg.notjson.sig', 1, NOW)).toBeNull();
  });
});

describe('JWT classification', () => {
  it('reports a service_role key as critical', () => {
    const token = jwt({ role: 'service_role', iss: 'supabase', iat: nowSec });
    const entry = finding(`<script>var k="${token}";</script>`, 'api.jwt.privileged');
    expect(entry?.severity).toBe('critical');
    expect(entry?.title).toContain('service_role');
    expect(entry?.evidence).not.toContain(token);
    expect(entry?.detail).toContain('no meaningful expiry');
  });

  it('reports an anon key as information, not a leak', () => {
    const token = jwt({ role: 'anon', iss: 'supabase', exp: nowSec + 10 * 365 * 24 * 3600 });
    const found = ids(`<script>var k="${token}";</script>`);
    expect(found).toContain('api.jwt.public-anon');
    expect(found).not.toContain('api.jwt.privileged');
    expect(found).not.toContain('api.jwt.long-lived');
  });

  it('grades a long-lived bearer token above an expiring one', () => {
    const long = jwt({ sub: 'user-1', iat: nowSec });
    const short = jwt({ sub: 'user-1', iat: nowSec, exp: nowSec + 900 });
    expect(finding(`<script>var a="${long}";</script>`, 'api.jwt.long-lived')?.severity).toBe(
      'medium',
    );
    expect(finding(`<script>var a="${short}";</script>`, 'api.jwt.live')?.severity).toBe('low');
  });

  it('treats an expired token as housekeeping', () => {
    const token = jwt({ sub: 'user-1', iat: nowSec - 7200, exp: nowSec - 3600 });
    const entry = finding(`<script>var a="${token}";</script>`, 'api.jwt.expired');
    expect(entry?.severity).toBe('info');
    expect(entry?.scoreImpact).toBe(0);
  });

  it('reports each distinct token once, however often it appears', () => {
    const token = jwt({ role: 'service_role', iat: nowSec });
    const html = `<script>var a="${token}";var b="${token}";</script>`;
    expect(run(html).data.jwts).toHaveLength(1);
  });
});

/* ------------------------- hard-coded Authorization ----------------------- */

describe('hard-coded Authorization headers', () => {
  it('flags a bearer credential compiled into the page', () => {
    const entry = finding(
      '<script>fetch("/api/v1/me", { headers: { Authorization: "Bearer sk-live-4f8a9c2e7b1d" } });</script>',
      'api.hardcoded-authorization',
    );
    expect(entry?.severity).toBe('high');
    expect(entry?.evidence).not.toContain('sk-live-4f8a9c2e7b1d');
  });

  it('flags basic auth too, and counts what it found', () => {
    const { data } = run(
      '<script>h["authorization"] = "Basic YWRtaW46c3VwZXJzZWNyZXQ=";</script>',
    );
    expect(data.hardcodedAuthHeaders).toBe(1);
  });

  it('does not fire on a header name mentioned without a value', () => {
    expect(
      ids('<script>var allowed = ["authorization", "content-type"];</script>'),
    ).not.toContain('api.hardcoded-authorization');
  });
});

/* ------------------------------- inventory -------------------------------- */

describe('endpoint inventory', () => {
  it('lists API paths and marks third-party ones', () => {
    const entry = finding(
      '<script>fetch("https://api.target.test/v1/me");' +
        'fetch("https://api.stripe.com/v1/charges");' +
        'fetch("https://cdn.target.test/graphql");</script>',
      'api.endpoint-inventory',
    );
    expect(entry?.severity).toBe('info');
    expect(entry?.evidence).toContain('https://api.stripe.com/v1/charges');
    expect(entry?.evidence).toContain('(third party)');
    expect(entry?.evidence).toContain('graphql');
  });

  it('ignores ordinary page URLs that are not API endpoints', () => {
    const { data } = run('<a href="https://target.test/about">about</a><img src="/logo.png">');
    expect(data.endpoints).toHaveLength(0);
  });

  it('passes a page with no API leakage at all', () => {
    const found = ids('<p>Just a page</p>');
    expect(found).toContain('api.none');
  });

  it('withholds the pass finding once something real is wrong', () => {
    const token = jwt({ role: 'service_role', iat: nowSec });
    expect(ids(`<script>var k="${token}";</script>`)).not.toContain('api.none');
  });
});

/* ----------------------------- exposure paths ----------------------------- */

describe('API documentation paths', () => {
  it('joins the exposure sweep without duplicating a path', () => {
    const paths = EXPOSURE_PATHS.map((entry) => entry.path);
    expect(new Set(paths).size).toBe(paths.length);
    for (const entry of API_PATHS) expect(paths).toContain(entry.path);
  });

  it('requires a content signature on every entry, so a soft 404 cannot match', () => {
    for (const entry of API_PATHS) {
      expect(entry.signatures, entry.path).toBeDefined();
      expect(entry.signatures!.length).toBeGreaterThan(0);
    }
  });

  it('matches a real OpenAPI document but not an HTML shell', () => {
    const spec = API_PATHS.find((entry) => entry.path === '/openapi.json')!;
    const matches = (body: string) => spec.signatures!.some((re) => re.test(body));
    expect(matches('{"openapi":"3.0.3","paths":{"/users":{}}}')).toBe(true);
    expect(matches('<!doctype html><html><body>Not found</body></html>')).toBe(false);
  });

  it('recognises an actuator env dump and carries a rotation recommendation', () => {
    const entry = API_PATHS.find((path) => path.path === '/actuator/env')!;
    expect(entry.severity).toBe('critical');
    expect(entry.signatures!.some((re) => re.test('{"activeProfiles":["prod"]}'))).toBe(true);
    expect(entry.recommendation).toMatch(/rotate/i);
  });

  it('matches Prometheus output only on its exposition format', () => {
    const entry = API_PATHS.find((path) => path.path === '/metrics')!;
    const matches = (body: string) => entry.signatures!.some((re) => re.test(body));
    expect(matches('# HELP http_requests_total Total requests\n# TYPE http_requests_total counter')).toBe(
      true,
    );
    expect(matches('{"metrics":[]}')).toBe(false);
  });

  it('keeps the whole sweep inside the default request budget', () => {
    // Baseline probe plus every path, with headroom for the page fetch,
    // redirects and the HTTPS-redirect test.
    expect(EXPOSURE_PATHS.length + 1).toBeLessThanOrEqual(30);
  });
});

/* --------------------------- section integration -------------------------- */

function page(
  html: string,
  headers: Record<string, string> = {},
  url = 'https://target.test/',
): RawResponse {
  return {
    url,
    status: 200,
    statusText: 'OK',
    headers,
    rawHeaders: Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, [v]])),
    body: html,
    bodyBytes: html.length,
    truncated: false,
    remoteAddress: '203.0.113.9',
    tls: null,
    durationMs: 10,
  };
}

describe('content section integration', () => {
  it('carries API findings, data and summary into the content section', () => {
    const token = jwt({ role: 'service_role', iat: nowSec });
    const section = runContentCheck(page(`<script>var k="${token}";</script>`));
    expect(section.findings.some((entry) => entry.id === 'api.jwt.privileged')).toBe(true);
    expect(section.data.apiSurface.jwts[0]!.privileged).toBe(true);
    expect(section.summary).toContain('API credential');
    expect(section.score).toBeLessThan(50);
  });

  it('reads CORS off the response headers the scanner already has', () => {
    const section = runContentCheck(
      page('<p>hi</p>', {
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
      }),
    );
    expect(section.data.apiSurface.cors.allowCredentials).toBe(true);
    expect(
      section.findings.some((entry) => entry.id === 'api.cors.wildcard-with-credentials'),
    ).toBe(true);
  });

  it('never serialises a raw token into the report', () => {
    const token = jwt({ role: 'service_role', iat: nowSec });
    const section = runContentCheck(page(`<script>var k="${token}";</script>`));
    expect(JSON.stringify(section)).not.toContain(token);
  });

  it('leaves a clean page with the pass finding and full marks for this group', () => {
    const section = runContentCheck(page('<p>Just a page</p>'));
    expect(section.findings.some((entry) => entry.id === 'api.none')).toBe(true);
    expect(section.findings.some((entry) => entry.id.startsWith('api.') && entry.scoreImpact < 0)).toBe(
      false,
    );
  });
});
