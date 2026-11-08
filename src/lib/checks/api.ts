/**
 * API surface leakage.
 *
 * Credential patterns in `data/secrets.ts` answer "is a key in this page?".
 * This module answers the questions that come after it: which API does the
 * page talk to, is any of it internal, does the page hand a token over in a
 * query string, what does an embedded JWT actually grant, and does the
 * response advertise a CORS policy that lets any site read it.
 *
 * Two things keep it honest:
 *
 *   - JWTs are decoded rather than pattern-matched. A Supabase anon key and a
 *     service_role key are the same shape and nearly opposite in consequence,
 *     so reporting both as "a JWT, severity medium" is useless to the reader.
 *     Only the claims are read; the signature is never verified and the token
 *     is masked everywhere it is reported.
 *   - the CORS headers observed belong to the HTML response, not to the API.
 *     The finding says so, because a permissive policy on a public page is
 *     normal and the same policy on a credentialed endpoint is a breach.
 */

import type {
  ApiEndpointObservation,
  ApiSurfaceData,
  Finding,
  JwtObservation,
  Severity,
} from '../types';
import { isPublicIp } from '../ip';
import { maskValue } from '../redact';
import { registrableDomain } from '../target';

/* -------------------------------------------------------------------------- */
/* URL harvesting                                                             */
/* -------------------------------------------------------------------------- */

/**
 * Absolute URLs anywhere in the document, plus the relative paths passed to
 * fetch()/axios/XHR. Quoted strings are the only reliable boundary available
 * without a parser, and minified bundles keep their string literals.
 */
function harvestUrls(html: string): string[] {
  const urls = new Set<string>();

  for (const match of html.matchAll(/https?:\/\/[^\s"'`<>()\\]{4,300}/gi)) {
    urls.add(match[0].replace(/[.,;:]+$/, ''));
  }

  const callRe =
    /(?:fetch|axios(?:\.\w+)?|\.open|XMLHttpRequest\(\)\.open)\s*\(\s*["'`]([^"'`]{2,300})["'`]/gi;
  for (const match of html.matchAll(callRe)) {
    urls.add(match[1]!);
  }

  return [...urls];
}

const INTERNAL_SUFFIX = /\.(?:local|internal|lan|corp|intranet|home|localdomain)$/i;
const NON_PROD_LABEL = /^(?:staging|stage|dev|develop|uat|qa|test|preprod|pre-prod|sandbox)\b/i;

const CLOUD_METADATA = /^(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)$/i;

const STORAGE_HOST =
  /(?:\.s3[.-][a-z0-9-]*\.amazonaws\.com|^s3[.-][a-z0-9-]*\.amazonaws\.com|\.blob\.core\.windows\.net|\.storage\.googleapis\.com|^storage\.googleapis\.com|\.firebaseio\.com|\.r2\.cloudflarestorage\.com)$/i;

/** Does this hostname name something that should not be reachable publicly? */
export function classifyHost(hostname: string): 'internal' | 'non-production' | 'public' {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost')) return 'internal';
  if (INTERNAL_SUFFIX.test(host)) return 'internal';
  // Bare IP literals: anything not publicly routable is internal.
  if (/^[\d.]+$/.test(host) || host.includes(':')) {
    return isPublicIp(host) ? 'public' : 'internal';
  }
  if (NON_PROD_LABEL.test(host.split('.')[0] ?? '')) return 'non-production';
  return 'public';
}

/** Query-string keys whose value is a credential rather than a parameter. */
const CREDENTIAL_PARAM =
  /^(?:api[_-]?key|apikey|key|access[_-]?token|auth[_-]?token|id[_-]?token|token|secret|client[_-]?secret|password|passwd|pwd|sig|signature|session|sessionid|jwt|bearer)$/i;

/** Values that are obviously placeholders rather than live credentials. */
const PLACEHOLDER =
  /^(?:your[_-]?|my[_-]?|xxx|null|undefined|true|false|none|test|demo|example|placeholder|\{\{?|%[0-9a-z_]+%|\$\{)/i;

/* -------------------------------------------------------------------------- */
/* JWT decoding                                                               */
/* -------------------------------------------------------------------------- */

const JWT_RE = /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,})\b/g;

function decodeSegment(segment: string): Record<string, unknown> | null {
  try {
    const padded = segment.replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    const parsed: unknown = JSON.parse(json);
    return parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** Role-ish claims that mean this token bypasses the usual authorisation. */
const PRIVILEGED_CLAIM = /\b(?:service[_-]?role|superuser|sudo|root|admin(?:istrator)?)\b/i;

const YEAR_SECONDS = 365 * 24 * 60 * 60;

function str(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Read the claims of a JWT found in page source. The signature is never
 * verified — this reports what the token says about itself, which is what
 * decides whether its presence in a public page matters.
 */
export function describeJwt(token: string, line: number, now = Date.now()): JwtObservation | null {
  const [headerPart, payloadPart] = token.split('.');
  if (!headerPart || !payloadPart) return null;

  const header = decodeSegment(headerPart);
  const payload = decodeSegment(payloadPart);
  if (!header || !payload) return null;

  const exp = typeof payload.exp === 'number' ? payload.exp : null;
  const iat = typeof payload.iat === 'number' ? payload.iat : null;
  const role =
    str(payload.role) ??
    str(payload.roles) ??
    (Array.isArray(payload.roles) ? str(payload.roles[0]) : null) ??
    str(payload.scope) ??
    str(payload.permissions) ??
    null;

  const lifetime = exp !== null && iat !== null ? exp - iat : null;

  return {
    masked: maskValue(token),
    alg: str(header.alg),
    role,
    issuer: str(payload.iss),
    subject: str(payload.sub),
    expiresAt: exp !== null ? new Date(exp * 1000).toISOString() : null,
    expired: exp !== null ? exp * 1000 < now : null,
    longLived: exp === null || (lifetime !== null && lifetime > YEAR_SECONDS),
    privileged: role !== null && PRIVILEGED_CLAIM.test(role),
    /** Supabase and friends publish an "anon" key in the page on purpose. */
    publicByDesign: role !== null && /^(?:anon|anonymous|public|guest)$/i.test(role),
    line,
  };
}

/* -------------------------------------------------------------------------- */
/* CORS                                                                       */
/* -------------------------------------------------------------------------- */

const REF_CORS =
  'https://developer.mozilla.org/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials';
const REF_API = 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/';
const REF_JWT = 'https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html';

/* -------------------------------------------------------------------------- */
/* Analysis                                                                   */
/* -------------------------------------------------------------------------- */

export function analyseApiSurface(
  html: string,
  base: URL,
  headers: Record<string, string>,
  now = Date.now(),
): { findings: Finding[]; data: ApiSurfaceData } {
  const findings: Finding[] = [];

  const lineAt = (index: number): number => {
    let line = 1;
    for (let i = 0; i < index && i < html.length; i += 1) if (html[i] === '\n') line += 1;
    return line;
  };

  /* --------------------------------- CORS -------------------------------- */
  const cors: ApiSurfaceData['cors'] = {
    allowOrigin: headers['access-control-allow-origin'] ?? null,
    allowCredentials: /^true$/i.test(headers['access-control-allow-credentials'] ?? ''),
    allowMethods: headers['access-control-allow-methods'] ?? null,
    allowHeaders: headers['access-control-allow-headers'] ?? null,
    exposeHeaders: headers['access-control-expose-headers'] ?? null,
  };
  const allowOrigin = cors.allowOrigin?.trim() ?? null;

  if (allowOrigin === '*' && cors.allowCredentials) {
    findings.push({
      id: 'api.cors.wildcard-with-credentials',
      title: 'CORS allows any origin and credentialed requests at once',
      severity: 'medium',
      status: 'fail',
      detail:
        'Access-Control-Allow-Origin is "*" while Access-Control-Allow-Credentials is "true". Browsers refuse that combination outright, so the cross-origin calls this was meant to enable are broken — and the usual fix applied under pressure is to reflect whatever Origin the caller sends, which turns it into a real "any website can read this user\'s data" hole.',
      evidence: `access-control-allow-origin: ${allowOrigin}\naccess-control-allow-credentials: true`,
      recommendation:
        'Keep credentials on and replace the wildcard with an explicit allowlist of origins, compared exactly — never by substring, and never by echoing the request Origin back.',
      scoreImpact: -15,
      references: [REF_CORS],
    });
  } else if (allowOrigin === 'null') {
    findings.push({
      id: 'api.cors.null-origin',
      title: 'CORS allows the "null" origin',
      severity: 'medium',
      status: 'fail',
      detail:
        'Any sandboxed iframe, data: URL or local file sends Origin: null, so allowing it hands access to content an attacker can host anywhere, including inside a page on your own site.',
      evidence: `access-control-allow-origin: null`,
      recommendation: 'Remove "null" from the allowlist and name the origins that need access.',
      scoreImpact: -12,
      references: [REF_CORS],
    });
  } else if (allowOrigin === '*') {
    findings.push({
      id: 'api.cors.wildcard',
      title: 'Responses are readable by any origin',
      severity: 'info',
      status: 'info',
      detail:
        'Access-Control-Allow-Origin is "*" on this response. For public HTML that is harmless. It is worth checking the same header is not set on endpoints that return per-user data, because there it lets any site read those responses on behalf of a logged-in visitor — the scanner only sees the page it fetched, not your API.',
      evidence: `access-control-allow-origin: *`,
      scoreImpact: 0,
      references: [REF_CORS],
    });
  } else if (allowOrigin && allowOrigin === base.origin && cors.allowCredentials) {
    // The scanner sends no Origin header, so a policy naming exactly our own
    // origin is static configuration. Worth noting, not worth penalising.
    findings.push({
      id: 'api.cors.reflected-candidate',
      title: 'CORS names a single origin and allows credentials',
      severity: 'info',
      status: 'info',
      detail:
        'The response allows credentialed cross-origin reads from one named origin. The scanner sends no Origin header of its own, so it cannot tell a fixed allowlist from a server echoing the caller back. If it is echoing, any site can read authenticated responses.',
      evidence: `access-control-allow-origin: ${allowOrigin}\naccess-control-allow-credentials: true`,
      recommendation:
        'Confirm the header is produced from an allowlist rather than from the request Origin.',
      scoreImpact: 0,
      references: [REF_CORS],
    });
  }

  /* ------------------------------ endpoints ------------------------------ */
  const urls = harvestUrls(html);
  const endpoints: ApiEndpointObservation[] = [];
  const internalEndpoints: string[] = [];
  const metadataEndpoints: string[] = [];
  const credentialBearingUrls: string[] = [];
  const seenEndpoints = new Set<string>();

  for (const raw of urls) {
    let url: URL;
    try {
      url = new URL(raw, base);
    } catch {
      continue;
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;

    /* credentials carried in the query string */
    for (const [param, value] of url.searchParams) {
      if (!CREDENTIAL_PARAM.test(param)) continue;
      if (value.length < 8 || PLACEHOLDER.test(value)) continue;
      const masked = `${url.origin}${url.pathname}?${param}=${maskValue(value)}`;
      if (!credentialBearingUrls.includes(masked)) credentialBearingUrls.push(masked);
    }

    const hostClass = classifyHost(url.hostname);
    if (CLOUD_METADATA.test(url.hostname)) {
      if (!metadataEndpoints.includes(url.origin)) metadataEndpoints.push(url.origin);
      continue;
    }
    if (hostClass !== 'public') {
      const shown = `${url.origin}${url.pathname}`;
      if (!internalEndpoints.includes(shown)) internalEndpoints.push(shown);
      continue;
    }

    const kind: ApiEndpointObservation['kind'] = STORAGE_HOST.test(url.hostname)
      ? 'storage'
      : /\/graphql\b|\/gql\b/i.test(url.pathname)
        ? 'graphql'
        : /(?:^|\/)(?:api|rest|v\d+|graphql|wp-json|rpc)(?:\/|$)/i.test(url.pathname)
          ? 'rest'
          : 'other';
    if (kind === 'other') continue;

    const key = `${url.origin}${url.pathname}`;
    if (seenEndpoints.has(key)) continue;
    seenEndpoints.add(key);
    endpoints.push({
      url: key,
      kind,
      crossOrigin: url.origin !== base.origin,
      thirdParty: registrableDomain(url.hostname) !== registrableDomain(base.hostname),
    });
  }

  if (credentialBearingUrls.length > 0) {
    findings.push({
      id: 'api.credentials-in-url',
      title: `${credentialBearingUrls.length} API URL${credentialBearingUrls.length === 1 ? '' : 's'} carry a credential in the query string`,
      severity: 'high',
      status: 'fail',
      detail:
        'A token in a query string is copied into places designed to be kept: browser history, the Referer header sent to every third party on the page, proxy and CDN access logs, and any analytics product recording full URLs. It is also cached. Treat a key that has travelled this way as disclosed.',
      evidence: credentialBearingUrls.slice(0, 5).join('\n'),
      recommendation:
        'Send the credential in an Authorization header instead, rotate the value that has been exposed this way, and set Referrer-Policy so the URL does not leak onward in the meantime.',
      scoreImpact: -25,
      references: [REF_API],
    });
  }

  if (metadataEndpoints.length > 0) {
    findings.push({
      id: 'api.cloud-metadata-reference',
      title: 'Page references a cloud instance metadata endpoint',
      severity: 'high',
      status: 'fail',
      detail:
        'The link-local metadata service hands out instance credentials to anything that can reach it from inside the host. A reference to it in client-side code is either dead debug code that documents your hosting, or a proxy that will fetch URLs on request — which is the SSRF that turns into stolen cloud credentials.',
      evidence: metadataEndpoints.join('\n'),
      recommendation:
        'Remove the reference, enforce IMDSv2 (or the equivalent) on the instance, and make sure no server-side endpoint fetches a URL supplied by the client.',
      scoreImpact: -25,
      references: ['https://owasp.org/www-project-top-ten/2021/A10_2021-Server-Side_Request_Forgery'],
    });
  }

  if (internalEndpoints.length > 0) {
    findings.push({
      id: 'api.internal-endpoint',
      title: `${internalEndpoints.length} internal or non-production endpoint${internalEndpoints.length === 1 ? '' : 's'} referenced in page source`,
      severity: 'medium',
      status: 'warn',
      detail:
        'These hostnames are not meant to be reachable from the public internet: localhost, a private address, an internal suffix, or a staging environment. In a public page they map out your internal estate for free, and name the hosts worth aiming an SSRF or a VPN foothold at. Staging copies also tend to carry production data with none of the hardening.',
      evidence: internalEndpoints.slice(0, 6).join('\n'),
      recommendation:
        'Replace them with the public endpoint at build time, and keep environment-specific URLs in configuration rather than in shipped source.',
      scoreImpact: -12,
      references: [REF_API],
    });
  }

  /* -------------------------------- JWTs --------------------------------- */
  const jwts: JwtObservation[] = [];
  const seenTokens = new Set<string>();
  for (const match of html.matchAll(JWT_RE)) {
    const token = match[1]!;
    if (seenTokens.has(token)) continue;
    seenTokens.add(token);
    const described = describeJwt(token, lineAt(match.index ?? 0), now);
    if (described) jwts.push(described);
    if (jwts.length >= 6) break;
  }

  const privileged = jwts.filter((jwt) => jwt.privileged);
  const liveTokens = jwts.filter(
    (jwt) => !jwt.privileged && !jwt.publicByDesign && jwt.expired !== true,
  );
  const expiredTokens = jwts.filter((jwt) => jwt.expired === true && !jwt.publicByDesign);

  for (const jwt of privileged) {
    findings.push({
      id: 'api.jwt.privileged',
      title: `Privileged JWT in page source (role "${jwt.role}")`,
      severity: 'critical',
      status: 'fail',
      detail:
        `A token whose own claims say it carries the "${jwt.role}" role is served in the public page. Keys like this are built to bypass row-level security and per-user authorisation, so possession of it is usually equivalent to full read and write access to the data behind the API. Every visitor and every crawler already has it.` +
        (jwt.longLived ? ' It also has no meaningful expiry, so it does not stop working on its own.' : ''),
      evidence: [
        `line ~${jwt.line}: ${jwt.masked}`,
        jwt.issuer ? `iss: ${jwt.issuer}` : null,
        jwt.expiresAt ? `exp: ${jwt.expiresAt}` : 'exp: none',
        `alg: ${jwt.alg ?? 'unknown'}`,
      ]
        .filter(Boolean)
        .join('\n'),
      recommendation:
        'Revoke and rotate the key now, then audit the API logs for use of it. Serve calls that need this role from your backend, and ship only the public anon key to the browser.',
      scoreImpact: -60,
      references: [REF_JWT],
    });
  }

  for (const jwt of liveTokens) {
    const unbounded = jwt.longLived;
    findings.push({
      id: unbounded ? 'api.jwt.long-lived' : 'api.jwt.live',
      title: unbounded ? 'Long-lived JWT in page source' : 'Unexpired JWT in page source',
      severity: unbounded ? 'medium' : 'low',
      status: 'warn',
      detail: unbounded
        ? 'This token either has no expiry or is valid for more than a year, and it is readable by anyone who views the page. A bearer token that never expires cannot be contained after it leaks — revocation is the only remedy, and it has to be possible first.'
        : 'An unexpired bearer token is readable in the page. If it represents a session or a user, anyone who copies it acts as that principal until it expires.',
      evidence: [
        `line ~${jwt.line}: ${jwt.masked}`,
        jwt.role ? `role/scope: ${jwt.role}` : null,
        jwt.expiresAt ? `exp: ${jwt.expiresAt}` : 'exp: none',
      ]
        .filter(Boolean)
        .join('\n'),
      recommendation:
        'Confirm what the token grants. If it is not a deliberately public key, rotate it, give it a short lifetime, and keep it out of the document — a httpOnly cookie or a server-side session avoids shipping it at all.',
      scoreImpact: unbounded ? -15 : -8,
      references: [REF_JWT],
    });
  }

  for (const jwt of expiredTokens) {
    findings.push({
      id: 'api.jwt.expired',
      title: 'Expired JWT left in page source',
      severity: 'info',
      status: 'info',
      detail:
        'The token has expired, so it grants nothing today. It still shows the claim structure and issuer of your tokens, and its presence suggests tokens get baked into the build.',
      evidence: `line ~${jwt.line}: ${jwt.masked} (exp: ${jwt.expiresAt})`,
      recommendation: 'Remove it from the template or build output.',
      scoreImpact: 0,
    });
  }

  for (const jwt of jwts.filter((entry) => entry.publicByDesign)) {
    findings.push({
      id: 'api.jwt.public-anon',
      title: `Public anon key present (role "${jwt.role}")`,
      severity: 'info',
      status: 'info',
      detail:
        'This token claims an anonymous role, which is the key such platforms expect you to publish. It is not a leak. What it grants depends entirely on your access rules, so the question is whether those rules are restrictive — the key itself is doing its job.',
      evidence: `line ~${jwt.line}: ${jwt.masked}`,
      recommendation:
        'Verify your row-level security or access rules deny anonymous reads and writes on everything that is not meant to be public.',
      scoreImpact: 0,
    });
  }

  /* --------------------- hard-coded Authorization -------------------------- */
  const authHeaderMatches = [
    ...html.matchAll(
      // Covers object literals, header maps and setRequestHeader calls:
      // Authorization: "Bearer …", h["authorization"] = "Basic …", and
      // setRequestHeader("Authorization", "Bearer …").
      /["']?authorization["']?\s*\]?\s*(?:[:=]|,)\s*["'`]\s*(?:bearer|basic|token)\s+([A-Za-z0-9._~+/=-]{8,})["'`]/gi,
    ),
  ];
  const hardcodedAuthHeaders = authHeaderMatches.length;

  if (hardcodedAuthHeaders > 0) {
    findings.push({
      id: 'api.hardcoded-authorization',
      title: `${hardcodedAuthHeaders} hard-coded Authorization header${hardcodedAuthHeaders === 1 ? '' : 's'} in page source`,
      severity: 'high',
      status: 'fail',
      detail:
        'Client-side code is sending a fixed Authorization value, which means the credential ships to every visitor. Whatever authentication the API performs, it is performing it against a secret that is public.',
      evidence: authHeaderMatches
        .slice(0, 3)
        .map((match) => `line ~${lineAt(match.index ?? 0)}: fixed bearer/basic value ${maskValue(match[1]!)}`)
        .join('\n'),
      recommendation:
        'Rotate the credential and move the call behind your own backend, which can hold the secret and apply per-user authorisation before forwarding.',
      scoreImpact: -35,
      references: [REF_API],
    });
  }

  /* ---------------------------- inventory -------------------------------- */
  if (endpoints.length > 0) {
    const thirdParty = endpoints.filter((endpoint) => endpoint.thirdParty);
    findings.push({
      id: 'api.endpoint-inventory',
      title: `${endpoints.length} API endpoint${endpoints.length === 1 ? '' : 's'} referenced from the page`,
      severity: 'info',
      status: 'info',
      detail:
        `Distinct API paths visible in page source${thirdParty.length > 0 ? `, ${thirdParty.length} of them on a third-party domain` : ''}. This is the attack surface a reader of your HTML can see without any tooling, and it is worth comparing against the API inventory you think you have.`,
      evidence: endpoints
        .slice(0, 10)
        .map((endpoint) => `${endpoint.kind}: ${endpoint.url}${endpoint.thirdParty ? ' (third party)' : ''}`)
        .join('\n'),
      scoreImpact: 0,
      references: [REF_API],
    });
  }

  const worst = (): Severity | null => {
    const order: Severity[] = ['critical', 'high', 'medium', 'low'];
    for (const severity of order) {
      if (findings.some((finding) => finding.severity === severity)) return severity;
    }
    return null;
  };

  if (worst() === null) {
    findings.push({
      id: 'api.none',
      title: 'No API credential or internal-endpoint leaks in page source',
      severity: 'pass',
      status: 'pass',
      detail:
        'No credential in a query string, no hard-coded Authorization header, no privileged or long-lived token, and no internal, staging or metadata endpoint referenced in the document.',
      scoreImpact: 2,
    });
  }

  const data: ApiSurfaceData = {
    cors,
    endpoints: endpoints.slice(0, 25),
    internalEndpoints: internalEndpoints.slice(0, 15),
    metadataEndpoints,
    credentialBearingUrls: credentialBearingUrls.slice(0, 10),
    hardcodedAuthHeaders,
    jwts,
  };

  return { findings, data };
}
