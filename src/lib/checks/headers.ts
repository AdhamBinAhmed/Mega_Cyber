/**
 * HTTP security header analysis.
 *
 * Grading follows the spirit of Mozilla Observatory: start at 100 and subtract
 * for each missing or weakened control, with small bonuses for configurations
 * that go beyond the baseline.
 */

import type {
  CookieObservation,
  Finding,
  HeadersData,
  SectionReport,
} from '../types';
import { buildSection, sortFindings } from '../scoring';
import { rawRequest, type RawResponse } from '../http';
import { config } from '../config';
import { describeError } from '../errors';
import type { RequestBudget } from '../budget';

const GRADED_HEADERS = [
  'content-security-policy',
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
] as const;

/** Header names whose mere presence tells an attacker what to target. */
const DISCLOSURE_HEADERS = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-generator',
  'x-drupal-dynamic-cache',
  'x-runtime',
  'x-php-version',
];

/** A Server header is only interesting when it carries a version number. */
const VERSION_IN_VALUE = /\d+\.\d+/;

const REF_OBSERVATORY = 'https://developer.mozilla.org/docs/Web/HTTP/Headers';

export function parseCsp(value: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0]!.toLowerCase();
    if (!map.has(name)) map.set(name, tokens.slice(1));
  }
  return map;
}

export function parseSetCookie(values: string[]): CookieObservation[] {
  return values.map((raw) => {
    const [pair, ...attrs] = raw.split(';');
    const name = (pair ?? '').split('=')[0]?.trim() ?? '(unnamed)';
    const flags = attrs.map((a) => a.trim().toLowerCase());
    const valueOf = (key: string) => {
      const found = flags.find((f) => f.startsWith(key + '='));
      return found ? (found.split('=')[1]?.trim() ?? null) : null;
    };
    const maxAgeRaw = valueOf('max-age');
    const maxAge = maxAgeRaw !== null ? Number(maxAgeRaw) : null;

    return {
      name,
      secure: flags.includes('secure'),
      httpOnly: flags.includes('httponly'),
      sameSite: valueOf('samesite'),
      domain: valueOf('domain'),
      prefix: name.startsWith('__Host-')
        ? ('__Host-' as const)
        : name.startsWith('__Secure-')
          ? ('__Secure-' as const)
          : null,
      maxAgeSeconds: maxAge !== null && Number.isFinite(maxAge) ? maxAge : null,
    };
  });
}

/** Parse the max-age from an HSTS header value. */
export function hstsMaxAge(value: string): number | null {
  const match = value.match(/max-age\s*=\s*"?(\d+)"?/i);
  if (!match?.[1]) return null;
  const parsed = Number(match[1]);
  return Number.isFinite(parsed) ? parsed : null;
}

const SIX_MONTHS = 15_552_000; // seconds

function analyseCsp(value: string | null, reportOnly: string | null, findings: Finding[]): boolean {
  if (!value) {
    if (reportOnly) {
      findings.push({
        id: 'headers.csp.report-only',
        title: 'Content-Security-Policy is report-only',
        severity: 'medium',
        status: 'warn',
        detail:
          'A Content-Security-Policy-Report-Only header is set, so violations are reported but nothing is actually blocked.',
        evidence: truncate(reportOnly),
        recommendation:
          'Once the reports are clean, promote the policy to the enforcing Content-Security-Policy header.',
        scoreImpact: -20,
        references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy'],
      });
      return false;
    }
    findings.push({
      id: 'headers.csp.missing',
      title: 'Content-Security-Policy is missing',
      severity: 'medium',
      status: 'fail',
      detail:
        'Without a CSP the browser will execute any script the page references, so a single injection flaw becomes full script execution in your users’ sessions.',
      recommendation:
        "Start with a reporting policy such as default-src 'self'; object-src 'none'; base-uri 'self', then tighten it until inline script is no longer needed.",
      scoreImpact: -30,
      references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy'],
    });
    return false;
  }

  const directives = parseCsp(value);
  const scriptSrc = directives.get('script-src') ?? directives.get('default-src') ?? [];
  const scriptSrcLower = scriptSrc.map((s) => s.toLowerCase());

  findings.push({
    id: 'headers.csp.present',
    title: 'Content-Security-Policy is set',
    severity: 'pass',
    status: 'pass',
    detail: `Policy defines ${directives.size} directive${directives.size === 1 ? '' : 's'}.`,
    evidence: truncate(value),
    scoreImpact: 0,
  });

  const hasNonceOrHash = scriptSrcLower.some(
    (src) => src.startsWith("'nonce-") || src.startsWith("'sha256-") || src.startsWith("'sha384-") || src.startsWith("'sha512-"),
  );
  const strictDynamic = scriptSrcLower.includes("'strict-dynamic'");

  if (scriptSrcLower.includes("'unsafe-inline'") && !strictDynamic) {
    findings.push({
      id: 'headers.csp.unsafe-inline',
      title: "CSP allows 'unsafe-inline' script",
      severity: 'medium',
      status: 'warn',
      detail:
        "script-src permits 'unsafe-inline', which lets injected inline script run. That removes most of the XSS protection a CSP is there to provide.",
      evidence: `script-src ${scriptSrc.join(' ')}`,
      recommendation:
        "Replace 'unsafe-inline' with per-request nonces, or hashes of the inline scripts you actually ship.",
      scoreImpact: -10,
    });
  }

  if (scriptSrcLower.includes("'unsafe-eval'")) {
    findings.push({
      id: 'headers.csp.unsafe-eval',
      title: "CSP allows 'unsafe-eval'",
      severity: 'low',
      status: 'warn',
      detail: "script-src permits 'unsafe-eval', keeping eval() and friends available to injected code.",
      evidence: `script-src ${scriptSrc.join(' ')}`,
      recommendation: "Drop 'unsafe-eval' and move any runtime-compiled templates to a build step.",
      scoreImpact: -5,
    });
  }

  if (scriptSrcLower.includes('*') || scriptSrcLower.includes('http:') || scriptSrcLower.includes('https:')) {
    findings.push({
      id: 'headers.csp.wildcard',
      title: 'CSP script source is effectively unrestricted',
      severity: 'medium',
      status: 'warn',
      detail: 'script-src includes a wildcard or bare scheme, so script may be loaded from any host.',
      evidence: `script-src ${scriptSrc.join(' ')}`,
      recommendation: 'List the specific origins you load script from.',
      scoreImpact: -10,
    });
  }

  if (scriptSrc.length === 0) {
    findings.push({
      id: 'headers.csp.no-script-src',
      title: 'CSP does not constrain script',
      severity: 'medium',
      status: 'warn',
      detail: 'Neither script-src nor default-src is defined, so the policy places no limit on script sources.',
      evidence: truncate(value),
      recommendation: "Add default-src 'self' as a floor, then a specific script-src.",
      scoreImpact: -15,
    });
  }

  if (hasNonceOrHash || strictDynamic) {
    findings.push({
      id: 'headers.csp.strict',
      title: 'CSP uses nonces, hashes or strict-dynamic',
      severity: 'pass',
      status: 'pass',
      detail: 'Script sources are pinned per-response rather than by host allow-list — the strongest common CSP pattern.',
      scoreImpact: 5,
    });
  }

  const objectSrc = directives.get('object-src');
  if (objectSrc?.map((s) => s.toLowerCase()).includes("'none'")) {
    findings.push({
      id: 'headers.csp.object-src-none',
      title: "CSP sets object-src 'none'",
      severity: 'pass',
      status: 'pass',
      detail: 'Legacy plugin content cannot be embedded.',
      scoreImpact: 2,
    });
  }

  if (directives.has('base-uri')) {
    findings.push({
      id: 'headers.csp.base-uri',
      title: 'CSP restricts base-uri',
      severity: 'pass',
      status: 'pass',
      detail: 'Injected <base> tags cannot redirect relative URLs to an attacker-controlled host.',
      scoreImpact: 2,
    });
  }

  const hasFrameAncestors = directives.has('frame-ancestors');
  if (hasFrameAncestors) {
    findings.push({
      id: 'headers.csp.frame-ancestors',
      title: 'CSP sets frame-ancestors',
      severity: 'pass',
      status: 'pass',
      detail: `Framing is controlled by CSP: frame-ancestors ${(directives.get('frame-ancestors') ?? []).join(' ')}`,
      scoreImpact: 3,
    });
  }

  return hasFrameAncestors;
}

function analyseHsts(value: string | null, isHttps: boolean, findings: Finding[]): void {
  if (!isHttps) {
    findings.push({
      id: 'headers.hsts.not-applicable',
      title: 'Strict-Transport-Security cannot apply over plain HTTP',
      severity: 'info',
      status: 'info',
      detail: 'HSTS is ignored by browsers when sent over an unencrypted connection.',
      recommendation: 'Serve the site over HTTPS first, then add HSTS.',
      scoreImpact: 0,
    });
    return;
  }

  if (!value) {
    findings.push({
      id: 'headers.hsts.missing',
      title: 'Strict-Transport-Security is missing',
      severity: 'medium',
      status: 'fail',
      detail:
        'Browsers will still try plain HTTP for this host, leaving the first request of every session open to interception and downgrade.',
      recommendation:
        'Send Strict-Transport-Security: max-age=31536000; includeSubDomains once you are confident every subdomain serves HTTPS.',
      scoreImpact: -25,
      references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security'],
    });
    return;
  }

  const maxAge = hstsMaxAge(value);
  const lower = value.toLowerCase();

  if (maxAge === null) {
    findings.push({
      id: 'headers.hsts.invalid',
      title: 'Strict-Transport-Security has no valid max-age',
      severity: 'medium',
      status: 'fail',
      detail: 'The header is present but max-age could not be parsed, so browsers will ignore it.',
      evidence: truncate(value),
      recommendation: 'Use the form max-age=31536000; includeSubDomains.',
      scoreImpact: -25,
    });
    return;
  }

  if (maxAge === 0) {
    findings.push({
      id: 'headers.hsts.disabled',
      title: 'Strict-Transport-Security is disabled (max-age=0)',
      severity: 'medium',
      status: 'fail',
      detail: 'max-age=0 actively tells browsers to forget the HTTPS requirement.',
      evidence: truncate(value),
      recommendation: 'Set a positive max-age, ideally 31536000 (one year).',
      scoreImpact: -25,
    });
    return;
  }

  if (maxAge < 86_400) {
    findings.push({
      id: 'headers.hsts.too-short',
      title: 'HSTS max-age is very short',
      severity: 'medium',
      status: 'warn',
      detail: `max-age is ${maxAge}s (under a day), so the protection lapses almost immediately.`,
      evidence: truncate(value),
      recommendation: 'Raise max-age to at least 15552000 (six months).',
      scoreImpact: -15,
    });
  } else if (maxAge < SIX_MONTHS) {
    findings.push({
      id: 'headers.hsts.short',
      title: 'HSTS max-age is below six months',
      severity: 'low',
      status: 'warn',
      detail: `max-age is ${maxAge}s. Preload lists and most guidance expect at least 15552000.`,
      evidence: truncate(value),
      recommendation: 'Raise max-age to 31536000 once you are confident in your HTTPS coverage.',
      scoreImpact: -10,
    });
  } else {
    findings.push({
      id: 'headers.hsts.present',
      title: 'Strict-Transport-Security is set',
      severity: 'pass',
      status: 'pass',
      detail: `max-age is ${maxAge}s.`,
      evidence: truncate(value),
      scoreImpact: 0,
    });
  }

  if (lower.includes('includesubdomains')) {
    findings.push({
      id: 'headers.hsts.subdomains',
      title: 'HSTS covers subdomains',
      severity: 'pass',
      status: 'pass',
      detail: 'includeSubDomains extends the HTTPS requirement to every subdomain.',
      scoreImpact: 3,
    });
  }
  if (lower.includes('preload')) {
    findings.push({
      id: 'headers.hsts.preload',
      title: 'HSTS requests preloading',
      severity: 'pass',
      status: 'pass',
      detail: 'The preload directive is present, so the host can ship in browser preload lists.',
      scoreImpact: 2,
    });
  }
}

function analyseXfo(value: string | null, cspCoversFraming: boolean, findings: Finding[]): void {
  if (!value) {
    if (cspCoversFraming) {
      findings.push({
        id: 'headers.xfo.superseded',
        title: 'X-Frame-Options absent but CSP frame-ancestors is set',
        severity: 'info',
        status: 'info',
        detail: 'Modern browsers honour frame-ancestors, which supersedes X-Frame-Options.',
        recommendation: 'Optionally add X-Frame-Options: DENY for very old browsers.',
        scoreImpact: 0,
      });
      return;
    }
    findings.push({
      id: 'headers.xfo.missing',
      title: 'X-Frame-Options is missing',
      severity: 'medium',
      status: 'fail',
      detail:
        'Nothing stops another site embedding these pages in an invisible frame and tricking users into clicking through them (clickjacking).',
      recommendation: "Send X-Frame-Options: DENY, or better, CSP frame-ancestors 'none'.",
      scoreImpact: -20,
      references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options'],
    });
    return;
  }

  const normalised = value.trim().toUpperCase();
  if (normalised === 'DENY' || normalised === 'SAMEORIGIN') {
    findings.push({
      id: 'headers.xfo.present',
      title: 'X-Frame-Options is set',
      severity: 'pass',
      status: 'pass',
      detail: `Framing policy is ${normalised}.`,
      evidence: value,
      scoreImpact: 0,
    });
    return;
  }

  if (normalised.startsWith('ALLOW-FROM')) {
    findings.push({
      id: 'headers.xfo.allow-from',
      title: 'X-Frame-Options uses the obsolete ALLOW-FROM',
      severity: 'medium',
      status: 'warn',
      detail: 'No current browser supports ALLOW-FROM, so this page is effectively unprotected.',
      evidence: value,
      recommendation: 'Use CSP frame-ancestors to allow specific origins.',
      scoreImpact: -15,
    });
    return;
  }

  findings.push({
    id: 'headers.xfo.invalid',
    title: 'X-Frame-Options value is not valid',
    severity: 'medium',
    status: 'warn',
    detail: 'Browsers ignore values other than DENY and SAMEORIGIN.',
    evidence: value,
    recommendation: 'Use DENY or SAMEORIGIN.',
    scoreImpact: -15,
  });
}

function analyseXcto(value: string | null, findings: Finding[]): void {
  if (!value) {
    findings.push({
      id: 'headers.xcto.missing',
      title: 'X-Content-Type-Options is missing',
      severity: 'medium',
      status: 'fail',
      detail:
        'Browsers may MIME-sniff responses, so a file served with the wrong Content-Type can be reinterpreted as script.',
      recommendation: 'Send X-Content-Type-Options: nosniff on every response.',
      scoreImpact: -15,
      references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options'],
    });
    return;
  }
  if (value.trim().toLowerCase() !== 'nosniff') {
    findings.push({
      id: 'headers.xcto.invalid',
      title: 'X-Content-Type-Options is not "nosniff"',
      severity: 'medium',
      status: 'warn',
      detail: 'nosniff is the only value browsers act on.',
      evidence: value,
      recommendation: 'Set the value to exactly: nosniff',
      scoreImpact: -15,
    });
    return;
  }
  findings.push({
    id: 'headers.xcto.present',
    title: 'X-Content-Type-Options: nosniff is set',
    severity: 'pass',
    status: 'pass',
    detail: 'MIME sniffing is disabled.',
    scoreImpact: 0,
  });
}

const WEAK_REFERRER = new Set(['unsafe-url', 'no-referrer-when-downgrade', '']);
const STRONG_REFERRER = new Set([
  'no-referrer',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
]);

function analyseReferrerPolicy(value: string | null, findings: Finding[]): void {
  if (!value) {
    findings.push({
      id: 'headers.referrer.missing',
      title: 'Referrer-Policy is missing',
      severity: 'low',
      status: 'fail',
      detail:
        'Without an explicit policy the browser default applies, and full URLs — including any tokens in the path or query — can leak to third-party sites.',
      recommendation: 'Send Referrer-Policy: strict-origin-when-cross-origin.',
      scoreImpact: -10,
      references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy'],
    });
    return;
  }

  // A list is allowed; the last token the browser understands wins.
  const tokens = value.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
  const effective = tokens[tokens.length - 1] ?? '';

  if (WEAK_REFERRER.has(effective)) {
    findings.push({
      id: 'headers.referrer.weak',
      title: 'Referrer-Policy is permissive',
      severity: 'low',
      status: 'warn',
      detail: `"${effective}" still sends the full URL in common cases.`,
      evidence: value,
      recommendation: 'Use strict-origin-when-cross-origin or stricter.',
      scoreImpact: -8,
    });
    return;
  }

  findings.push({
    id: 'headers.referrer.present',
    title: 'Referrer-Policy is set',
    severity: 'pass',
    status: 'pass',
    detail: `Policy is ${effective}.`,
    evidence: value,
    scoreImpact: STRONG_REFERRER.has(effective) ? 2 : 0,
  });
}

function analysePermissionsPolicy(value: string | null, findings: Finding[]): void {
  if (!value) {
    findings.push({
      id: 'headers.permissions.missing',
      title: 'Permissions-Policy is missing',
      severity: 'low',
      status: 'fail',
      detail:
        'Powerful browser features (camera, microphone, geolocation, payment) are not explicitly denied, so embedded third-party frames may request them.',
      recommendation:
        'Send Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=() and open up only what you use.',
      scoreImpact: -10,
      references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy'],
    });
    return;
  }
  findings.push({
    id: 'headers.permissions.present',
    title: 'Permissions-Policy is set',
    severity: 'pass',
    status: 'pass',
    detail: 'Browser feature access is explicitly declared.',
    evidence: truncate(value),
    scoreImpact: 2,
  });
}

/**
 * The cross-origin isolation trio. COOP is the one that matters on an ordinary
 * site: without it, a page that opens yours keeps a window handle and can
 * navigate or probe it, which is the mechanism behind OAuth popup tampering.
 */
function analyseCrossOrigin(
  headers: Record<string, string>,
  findings: Finding[],
): Record<string, string | null> {
  const coop = headers['cross-origin-opener-policy'] ?? null;
  const coep = headers['cross-origin-embedder-policy'] ?? null;
  const corp = headers['cross-origin-resource-policy'] ?? null;

  if (!coop) {
    findings.push({
      id: 'headers.coop.missing',
      title: 'Cross-Origin-Opener-Policy is missing',
      severity: 'low',
      status: 'fail',
      detail:
        'Any page that opens yours, or that you open, keeps a reference to your window and can navigate it. This is what makes tabnabbing and OAuth popup tampering possible.',
      recommendation: 'Send Cross-Origin-Opener-Policy: same-origin.',
      scoreImpact: -8,
      references: [
        'https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy',
      ],
    });
  } else {
    const value = coop.trim().toLowerCase();
    const strong = value === 'same-origin' || value === 'same-origin-allow-popups';
    findings.push({
      id: 'headers.coop.present',
      title: 'Cross-Origin-Opener-Policy is set',
      severity: strong ? 'pass' : 'low',
      status: strong ? 'pass' : 'warn',
      detail: strong
        ? 'Window references from other origins are severed (' + value + ').'
        : '"' + value + '" leaves the window reachable from other origins.',
      evidence: coop,
      recommendation: strong ? undefined : 'Use same-origin, or same-origin-allow-popups.',
      scoreImpact: strong ? 3 : -5,
    });
  }

  if (corp) {
    findings.push({
      id: 'headers.corp.present',
      title: 'Cross-Origin-Resource-Policy is set',
      severity: 'pass',
      status: 'pass',
      detail: 'Responses cannot be embedded cross-origin (' + corp + ').',
      scoreImpact: 2,
    });
  } else if (!coep) {
    findings.push({
      id: 'headers.corp.missing',
      title: 'No Cross-Origin-Resource-Policy',
      severity: 'info',
      status: 'info',
      detail:
        'CORP tells browsers to refuse embedding your responses from other sites, blocking a class of cross-site leak. Optional for most sites, valuable for anything serving user-specific content.',
      recommendation: 'Consider Cross-Origin-Resource-Policy: same-origin.',
      scoreImpact: 0,
    });
  }

  return {
    'cross-origin-opener-policy': coop,
    'cross-origin-embedder-policy': coep,
    'cross-origin-resource-policy': corp,
  };
}

/**
 * A personalised response that a shared cache may store can be handed to the
 * wrong user. We see only one unauthenticated response, so the signal we can
 * trust is Set-Cookie alongside permissive caching.
 */
function analyseCaching(
  headers: Record<string, string>,
  hasCookies: boolean,
  findings: Finding[],
): void {
  if (!hasCookies) return;
  const cacheControl = headers['cache-control'] ?? null;
  const value = (cacheControl ?? '').toLowerCase();
  const safe = /no-store|private|no-cache|max-age\s*=\s*0/.test(value);

  if (safe) {
    findings.push({
      id: 'headers.cache.safe',
      title: 'Cookie-setting response is not shared-cacheable',
      severity: 'pass',
      status: 'pass',
      detail: 'Cache-Control is ' + cacheControl + '.',
      scoreImpact: 0,
    });
    return;
  }

  findings.push({
    id: 'headers.cache.cookie-cacheable',
    title: 'Response sets a cookie but is publicly cacheable',
    severity: 'medium',
    status: 'warn',
    detail:
      'This response carries Set-Cookie and does not forbid shared caching, so a CDN or proxy may store it and serve one visitor a page, or a session cookie, belonging to another.',
    evidence: 'set-cookie present; cache-control: ' + (cacheControl ?? '(not set)'),
    recommendation:
      'Send Cache-Control: no-store, or at least private, on any response that sets a cookie or contains user-specific content.',
    scoreImpact: -12,
  });
}

function analyseCookies(cookies: CookieObservation[], isHttps: boolean, findings: Finding[]): void {
  if (cookies.length === 0) return;

  const insecure = cookies.filter((c) => !c.secure);
  if (isHttps && insecure.length > 0) {
    findings.push({
      id: 'headers.cookies.insecure',
      title: `${insecure.length} cookie${insecure.length === 1 ? '' : 's'} set without the Secure flag`,
      severity: 'medium',
      status: 'warn',
      detail: 'Cookies without Secure are also sent over plain HTTP, where they can be read in transit.',
      evidence: insecure.map((c) => c.name).join(', '),
      recommendation: 'Add the Secure attribute to every cookie on an HTTPS site.',
      scoreImpact: -10,
    });
  }

  const noHttpOnly = cookies.filter((c) => !c.httpOnly);
  if (noHttpOnly.length > 0) {
    findings.push({
      id: 'headers.cookies.no-httponly',
      title: `${noHttpOnly.length} cookie${noHttpOnly.length === 1 ? '' : 's'} readable from JavaScript`,
      severity: 'low',
      status: 'warn',
      detail:
        'Cookies without HttpOnly can be read by any script on the page, so an XSS flaw hands over the session directly.',
      evidence: noHttpOnly.map((c) => c.name).join(', '),
      recommendation: 'Add HttpOnly to any cookie your front-end code does not need to read.',
      scoreImpact: -5,
    });
  }

  // SameSite=None without Secure is rejected outright by current browsers, so
  // the cookie silently stops working: a correctness bug as much as a risk.
  const noneWithoutSecure = cookies.filter((c) => c.sameSite === 'none' && !c.secure);
  if (noneWithoutSecure.length > 0) {
    findings.push({
      id: 'headers.cookies.none-without-secure',
      title: `${noneWithoutSecure.length} cookie${noneWithoutSecure.length === 1 ? '' : 's'} set SameSite=None without Secure`,
      severity: 'medium',
      status: 'fail',
      detail:
        'Browsers reject SameSite=None unless Secure is also set, so these cookies are being dropped entirely.',
      evidence: noneWithoutSecure.map((c) => c.name).join(', '),
      recommendation: 'Add Secure, or change SameSite to Lax.',
      scoreImpact: -10,
    });
  }

  // An explicit Domain attribute shares the cookie with every subdomain, so a
  // flaw on any one of them reaches the session.
  const widened = cookies.filter((c) => c.domain && !c.prefix);
  if (widened.length > 0) {
    findings.push({
      id: 'headers.cookies.domain-scope',
      title: `${widened.length} cookie${widened.length === 1 ? '' : 's'} scoped to the whole domain`,
      severity: 'low',
      status: 'warn',
      detail:
        'An explicit Domain attribute sends the cookie to every subdomain, including ones you may no longer control.',
      evidence: widened.map((c) => `${c.name} (Domain=${c.domain})`).join(', '),
      recommendation:
        'Drop the Domain attribute to make the cookie host-only, or use the __Host- prefix, which browsers enforce.',
      scoreImpact: -5,
    });
  }

  const prefixed = cookies.filter((c) => c.prefix);
  if (prefixed.length > 0) {
    findings.push({
      id: 'headers.cookies.prefix',
      title: `${prefixed.length} cookie${prefixed.length === 1 ? '' : 's'} use a browser-enforced prefix`,
      severity: 'pass',
      status: 'pass',
      detail:
        'The __Host- and __Secure- prefixes make the browser refuse the cookie unless it is correctly scoped and secure.',
      evidence: prefixed.map((c) => c.name).join(', '),
      scoreImpact: 3,
    });
  }

  const noSameSite = cookies.filter((c) => !c.sameSite);
  if (noSameSite.length > 0) {
    findings.push({
      id: 'headers.cookies.no-samesite',
      title: `${noSameSite.length} cookie${noSameSite.length === 1 ? '' : 's'} without SameSite`,
      severity: 'low',
      status: 'warn',
      detail: 'No explicit SameSite attribute, so cross-site request forgery protection depends on browser defaults.',
      evidence: noSameSite.map((c) => c.name).join(', '),
      recommendation: 'Set SameSite=Lax (or Strict) explicitly.',
      scoreImpact: -5,
    });
  }
}

function truncate(value: string, limit = 300): string {
  return value.length > limit ? `${value.slice(0, limit)}…` : value;
}

/**
 * Probe whether plain HTTP redirects to HTTPS. One extra request, to the same
 * public host we are already scanning.
 */
async function testHttpsRedirect(
  target: URL,
  budget?: RequestBudget,
): Promise<HeadersData['httpsRedirect']> {
  if (target.protocol !== 'https:') {
    return { tested: false, redirectsToHttps: null, note: 'Target was requested over HTTP.' };
  }
  const plain = new URL(target.toString());
  plain.protocol = 'http:';
  if (plain.port === '443') plain.port = '';

  try {
    const response = await rawRequest(
      plain,
      { wantBody: false, timeoutMs: Math.min(config.requestTimeoutMs, 6000), budget },
    );
    const location = response.headers['location'];
    const redirects =
      response.status >= 300 &&
      response.status < 400 &&
      !!location &&
      new URL(location, plain).protocol === 'https:';
    return {
      tested: true,
      redirectsToHttps: redirects,
      note: `HTTP responded ${response.status}${location ? ` -> ${location}` : ''}`,
    };
  } catch (err) {
    // A refused connection on port 80 is a perfectly good outcome.
    return {
      tested: true,
      redirectsToHttps: null,
      note: `Port 80 did not answer (${describeError(err)}). HTTPS-only is fine.`,
    };
  }
}

export async function runHeadersCheck(
  target: URL,
  response: RawResponse,
  redirectChain: HeadersData['redirectChain'],
  budget?: RequestBudget,
): Promise<SectionReport<HeadersData>> {
  const startedAt = Date.now();
  const findings: Finding[] = [];
  const finalUrl = new URL(response.url);
  const isHttps = finalUrl.protocol === 'https:';

  const securityHeaders: Record<string, string | null> = {};
  for (const name of GRADED_HEADERS) {
    securityHeaders[name] = response.headers[name] ?? null;
  }

  if (!isHttps) {
    findings.push({
      id: 'headers.transport.plaintext',
      title: 'Site is served over plain HTTP',
      severity: 'high',
      status: 'fail',
      detail:
        'Traffic is unencrypted, so anyone on the network path can read and modify every page and credential.',
      recommendation: 'Obtain a certificate (Let’s Encrypt is free) and redirect all HTTP traffic to HTTPS.',
      scoreImpact: -30,
    });
  }

  const cspCoversFraming = analyseCsp(
    securityHeaders['content-security-policy'] ?? null,
    response.headers['content-security-policy-report-only'] ?? null,
    findings,
  );
  analyseHsts(securityHeaders['strict-transport-security'] ?? null, isHttps, findings);
  analyseXfo(securityHeaders['x-frame-options'] ?? null, cspCoversFraming, findings);
  analyseXcto(securityHeaders['x-content-type-options'] ?? null, findings);
  analyseReferrerPolicy(securityHeaders['referrer-policy'] ?? null, findings);
  analysePermissionsPolicy(securityHeaders['permissions-policy'] ?? null, findings);

  const cookies = parseSetCookie(response.rawHeaders['set-cookie'] ?? []);
  analyseCookies(cookies, isHttps, findings);
  const crossOrigin = analyseCrossOrigin(response.headers, findings);
  analyseCaching(response.headers, cookies.length > 0, findings);

  const informationDisclosure: HeadersData['informationDisclosure'] = [];
  for (const name of DISCLOSURE_HEADERS) {
    const value = response.headers[name];
    if (!value) continue;
    // "Server: cloudflare" tells an attacker nothing useful; "Apache/2.4.29" does.
    if (name === 'server' && !VERSION_IN_VALUE.test(value)) continue;
    informationDisclosure.push({ header: name, value });
  }
  if (informationDisclosure.length > 0) {
    findings.push({
      id: 'headers.disclosure',
      title: 'Response headers disclose software versions',
      severity: 'low',
      status: 'warn',
      detail:
        'Version banners let an attacker match your stack against public vulnerability lists without touching the site again.',
      evidence: informationDisclosure.map((d) => `${d.header}: ${d.value}`).join(' | '),
      recommendation: 'Suppress or genericise these headers at the web server or CDN.',
      scoreImpact: -5,
    });
  }

  const httpsRedirect = await testHttpsRedirect(target, budget);
  if (httpsRedirect.tested && httpsRedirect.redirectsToHttps === false) {
    findings.push({
      id: 'headers.transport.no-redirect',
      title: 'HTTP does not redirect to HTTPS',
      severity: 'medium',
      status: 'fail',
      detail:
        'The site answers on port 80 without sending visitors to the encrypted version, so a plain-HTTP visit stays plain HTTP.',
      evidence: httpsRedirect.note,
      recommendation: 'Return a 301 to the https:// URL for every HTTP request.',
      scoreImpact: -20,
    });
  } else if (httpsRedirect.redirectsToHttps === true) {
    findings.push({
      id: 'headers.transport.redirect',
      title: 'HTTP redirects to HTTPS',
      severity: 'pass',
      status: 'pass',
      detail: 'Plain HTTP requests are sent to the encrypted site.',
      evidence: httpsRedirect.note,
      scoreImpact: 0,
    });
  }

  const data: HeadersData = {
    finalUrl: response.url,
    statusCode: response.status,
    headers: response.headers,
    securityHeaders,
    redirectChain,
    httpsRedirect,
    cookies,
    informationDisclosure,
    crossOrigin,
    cacheControl: response.headers['cache-control'] ?? null,
  };

  const missing = GRADED_HEADERS.filter((name) => !securityHeaders[name]).length;
  const summary =
    missing === 0
      ? 'All six graded security headers are present.'
      : `${missing} of 6 graded security headers ${missing === 1 ? 'is' : 'are'} missing.`;

  const section = buildSection('headers', data, sortFindings(findings), summary, Date.now() - startedAt);
  section.findings.forEach((finding) => {
    if (!finding.references) finding.references = [REF_OBSERVATORY];
  });
  return section;
}
