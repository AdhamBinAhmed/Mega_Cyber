/** Turning whatever the user typed into a target we are willing to scan. */

import { isIP } from 'node:net';
import dns from 'node:dns/promises';
import type { LookupAddress } from 'node:dns';

import { classifyIp } from './ip';
import { allowPrivateTargets } from './config';

/** Ports a public website scanner has any business touching. */
const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);

/** Names that never point anywhere public. */
const BLOCKED_HOST_SUFFIXES = [
  '.localhost',
  '.local',
  '.internal',
  '.intranet',
  '.lan',
  '.home.arpa',
  '.test',
  '.example',
  '.invalid',
];

const BLOCKED_HOST_EXACT = new Set([
  'localhost',
  'metadata',
  'metadata.google.internal',
  'instance-data',
]);

export type TargetFailureCode = 'invalid_url' | 'blocked_target';

export interface TargetOk {
  ok: true;
  url: URL;
  hostname: string;
  port: number | null;
}

export interface TargetFailure {
  ok: false;
  code: TargetFailureCode;
  message: string;
}

/**
 * Parse and sanity-check a user-supplied target. This is the syntactic half of
 * the guard; the DNS half runs in {@link resolveTarget}.
 */
export function parseTarget(input: string): TargetOk | TargetFailure {
  const trimmed = (input ?? '').trim();
  if (!trimmed) {
    return { ok: false, code: 'invalid_url', message: 'Enter a URL to scan.' };
  }
  if (trimmed.length > 2048) {
    return { ok: false, code: 'invalid_url', message: 'That URL is too long.' };
  }

  // Default to https when the visitor omits the scheme.
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return { ok: false, code: 'invalid_url', message: 'That does not look like a valid URL.' };
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return {
      ok: false,
      code: 'invalid_url',
      message: `Only http:// and https:// targets are supported (got ${url.protocol}).`,
    };
  }

  if (url.username || url.password) {
    return {
      ok: false,
      code: 'invalid_url',
      message: 'Remove the credentials from the URL before scanning.',
    };
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname) {
    return { ok: false, code: 'invalid_url', message: 'The URL has no hostname.' };
  }

  if (!isIP(hostname) && !/^[a-z0-9.-]+$/.test(hostname)) {
    return { ok: false, code: 'invalid_url', message: 'The hostname contains invalid characters.' };
  }

  // ALLOW_PRIVATE_TARGETS (development only) skips the public-host rules so a
  // developer can scan a site running on their own machine.
  if (!allowPrivateTargets) {
    const verdict = checkHostIsPublic(hostname);
    if (verdict) return verdict;
  }

  const port = url.port ? Number(url.port) : null;
  if (!allowPrivateTargets && port !== null && !ALLOWED_PORTS.has(port)) {
    return {
      ok: false,
      code: 'blocked_target',
      message: `Port ${port} is not scannable. Allowed: ${[...ALLOWED_PORTS].join(', ')}.`,
    };
  }

  // Normalise: keep path and query, drop the fragment.
  url.hash = '';
  url.hostname = hostname;

  return { ok: true, url, hostname, port };
}

/** The public-host rules, factored out so the dev flag can skip them wholesale. */
function checkHostIsPublic(hostname: string): TargetFailure | null {
  if (BLOCKED_HOST_EXACT.has(hostname)) {
    return { ok: false, code: 'blocked_target', message: `"${hostname}" is not a public host.` };
  }
  if (BLOCKED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    return {
      ok: false,
      code: 'blocked_target',
      message: `"${hostname}" is a private or reserved name.`,
    };
  }

  // A bare IP literal can be judged immediately.
  if (isIP(hostname)) {
    const verdict = classifyIp(hostname);
    if (!verdict.public) {
      return {
        ok: false,
        code: 'blocked_target',
        message: `${hostname} is a ${verdict.reason} address, not a public site.`,
      };
    }
  } else if (!hostname.includes('.')) {
    // Single-label names only resolve on an internal network.
    return {
      ok: false,
      code: 'blocked_target',
      message: `"${hostname}" is not a fully qualified domain name.`,
    };
  }

  return null;
}

export interface ResolveOk {
  ok: true;
  ips: string[];
}

export interface ResolveFailure {
  ok: false;
  code: 'blocked_target' | 'unreachable';
  message: string;
}

/**
 * Resolve the hostname and confirm every address is publicly routable.
 *
 * This is an up-front sanity check so the user gets a clear error. The
 * authoritative enforcement happens per-connection in http.ts, which pins the
 * socket to an approved address.
 */
export async function resolveTarget(hostname: string): Promise<ResolveOk | ResolveFailure> {
  if (isIP(hostname)) {
    const verdict = classifyIp(hostname);
    return verdict.public || allowPrivateTargets
      ? { ok: true, ips: [hostname] }
      : { ok: false, code: 'blocked_target', message: `${hostname} is ${verdict.reason}.` };
  }

  let addresses: LookupAddress[];
  try {
    addresses = await dns.lookup(hostname, { all: true, verbatim: true });
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    return {
      ok: false,
      code: 'unreachable',
      message:
        code === 'ENOTFOUND' || code === 'EAI_AGAIN'
          ? `${hostname} does not resolve. Check the spelling.`
          : `Could not resolve ${hostname}.`,
    };
  }

  if (addresses.length === 0) {
    return { ok: false, code: 'unreachable', message: `${hostname} does not resolve.` };
  }

  const blocked = addresses
    .map((a) => ({ address: a.address, verdict: classifyIp(a.address) }))
    .filter((entry) => !entry.verdict.public);

  if (blocked.length === addresses.length && !allowPrivateTargets) {
    const first = blocked[0]!;
    return {
      ok: false,
      code: 'blocked_target',
      message: `${hostname} resolves to ${first.address} — ${first.verdict.reason}. The scanner only targets public hosts.`,
    };
  }

  return { ok: true, ips: addresses.map((a) => a.address) };
}

/**
 * Multi-label public suffixes common enough to matter for email-policy lookups.
 * Not a full Public Suffix List — good enough to pick the right apex for SPF
 * and DMARC on the domains an MVP will realistically see.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'net.uk', 'sch.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
  'co.za', 'org.za', 'net.za', 'web.za',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'co.kr', 'or.kr', 'ne.kr',
  'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.tr', 'com.sg', 'com.my',
  'com.hk', 'com.tw', 'com.ua', 'com.pl', 'com.pk', 'com.ng', 'com.eg',
  'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa',
  'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il',
  'co.id', 'or.id', 'web.id', 'ac.id',
  'co.th', 'in.th', 'ac.th', 'go.th',
]);

/**
 * Best-effort registrable domain ("mail.shop.example.co.uk" -> "example.co.uk").
 * Email policy records (SPF, DMARC) live at the apex, not on the subdomain.
 */
export function registrableDomain(hostname: string): string {
  if (isIP(hostname)) return hostname;
  const labels = hostname.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');

  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join('.');
  }
  return lastTwo;
}
