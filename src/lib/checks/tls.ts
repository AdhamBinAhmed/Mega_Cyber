/**
 * SSL/TLS assessment.
 *
 * Two sources, because neither alone is enough:
 *
 *  1. Qualys SSL Labs — the authoritative grade, but a cold scan takes minutes,
 *     far longer than a serverless request should stay open. We ask for a
 *     cached result and, if the scan is still running, hand the dashboard a
 *     pending section to poll.
 *
 *  2. A local TLS handshake — the same connection a browser makes, which gives
 *     us the certificate and the negotiated protocol immediately. Protocol
 *     version probing (four short handshakes to the port we already use) is
 *     the one place the scanner does more than a single plain request; it is
 *     still read-only, and TLS_LOCAL_PROBE=cert|off narrows or disables it.
 */

import tls from 'node:tls';
import type { PeerCertificate } from 'node:tls';

import type {
  Finding,
  SectionReport,
  SslLabsSummary,
  TlsCertificate,
  TlsData,
  TlsProtocolName,
  TlsProtocolSupport,
} from '../types';
import { buildSection, errorSection, sortFindings } from '../scoring';
import { config, USER_AGENT } from '../config';
import { guardedLookup } from '../lookup';
import { describeError } from '../errors';

const PROBE_VERSIONS: Array<{ name: TlsProtocolName; version: tls.SecureVersion }> = [
  { name: 'TLS 1.0', version: 'TLSv1' },
  { name: 'TLS 1.1', version: 'TLSv1.1' },
  { name: 'TLS 1.2', version: 'TLSv1.2' },
  { name: 'TLS 1.3', version: 'TLSv1.3' },
];

const HANDSHAKE_TIMEOUT_MS = 7000;

/**
 * Errors that genuinely mean "there is no usable HTTPS service here".
 *
 * This list is deliberately narrow. Declaring that a site has no encryption is
 * a critical finding that caps its entire grade at F, so only unambiguous
 * signals belong here: nothing accepted the connection, or something did but
 * it was not speaking TLS.
 *
 * ECONNRESET, ETIMEDOUT and EPIPE are specifically NOT here. A loaded server,
 * a rate limiter, a firewall or a middlebox all produce those against sites
 * whose TLS is perfectly fine — observed while testing this scanner, where
 * back-to-back scans of one small host started getting reset.
 */
const NO_HTTPS_CODES = new Set([
  'ECONNREFUSED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EPROTO',
  'ERR_SSL_WRONG_VERSION_NUMBER',
  'ERR_SSL_PACKET_LENGTH_TOO_LONG',
])

/** Transient failures worth one more try before we give up on a verdict. */
const RETRYABLE_CODES = new Set(['ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN']);

interface HandshakeResult {
  ok: boolean;
  socket?: tls.TLSSocket;
  error?: NodeJS.ErrnoException;
}

function handshake(
  host: string,
  port: number,
  options: tls.ConnectionOptions = {},
): Promise<HandshakeResult> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (result: HandshakeResult) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    let socket: tls.TLSSocket;
    try {
      socket = tls.connect({
        host,
        port,
        servername: host,
        // We are inspecting the certificate, not trusting it. Rejecting here
        // would stop us reporting on exactly the sites that need it most.
        rejectUnauthorized: false,
        timeout: HANDSHAKE_TIMEOUT_MS,
        // Pin the socket to an address the SSRF guard approves of.
        lookup: guardedLookup(),
        ...options,
      });
    } catch (err) {
      done({ ok: false, error: err as NodeJS.ErrnoException });
      return;
    }

    socket.once('secureConnect', () => done({ ok: true, socket }));
    socket.once('error', (err) => {
      done({ ok: false, error: err as NodeJS.ErrnoException });
      socket.destroy();
    });
    socket.once('timeout', () => {
      done({ ok: false, error: Object.assign(new Error('handshake timed out'), { code: 'ETIMEDOUT' }) });
      socket.destroy();
    });
  });
}

/** Does the certificate cover this hostname? Handles a single-label wildcard. */
export function hostnameMatchesCert(hostname: string, altNames: string[], commonName: string | null): boolean {
  const names = altNames.length > 0 ? altNames : commonName ? [commonName] : [];
  const target = hostname.toLowerCase();
  return names.some((raw) => {
    const name = raw.toLowerCase().trim();
    if (name === target) return true;
    if (!name.startsWith('*.')) return false;
    const suffix = name.slice(1); // ".example.com"
    if (!target.endsWith(suffix)) return false;
    // A wildcard matches exactly one label.
    const prefix = target.slice(0, target.length - suffix.length);
    return prefix.length > 0 && !prefix.includes('.');
  });
}

function parseAltNames(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.toUpperCase().startsWith('DNS:'))
    .map((entry) => entry.slice(4));
}

function formatName(name: Record<string, string | string[]> | undefined): string | null {
  if (!name) return null;
  const parts: string[] = [];
  for (const [key, value] of Object.entries(name)) {
    parts.push(`${key}=${Array.isArray(value) ? value.join('+') : value}`);
  }
  return parts.length > 0 ? parts.join(', ') : null;
}

function describeCertificate(
  cert: PeerCertificate,
  hostname: string,
  authorized: boolean,
  authorizationError: string | null,
): TlsCertificate {
  const altNames = parseAltNames(cert.subjectaltname);
  const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
  const validToValid = validTo && !Number.isNaN(validTo.getTime());
  const daysUntilExpiry = validToValid
    ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000)
    : null;

  const commonName = typeof cert.subject?.CN === 'string' ? cert.subject.CN : null;
  const ec = cert.asn1Curve ?? cert.nistCurve ?? null;

  return {
    subject: formatName(cert.subject as unknown as Record<string, string>),
    issuer: formatName(cert.issuer as unknown as Record<string, string>),
    altNames,
    validFrom: cert.valid_from ?? null,
    validTo: cert.valid_to ?? null,
    daysUntilExpiry,
    expired: daysUntilExpiry === null ? null : daysUntilExpiry < 0,
    hostnameMatch: hostnameMatchesCert(hostname, altNames, commonName),
    chainTrusted: authorized,
    chainError: authorizationError ?? undefined,
    keyType: ec ? `EC (${ec})` : cert.bits ? 'RSA' : null,
    keyBits: cert.bits ?? null,
    serialNumber: cert.serialNumber ?? null,
    fingerprintSha256: cert.fingerprint256 ?? null,
  };
}

/** Decide what a failed handshake tells us about the server. */
function classifyHandshakeError(err: NodeJS.ErrnoException | undefined): {
  supported: boolean | null;
  note?: string;
} {
  const code = err?.code ?? '';
  const message = (err?.message ?? '').toLowerCase();

  // Our own OpenSSL build refused to offer the version — says nothing about
  // the server. Node disables TLS 1.0/1.1 ciphers at the default security level.
  if (
    code === 'ERR_TLS_INVALID_PROTOCOL_VERSION' ||
    message.includes('no protocols available') ||
    message.includes('unsupported protocol version')
  ) {
    return { supported: null, note: 'This scanner could not offer the version, so support is unknown.' };
  }
  if (code === 'ETIMEDOUT' || message.includes('timed out')) {
    return { supported: null, note: 'Handshake timed out.' };
  }
  if (code === 'EBLOCKED') {
    return { supported: null, note: 'Target address is not public.' };
  }
  // Everything else — protocol alerts, resets, handshake failures — is the
  // server declining, which is the answer we want.
  return { supported: false };
}

async function probeProtocols(host: string, port: number): Promise<TlsProtocolSupport[]> {
  const results = await Promise.all(
    PROBE_VERSIONS.map(async ({ name, version }) => {
      const legacy = version === 'TLSv1' || version === 'TLSv1.1';
      const result = await handshake(host, port, {
        minVersion: version,
        maxVersion: version,
        // OpenSSL 3 hides the legacy ciphers behind security level 0.
        ...(legacy ? { ciphers: 'DEFAULT:@SECLEVEL=0' } : {}),
      });
      if (result.ok) {
        result.socket?.destroy();
        return { protocol: name, supported: true } satisfies TlsProtocolSupport;
      }
      const verdict = classifyHandshakeError(result.error);
      return { protocol: name, ...verdict } satisfies TlsProtocolSupport;
    }),
  );
  return results;
}

/**
 * The certificate handshake drives a critical finding, so give a transient
 * failure one second chance before concluding anything from it.
 */
async function handshakeWithRetry(host: string, port: number): Promise<HandshakeResult> {
  const first = await handshake(host, port);
  if (first.ok || !RETRYABLE_CODES.has(first.error?.code ?? '')) return first;

  await new Promise((resolve) => setTimeout(resolve, 750));
  const second = await handshake(host, port);
  // Report whichever attempt is more informative.
  return second.ok ? second : first;
}

/* -------------------------------------------------------------------------- */
/* SSL Labs                                                                   */
/* -------------------------------------------------------------------------- */

interface SslLabsEndpoint {
  ipAddress?: string;
  grade?: string;
  gradeTrustIgnored?: string;
  statusMessage?: string;
}

interface SslLabsResponse {
  host?: string;
  status?: string;
  statusMessage?: string;
  endpoints?: SslLabsEndpoint[];
  testTime?: number;
  errors?: Array<{ message: string }>;
}

function emptySslLabs(status: SslLabsSummary['status'], message: string | null): SslLabsSummary {
  return {
    enabled: config.sslLabs.enabled,
    status,
    grade: null,
    gradeTrustIgnored: null,
    endpointCount: 0,
    endpoints: [],
    testTime: null,
    message,
    pollable: status === 'IN_PROGRESS' || status === 'DNS',
  };
}

/**
 * Query SSL Labs. Deliberately cache-friendly: we never force a fresh scan, so
 * repeated dashboard loads do not hammer a free public service.
 */
export async function querySslLabs(host: string, timeoutMs: number): Promise<SslLabsSummary> {
  if (!config.sslLabs.enabled) {
    return emptySslLabs('SKIPPED', 'SSL Labs lookups are disabled by configuration.');
  }

  const base = `https://api.ssllabs.com/api/${config.sslLabs.version}/analyze`;
  const params = new URLSearchParams({
    host,
    fromCache: 'on',
    maxAge: String(config.sslLabs.maxAgeHours),
    all: 'done',
  });

  const headers: Record<string, string> = { 'user-agent': USER_AGENT };
  if (config.sslLabs.version === 'v4') {
    // v4 requires a registered email address; the API key header is optional.
    if (!config.sslLabs.email) {
      return emptySslLabs(
        'SKIPPED',
        'SSL Labs API v4 requires a registered email address — set SSLLABS_EMAIL.',
      );
    }
    headers['email'] = config.sslLabs.email;
    if (config.sslLabs.apiKey) headers['apikey'] = config.sslLabs.apiKey;
  }

  let payload: SslLabsResponse;
  try {
    const response = await fetch(`${base}?${params.toString()}`, {
      headers,
      signal: AbortSignal.timeout(timeoutMs),
    });

    if (response.status === 429 || response.status === 529) {
      return emptySslLabs('UNAVAILABLE', 'SSL Labs is rate limiting or overloaded; try again shortly.');
    }
    if (!response.ok) {
      return emptySslLabs('UNAVAILABLE', `SSL Labs returned HTTP ${response.status}.`);
    }
    payload = (await response.json()) as SslLabsResponse;
  } catch (err) {
    const reason = (err as Error).name === 'TimeoutError' ? 'timed out' : (err as Error).message;
    return emptySslLabs('UNAVAILABLE', `Could not reach SSL Labs (${reason}).`);
  }

  const status = (payload.status ?? 'ERROR').toUpperCase();
  const endpoints = (payload.endpoints ?? []).map((endpoint) => ({
    ipAddress: endpoint.ipAddress ?? 'unknown',
    grade: endpoint.grade ?? null,
    statusMessage: endpoint.statusMessage ?? '',
  }));

  const graded = (payload.endpoints ?? []).filter((endpoint) => endpoint.grade);
  // Report the worst endpoint: a site is only as good as its weakest server.
  const worst = graded.sort((a, b) => (a.grade ?? '').localeCompare(b.grade ?? '')).pop();

  const summary: SslLabsSummary = {
    enabled: true,
    status: (['READY', 'IN_PROGRESS', 'DNS', 'ERROR'].includes(status)
      ? status
      : 'ERROR') as SslLabsSummary['status'],
    grade: worst?.grade ?? null,
    gradeTrustIgnored: worst?.gradeTrustIgnored ?? null,
    endpointCount: endpoints.length,
    endpoints,
    testTime: payload.testTime ? new Date(payload.testTime).toISOString() : null,
    message: payload.statusMessage ?? payload.errors?.[0]?.message ?? null,
    pollable: status === 'IN_PROGRESS' || status === 'DNS',
  };

  return summary;
}

/** SSL Labs grade -> score modifier. Overlaps our own checks, so kept modest. */
const GRADE_IMPACT: Record<string, number> = {
  'A+': 5,
  A: 0,
  'A-': -3,
  B: -10,
  C: -20,
  D: -25,
  E: -30,
  F: -35,
  T: -30,
  M: -30,
};

/* -------------------------------------------------------------------------- */
/* Section                                                                    */
/* -------------------------------------------------------------------------- */

export interface TlsCheckOptions {
  /** How long to wait on SSL Labs before returning a pending section. */
  sslLabsTimeoutMs?: number;
}

export async function runTlsCheck(
  hostname: string,
  port = 443,
  options: TlsCheckOptions = {},
): Promise<SectionReport<TlsData | null>> {
  const startedAt = Date.now();
  const findings: Finding[] = [];

  const doLocal = config.tlsLocalProbe !== 'off';
  const doProtocols = config.tlsLocalProbe === 'on';

  const [primary, sslLabs] = await Promise.all([
    doLocal ? handshakeWithRetry(hostname, port) : Promise.resolve<HandshakeResult>({ ok: false }),
    querySslLabs(hostname, options.sslLabsTimeoutMs ?? config.sslLabs.initialWaitMs),
  ]);

  let certificate: TlsCertificate | null = null;
  let negotiated: TlsData['negotiated'] = null;
  let httpsAvailable = false;
  /** Set when the scanner itself failed, rather than the target. */
  let inconclusive: string | null = null;

  if (primary.ok && primary.socket) {
    const socket = primary.socket;
    httpsAvailable = true;
    negotiated = { protocol: socket.getProtocol(), cipher: socket.getCipher()?.name ?? null };
    const peer = socket.getPeerCertificate(false);
    if (peer && Object.keys(peer).length > 0) {
      certificate = describeCertificate(
        peer,
        hostname,
        socket.authorized === true,
        socket.authorized ? null : String(socket.authorizationError ?? 'unknown'),
      );
    }
    socket.destroy();
  } else if (doLocal) {
    const code = primary.error?.code ?? '';
    const serverHasNoHttps = NO_HTTPS_CODES.has(code);

    if (serverHasNoHttps) {
      findings.push({
        id: 'tls.unreachable',
        title: `No HTTPS service on port ${port}`,
        severity: 'critical',
        status: 'fail',
        detail:
          `The TLS handshake failed (${primary.error ? describeError(primary.error) : 'no response'}), so this host offers no encrypted connection. ` +
          'Everything sent to it — logins, form data, session cookies — travels in plain text.',
        recommendation:
          'Install a certificate (Let’s Encrypt issues them free) and serve the site over HTTPS.',
        scoreImpact: -100,
      });
    } else {
      // Something went wrong at our end. Saying nothing is far better than
      // telling a site with working TLS that it has none.
      inconclusive = primary.error
        ? describeError(primary.error)
        : 'the TLS handshake could not be completed';
    }
  }

  let protocols: TlsProtocolSupport[] = [];
  if (httpsAvailable && doProtocols) {
    protocols = await probeProtocols(hostname, port);
  } else if (httpsAvailable && negotiated?.protocol) {
    const map: Record<string, TlsProtocolName> = {
      TLSv1: 'TLS 1.0',
      'TLSv1.1': 'TLS 1.1',
      'TLSv1.2': 'TLS 1.2',
      'TLSv1.3': 'TLS 1.3',
    };
    const name = map[negotiated.protocol];
    protocols = PROBE_VERSIONS.map(({ name: label }) => ({
      protocol: label,
      supported: label === name ? true : null,
      note: label === name ? undefined : 'Protocol probing is disabled (TLS_LOCAL_PROBE).',
    }));
  }

  /* ---------------------------- Certificate ------------------------------ */
  if (certificate) {
    if (certificate.expired) {
      findings.push({
        id: 'tls.cert.expired',
        title: 'Certificate has expired',
        severity: 'critical',
        status: 'fail',
        detail: `The certificate expired on ${certificate.validTo}. Every visitor now sees a full-page browser warning.`,
        evidence: `notAfter ${certificate.validTo} (${Math.abs(certificate.daysUntilExpiry ?? 0)} days ago)`,
        recommendation: 'Renew the certificate now and set up automated renewal.',
        scoreImpact: -60,
      });
    } else if (certificate.daysUntilExpiry !== null && certificate.daysUntilExpiry <= 7) {
      findings.push({
        id: 'tls.cert.expiring-urgent',
        title: `Certificate expires in ${certificate.daysUntilExpiry} day${certificate.daysUntilExpiry === 1 ? '' : 's'}`,
        severity: 'high',
        status: 'warn',
        detail: 'Renewal is overdue. If automated renewal were working, it would have run by now.',
        evidence: `notAfter ${certificate.validTo}`,
        recommendation: 'Renew immediately and check why auto-renewal has not fired.',
        scoreImpact: -25,
      });
    } else if (certificate.daysUntilExpiry !== null && certificate.daysUntilExpiry <= 30) {
      findings.push({
        id: 'tls.cert.expiring',
        title: `Certificate expires in ${certificate.daysUntilExpiry} days`,
        severity: 'medium',
        status: 'warn',
        detail: 'Still valid, but inside the window where renewal should already have happened.',
        evidence: `notAfter ${certificate.validTo}`,
        recommendation: 'Confirm automated renewal is working.',
        scoreImpact: -10,
      });
    } else if (certificate.daysUntilExpiry !== null) {
      findings.push({
        id: 'tls.cert.valid',
        title: 'Certificate is valid',
        severity: 'pass',
        status: 'pass',
        detail: `Valid for another ${certificate.daysUntilExpiry} days (until ${certificate.validTo}).`,
        evidence: certificate.issuer ? `Issued by ${certificate.issuer}` : undefined,
        scoreImpact: 0,
      });
    }

    if (certificate.hostnameMatch === false) {
      findings.push({
        id: 'tls.cert.hostname-mismatch',
        title: 'Certificate does not cover this hostname',
        severity: 'high',
        status: 'fail',
        detail: `${hostname} is not listed in the certificate, so browsers will refuse the connection.`,
        evidence: `SAN: ${certificate.altNames.join(', ') || '(none)'}`,
        recommendation: 'Reissue the certificate with this hostname in the Subject Alternative Name list.',
        scoreImpact: -40,
      });
    }

    if (certificate.chainTrusted === false) {
      findings.push({
        id: 'tls.cert.untrusted',
        title: 'Certificate chain is not trusted',
        severity: 'high',
        status: 'fail',
        detail:
          `Validation failed: ${certificate.chainError ?? 'unknown error'}. This usually means a self-signed certificate or a missing intermediate.`,
        recommendation:
          'Serve the full chain including intermediates, or replace a self-signed certificate with one from a public CA.',
        scoreImpact: -40,
      });
    } else if (certificate.chainTrusted === true) {
      findings.push({
        id: 'tls.cert.trusted',
        title: 'Certificate chain validates',
        severity: 'pass',
        status: 'pass',
        detail: 'The chain is complete and signed by a trusted authority.',
        scoreImpact: 0,
      });
    }

    if (certificate.keyType === 'RSA' && certificate.keyBits !== null && certificate.keyBits < 2048) {
      findings.push({
        id: 'tls.cert.weak-key',
        title: `RSA key is only ${certificate.keyBits} bits`,
        severity: 'high',
        status: 'fail',
        detail: 'Keys below 2048 bits are considered breakable and are rejected by modern browsers.',
        recommendation: 'Reissue with at least a 2048-bit RSA key, or switch to ECDSA P-256.',
        scoreImpact: -30,
      });
    }
  }

  /* ----------------------------- Protocols -------------------------------- */
  const supportOf = (name: TlsProtocolName) =>
    protocols.find((entry) => entry.protocol === name)?.supported ?? null;

  for (const legacy of ['TLS 1.0', 'TLS 1.1'] as const) {
    if (supportOf(legacy) === true) {
      findings.push({
        id: `tls.protocol.${legacy.replace(/[^\d]/g, '')}`,
        title: `${legacy} is still accepted`,
        severity: 'medium',
        status: 'fail',
        detail:
          `${legacy} was deprecated by RFC 8996 and is disabled in every current browser. Leaving it enabled only helps downgrade attacks and fails PCI DSS.`,
        recommendation: 'Set the server minimum protocol version to TLS 1.2.',
        scoreImpact: legacy === 'TLS 1.0' ? -15 : -10,
        references: ['https://datatracker.ietf.org/doc/html/rfc8996'],
      });
    }
  }

  if (supportOf('TLS 1.3') === true) {
    findings.push({
      id: 'tls.protocol.13',
      title: 'TLS 1.3 is supported',
      severity: 'pass',
      status: 'pass',
      detail: 'The current protocol version is available, with forward secrecy by default.',
      scoreImpact: 5,
    });
  } else if (httpsAvailable && supportOf('TLS 1.3') === false) {
    findings.push({
      id: 'tls.protocol.no-13',
      title: 'TLS 1.3 is not supported',
      severity: 'low',
      status: 'warn',
      detail: 'TLS 1.2 still works, but 1.3 is faster and removes several legacy weaknesses.',
      recommendation: 'Enable TLS 1.3 on the server or CDN.',
      scoreImpact: -5,
    });
  }

  if (httpsAvailable && supportOf('TLS 1.2') === false && supportOf('TLS 1.3') === false) {
    findings.push({
      id: 'tls.protocol.no-modern',
      title: 'No modern TLS version accepted',
      severity: 'high',
      status: 'fail',
      detail: 'Neither TLS 1.2 nor 1.3 completed a handshake, so current browsers cannot connect.',
      scoreImpact: -40,
    });
  }

  const indeterminate = protocols.filter((entry) => entry.supported === null);
  if (indeterminate.length > 0 && httpsAvailable) {
    findings.push({
      id: 'tls.protocol.indeterminate',
      title: `${indeterminate.length} protocol version${indeterminate.length === 1 ? '' : 's'} could not be tested`,
      severity: 'info',
      status: 'info',
      detail:
        'The scanner could not offer these versions, usually because its own TLS library has them disabled. The SSL Labs result below covers them properly.',
      evidence: indeterminate.map((entry) => `${entry.protocol}: ${entry.note ?? 'unknown'}`).join(' | '),
      scoreImpact: 0,
    });
  }

  /* ----------------------------- SSL Labs --------------------------------- */
  if (sslLabs.status === 'READY' && sslLabs.grade) {
    const impact = GRADE_IMPACT[sslLabs.grade] ?? 0;
    const good = impact >= 0;
    findings.push({
      id: 'tls.ssllabs.grade',
      title: `SSL Labs grade: ${sslLabs.grade}`,
      severity: good ? 'pass' : impact <= -20 ? 'medium' : 'low',
      status: good ? 'pass' : 'warn',
      detail: good
        ? 'Qualys SSL Labs rates this endpoint well.'
        : `Qualys SSL Labs rates this endpoint ${sslLabs.grade}. Their report explains which cipher suites or protocol settings cost the points.`,
      evidence:
        sslLabs.endpoints.map((endpoint) => `${endpoint.ipAddress}: ${endpoint.grade ?? '-'}`).join(', ') ||
        undefined,
      recommendation: good
        ? undefined
        : `See the full report at https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}`,
      scoreImpact: impact,
      references: [`https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}`],
    });
  } else if (sslLabs.pollable) {
    findings.push({
      id: 'tls.ssllabs.pending',
      title: 'SSL Labs scan still running',
      severity: 'info',
      status: 'info',
      detail:
        'A full SSL Labs assessment takes a couple of minutes. The certificate and protocol results above come from a direct connection and are already final.',
      evidence: sslLabs.message ?? undefined,
      scoreImpact: 0,
    });
  } else if (sslLabs.status !== 'SKIPPED' && sslLabs.message) {
    findings.push({
      id: 'tls.ssllabs.unavailable',
      title: 'SSL Labs result unavailable',
      severity: 'info',
      status: 'info',
      detail: sslLabs.message,
      scoreImpact: 0,
    });
  }

  // No local result and no SSL Labs grade means we have nothing to grade on.
  // An error section is excluded from the overall score, which is honest;
  // inventing a zero would not be.
  if (inconclusive && !httpsAvailable && !(sslLabs.status === 'READY' && sslLabs.grade)) {
    return errorSection('tls', `TLS could not be assessed: ${inconclusive}`, Date.now() - startedAt);
  }

  const data: TlsData = {
    host: hostname,
    httpsAvailable,
    certificate,
    negotiated,
    protocols,
    sslLabs,
  };

  const summary = !httpsAvailable
    ? 'No HTTPS service answered on port 443.'
    : certificate?.expired
      ? 'Certificate has expired.'
      : sslLabs.status === 'READY' && sslLabs.grade
        ? `SSL Labs grade ${sslLabs.grade}; certificate valid for ${certificate?.daysUntilExpiry ?? '?'} more days.`
        : `Certificate valid for ${certificate?.daysUntilExpiry ?? '?'} more days${sslLabs.pollable ? '; SSL Labs scan in progress' : ''}.`;

  return buildSection(
    'tls',
    data,
    sortFindings(findings),
    summary,
    Date.now() - startedAt,
    sslLabs.pollable ? 'pending' : 'ok',
  );
}
