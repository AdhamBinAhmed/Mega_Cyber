/**
 * DNS posture: the records that stop other people sending mail as you, and
 * the one that stops them getting a certificate for you.
 *
 * All lookups use node:dns — no third-party DNS service sees the target.
 */

import { Resolver } from 'node:dns/promises';
import { isIP } from 'node:net';

import type { DnsData, DnsRecordCheck, Finding, SectionReport } from '../types';
import { buildSection, errorSection, sortFindings } from '../scoring';
import { registrableDomain } from '../target';

/**
 * DKIM keys live at <selector>._domainkey.<domain> and the selector is chosen
 * by whoever sends the mail, so it cannot be enumerated from DNS. We probe the
 * selectors used by the major providers; a miss is inconclusive, not a failure.
 */
const COMMON_DKIM_SELECTORS = [
  'default',
  'google',
  'selector1',
  'selector2',
  'k1',
  'k2',
  'dkim',
  'mail',
  's1',
  's2',
  'mandrill',
  'zoho',
  'protonmail',
  'pm',
  'sendgrid',
  'mailjet',
  'postmark',
  'everlytickey1',
  'fm1',
];

function resolver(): Resolver {
  // Keep every lookup on a short leash so one dead nameserver cannot eat the
  // whole scan budget.
  return new Resolver({ timeout: 4000, tries: 2 });
}

async function safe<T>(promise: Promise<T>): Promise<T | null> {
  try {
    return await promise;
  } catch {
    return null;
  }
}

/** TXT records arrive as arrays of 255-byte chunks that must be concatenated. */
function flattenTxt(records: string[][] | null): string[] {
  return (records ?? []).map((chunks) => chunks.join(''));
}

function parseSpfAll(record: string): '+all' | '-all' | '~all' | '?all' | null {
  const match = record.match(/(?:^|\s)([+\-~?])all(?:\s|$)/i);
  if (!match?.[1]) return null;
  return `${match[1]}all` as '+all' | '-all' | '~all' | '?all';
}

function parseDmarcTag(record: string, tag: string): string | null {
  const match = record.match(new RegExp(`(?:^|;)\\s*${tag}\\s*=\\s*([^;]+)`, 'i'));
  return match?.[1]?.trim().toLowerCase() ?? null;
}

function analyseSpf(records: string[], findings: Finding[]): DnsRecordCheck {
  const spf = records.filter((r) => r.toLowerCase().startsWith('v=spf1'));

  if (spf.length === 0) {
    findings.push({
      id: 'dns.spf.missing',
      title: 'No SPF record',
      severity: 'medium',
      status: 'fail',
      detail:
        'Nothing declares which servers may send mail for this domain, so anyone can forge your address and receiving servers have no basis to reject it.',
      recommendation:
        'Publish a TXT record at the apex listing your senders, ending in -all. If the domain never sends mail, use: v=spf1 -all',
      scoreImpact: -30,
      references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
    });
    return { type: 'SPF', present: false, records: [], queried: ['TXT @'] };
  }

  if (spf.length > 1) {
    findings.push({
      id: 'dns.spf.multiple',
      title: 'More than one SPF record',
      severity: 'medium',
      status: 'fail',
      detail:
        'RFC 7208 allows exactly one SPF record. Receivers treat multiple records as a permanent error and SPF stops working entirely.',
      evidence: spf.join(' || '),
      recommendation: 'Merge them into a single v=spf1 record.',
      scoreImpact: -20,
    });
  }

  const primary = spf[0]!;
  const all = parseSpfAll(primary);

  if (all === '+all') {
    findings.push({
      id: 'dns.spf.permissive',
      title: 'SPF ends in +all',
      severity: 'high',
      status: 'fail',
      detail: '+all authorises every server on the internet to send mail as this domain. It is worse than having no SPF at all.',
      evidence: primary,
      recommendation: 'Change +all to -all and list only your real senders.',
      scoreImpact: -25,
    });
  } else if (all === '?all' || all === null) {
    findings.push({
      id: 'dns.spf.neutral',
      title: 'SPF has no enforcing policy',
      severity: 'low',
      status: 'warn',
      detail: `The record ${all ? 'ends in ?all (neutral)' : 'has no "all" mechanism'}, so unlisted senders are not challenged.`,
      evidence: primary,
      recommendation: 'End the record with -all (hard fail) or at minimum ~all (soft fail).',
      scoreImpact: -10,
    });
  } else {
    findings.push({
      id: 'dns.spf.present',
      title: 'SPF record published',
      severity: 'pass',
      status: 'pass',
      detail: `Policy ends in ${all}.`,
      evidence: primary,
      scoreImpact: all === '-all' ? 2 : 0,
    });
  }

  return { type: 'SPF', present: true, records: spf, queried: ['TXT @'] };
}

function analyseDmarc(records: string[], queried: string[], findings: Finding[]): DnsRecordCheck {
  const dmarc = records.filter((r) => r.toLowerCase().startsWith('v=dmarc1'));

  if (dmarc.length === 0) {
    findings.push({
      id: 'dns.dmarc.missing',
      title: 'No DMARC record',
      severity: 'medium',
      status: 'fail',
      detail:
        'Without DMARC there is no instruction for what a receiving server should do with mail that fails SPF or DKIM, and you get no visibility into who is spoofing you.',
      recommendation:
        'Start with _dmarc TXT: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain — read the reports, then move to p=quarantine and p=reject.',
      scoreImpact: -30,
      references: ['https://datatracker.ietf.org/doc/html/rfc7489'],
    });
    return { type: 'DMARC', present: false, records: [], queried };
  }

  const primary = dmarc[0]!;
  const policy = parseDmarcTag(primary, 'p');
  const rua = parseDmarcTag(primary, 'rua');

  if (policy === 'reject') {
    findings.push({
      id: 'dns.dmarc.reject',
      title: 'DMARC policy is p=reject',
      severity: 'pass',
      status: 'pass',
      detail: 'Spoofed mail that fails authentication is rejected outright — the strongest DMARC policy.',
      evidence: primary,
      scoreImpact: 3,
    });
  } else if (policy === 'quarantine') {
    findings.push({
      id: 'dns.dmarc.quarantine',
      title: 'DMARC policy is p=quarantine',
      severity: 'low',
      status: 'warn',
      detail: 'Failing mail goes to spam rather than being rejected. A good intermediate step.',
      evidence: primary,
      recommendation: 'Once your reports are clean, move to p=reject.',
      scoreImpact: -5,
    });
  } else if (policy === 'none') {
    findings.push({
      id: 'dns.dmarc.none',
      title: 'DMARC policy is p=none (monitoring only)',
      severity: 'medium',
      status: 'warn',
      detail: 'DMARC is published but takes no action, so spoofed mail is still delivered normally.',
      evidence: primary,
      recommendation: 'Use the aggregate reports to find your legitimate senders, then move to p=quarantine.',
      scoreImpact: -15,
    });
  } else {
    findings.push({
      id: 'dns.dmarc.invalid',
      title: 'DMARC record has no valid policy tag',
      severity: 'medium',
      status: 'warn',
      detail: 'The p= tag is missing or unrecognised, so the record is ignored.',
      evidence: primary,
      recommendation: 'Add p=none, p=quarantine or p=reject.',
      scoreImpact: -20,
    });
  }

  if (!rua) {
    findings.push({
      id: 'dns.dmarc.no-rua',
      title: 'DMARC has no reporting address',
      severity: 'info',
      status: 'info',
      detail: 'Without rua= you never receive the aggregate reports that show who is sending as your domain.',
      recommendation: 'Add rua=mailto:dmarc@yourdomain to the record.',
      scoreImpact: -3,
    });
  }

  return { type: 'DMARC', present: true, records: dmarc, queried };
}

function analyseCaa(
  records: Array<Record<string, string | number>>,
  queried: string[],
  findings: Finding[],
): DnsRecordCheck {
  const rendered = records.map((r) => {
    const entries = Object.entries(r).filter(([key]) => key !== 'critical');
    return entries.map(([key, value]) => `${key}="${value}"`).join(' ');
  });

  if (records.length === 0) {
    findings.push({
      id: 'dns.caa.missing',
      title: 'No CAA record',
      severity: 'low',
      status: 'fail',
      detail:
        'Any public certificate authority is allowed to issue a certificate for this domain. A CAA record limits that to the CAs you actually use.',
      recommendation: 'Publish a CAA record, e.g. 0 issue "letsencrypt.org", plus an iodef address for violation reports.',
      scoreImpact: -10,
      references: ['https://datatracker.ietf.org/doc/html/rfc8659'],
    });
    return { type: 'CAA', present: false, records: [], queried };
  }

  const hasIodef = records.some((r) => 'iodef' in r);
  findings.push({
    id: 'dns.caa.present',
    title: 'CAA record published',
    severity: 'pass',
    status: 'pass',
    detail: `Certificate issuance is restricted to the listed authorities${hasIodef ? ', with a reporting address' : ''}.`,
    evidence: rendered.join(' | '),
    scoreImpact: 2,
  });

  return { type: 'CAA', present: true, records: rendered, queried };
}

export async function runDnsCheck(hostname: string): Promise<SectionReport<DnsData | null>> {
  const startedAt = Date.now();

  if (isIP(hostname)) {
    const section = errorSection('dns', 'Target is a bare IP address, so there are no DNS records to inspect.', Date.now() - startedAt);
    section.status = 'skipped';
    return section;
  }

  const baseDomain = registrableDomain(hostname);
  const res = resolver();
  const findings: Finding[] = [];

  const [a, aaaa, mx, ns, apexTxt, dmarcTxt, caaHost, caaBase] = await Promise.all([
    safe(res.resolve4(hostname)),
    safe(res.resolve6(hostname)),
    safe(res.resolveMx(baseDomain)),
    safe(res.resolveNs(baseDomain)),
    safe(res.resolveTxt(baseDomain)),
    safe(res.resolveTxt(`_dmarc.${baseDomain}`)),
    safe(res.resolveCaa(hostname)),
    hostname === baseDomain ? Promise.resolve(null) : safe(res.resolveCaa(baseDomain)),
  ]);

  // Nothing resolved at all — treat as an error rather than a wall of failures.
  if (!a && !aaaa && !ns) {
    return errorSection('dns', `No DNS records could be resolved for ${hostname}.`, Date.now() - startedAt);
  }

  const checks: DnsRecordCheck[] = [];
  checks.push(analyseSpf(flattenTxt(apexTxt), findings));
  checks.push(analyseDmarc(flattenTxt(dmarcTxt), [`TXT _dmarc.${baseDomain}`], findings));

  // DKIM: probe the well-known selectors in parallel.
  const dkimHits = await Promise.all(
    COMMON_DKIM_SELECTORS.map(async (selector) => {
      const name = `${selector}._domainkey.${baseDomain}`;
      const txt = flattenTxt(await safe(res.resolveTxt(name)));
      const record = txt.find((r) => /v=dkim1|p=[A-Za-z0-9+/]/i.test(r));
      return record ? { selector, name, record } : null;
    }),
  );
  const foundDkim = dkimHits.filter((hit): hit is NonNullable<typeof hit> => hit !== null);

  if (foundDkim.length > 0) {
    findings.push({
      id: 'dns.dkim.present',
      title: `DKIM key found (${foundDkim.map((h) => h.selector).join(', ')})`,
      severity: 'pass',
      status: 'pass',
      detail: 'At least one DKIM selector publishes a public key, so outbound mail can be cryptographically signed.',
      evidence: foundDkim.map((h) => `${h.name}: ${h.record.slice(0, 80)}…`).join(' | '),
      scoreImpact: 2,
    });
  } else {
    findings.push({
      id: 'dns.dkim.not-found',
      title: 'No DKIM key found at the common selectors',
      severity: 'info',
      status: 'info',
      detail:
        `DKIM selectors are chosen by the sender and cannot be enumerated from DNS, so this is inconclusive — we probed ${COMMON_DKIM_SELECTORS.length} well-known selectors and none answered.`,
      evidence: COMMON_DKIM_SELECTORS.join(', '),
      recommendation:
        'Confirm with your mail provider that DKIM signing is enabled and the selector is published.',
      scoreImpact: -8,
      references: ['https://datatracker.ietf.org/doc/html/rfc6376'],
    });
  }

  checks.push({
    type: 'DKIM',
    present: foundDkim.length > 0,
    records: foundDkim.map((h) => `${h.selector}: ${h.record}`),
    queried: COMMON_DKIM_SELECTORS.map((s) => `TXT ${s}._domainkey.${baseDomain}`),
    note: foundDkim.length === 0 ? 'Absence is inconclusive — selectors cannot be enumerated.' : undefined,
  });

  const caaRecords = (caaHost?.length ? caaHost : caaBase) ?? [];
  const caaQueried = [`CAA ${hostname}`];
  if (hostname !== baseDomain) caaQueried.push(`CAA ${baseDomain}`);
  checks.push(
    analyseCaa(caaRecords as unknown as Array<Record<string, string | number>>, caaQueried, findings),
  );

  if (mx && mx.length === 0) {
    findings.push({
      id: 'dns.mx.none',
      title: 'Domain has no MX records',
      severity: 'info',
      status: 'info',
      detail:
        'The domain does not receive mail. SPF and DMARC still matter: they stop attackers sending mail that appears to come from you.',
      scoreImpact: 0,
    });
  }

  const data: DnsData = {
    domain: hostname,
    baseDomain,
    a: a ?? [],
    aaaa: aaaa ?? [],
    mx: (mx ?? []).map((record) => ({ exchange: record.exchange, priority: record.priority })),
    ns: ns ?? [],
    checks,
    dkimSelectorsTried: COMMON_DKIM_SELECTORS,
  };

  const missing = checks.filter((c) => !c.present).map((c) => c.type);
  const summary =
    missing.length === 0
      ? `SPF, DKIM, DMARC and CAA are all published for ${baseDomain}.`
      : `Missing or not found for ${baseDomain}: ${missing.join(', ')}.`;

  return buildSection('dns', data, sortFindings(findings), summary, Date.now() - startedAt);
}
