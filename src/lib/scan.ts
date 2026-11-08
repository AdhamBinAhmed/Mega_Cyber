/**
 * Scan orchestration: validate the target, fetch it once, then fan out to the
 * individual checks and assemble one report.
 */

import { randomUUID } from 'node:crypto';

import type { ApiErrorCode, ScanReport, ScanSections, SectionReport } from './types';
import { SCHEMA_VERSION } from './types';
import { SCANNER_NAME, SCANNER_VERSION, config } from './config';
import { computeOverall, errorSection } from './scoring';
import { describeError } from './errors';
import { parseTarget, resolveTarget } from './target';
import { rawRequest, requestFollowingRedirects, type RawResponse } from './http';
import { externalScriptUrls, type ExternalScript } from './checks/injection';
import { runHeadersCheck } from './checks/headers';
import { runDnsCheck } from './checks/dns';
import { runExposureCheck } from './checks/exposure';
import { runFingerprintCheck } from './checks/fingerprint';
import { runTlsCheck } from './checks/tls';
import { runContentCheck } from './checks/content';
import { RequestBudget, isBudgetError } from './budget';

export class ScanError extends Error {
  readonly code: ApiErrorCode;
  readonly detail: string | undefined;

  constructor(code: ApiErrorCode, message: string, detail?: string) {
    super(message);
    this.name = 'ScanError';
    this.code = code;
    this.detail = detail;
  }
}

/** Run a check with its own ceiling so one slow target cannot stall the scan. */
async function withBudget<T>(
  label: string,
  ms: number,
  work: () => Promise<T>,
): Promise<T | { __timedOut: true; label: string }> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      work(),
      new Promise<{ __timedOut: true; label: string }>((resolve) => {
        timer = setTimeout(() => resolve({ __timedOut: true, label }), ms);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function settle<T>(
  id: Parameters<typeof errorSection>[0],
  outcome: PromiseSettledResult<SectionReport<T> | { __timedOut: true; label: string }>,
): SectionReport<T | null> {
  if (outcome.status === 'rejected') {
    return errorSection(id, describeError(outcome.reason));
  }
  if ('__timedOut' in outcome.value) {
    return errorSection(id, `${outcome.value.label} did not finish within the time budget`);
  }
  return outcome.value;
}

export interface ScanOptions {
  /** Milliseconds to wait on SSL Labs before returning a pending TLS section. */
  sslLabsTimeoutMs?: number;
}

/**
 * Fetch the site's own script files so the DOM XSS scan can read them.
 *
 * Needed because a bundled app (Next, Vue, anything with a build step) keeps
 * every line of its client code in files, so an inline-only scan reports "no
 * DOM XSS sinks" on a site it never actually looked at. Deliberately bounded:
 * same-origin only, a small file cap, sequential, and spending the same
 * per-scan request budget as every other check. Whatever does not fit comes
 * back as `skipped` and is named in the report rather than quietly dropped.
 */
export async function fetchOwnScripts(
  html: string,
  base: URL,
  budget: RequestBudget,
  collector?: { ips: string[] },
): Promise<{ scripts: ExternalScript[]; skipped: string[] }> {
  const urls = externalScriptUrls(html, base);
  const scripts: ExternalScript[] = [];
  const skipped: string[] = [];

  for (const [index, url] of urls.entries()) {
    if (index >= config.maxScriptFiles || budget.remaining <= config.scriptFetchReserve) {
      skipped.push(url);
      continue;
    }
    try {
      const response = await rawRequest(
        new URL(url),
        { budget, maxBytes: config.maxScriptBytes, timeoutMs: config.scriptTimeoutMs },
        collector,
      );
      // A 404 or an HTML error page is not script; reading it would only
      // produce findings about the error template.
      const type = response.headers['content-type'] ?? '';
      if (response.status >= 400 || (type && !/javascript|ecmascript|text\/plain/i.test(type))) {
        skipped.push(url);
        continue;
      }
      scripts.push({ url: response.url, code: response.body });
    } catch {
      skipped.push(url);
    }
  }

  return { scripts, skipped };
}

export async function runScan(input: string, options: ScanOptions = {}): Promise<ScanReport> {
  const startedAt = new Date();
  const scanId = randomUUID();
  const notes: string[] = [];

  const parsed = parseTarget(input);
  if (!parsed.ok) {
    throw new ScanError(parsed.code, parsed.message);
  }

  const resolution = await resolveTarget(parsed.hostname);
  if (!resolution.ok) {
    throw new ScanError(resolution.code, resolution.message);
  }

  const resolvedIps = [...resolution.ips];
  const collector = { ips: resolvedIps };

  // One allowance for the whole scan, enforced in the HTTP client. Checks that
  // run out say so rather than silently skipping.
  const budget = new RequestBudget(config.requestBudget);

  // One fetch of the page itself; headers and fingerprinting both read it.
  let mainResponse: RawResponse | null = null;
  let redirectChain: Array<{ url: string; status: number; location: string | null }> = [];
  let fetchError: string | null = null;

  try {
    const followed = await requestFollowingRedirects(parsed.url, { budget }, collector);
    mainResponse = followed.final;
    redirectChain = followed.chain;
  } catch (err) {
    fetchError = describeError(err);
  }

  // Probe well-known paths relative to wherever the redirects landed.
  const probeBase = mainResponse ? new URL(mainResponse.url) : parsed.url;
  const tlsPort = parsed.url.protocol === 'https:' ? Number(parsed.url.port || 443) : 443;

  const timeBudget = config.totalBudgetMs;

  const [headersOutcome, dnsOutcome, exposureOutcome, tlsOutcome, scriptsOutcome] =
    await Promise.allSettled([
    mainResponse
      ? withBudget('Header analysis', timeBudget, () =>
          runHeadersCheck(parsed.url, mainResponse!, redirectChain, budget),
        )
      : Promise.reject(new Error(fetchError || 'the site did not respond')),
    withBudget('DNS lookup', Math.min(timeBudget, 15_000), () => runDnsCheck(parsed.hostname)),
    mainResponse
      ? withBudget('Exposed-file check', timeBudget, () => runExposureCheck(probeBase, budget))
      : Promise.reject(new Error(fetchError || 'the site did not respond')),
    withBudget('TLS inspection', timeBudget, () =>
      runTlsCheck(parsed.hostname, tlsPort, { sslLabsTimeoutMs: options.sslLabsTimeoutMs }),
    ),
    mainResponse
      ? withBudget('Script-file fetch', timeBudget, () =>
          fetchOwnScripts(mainResponse!.body, new URL(mainResponse!.url), budget, collector),
        )
      : Promise.resolve({ scripts: [], skipped: [] }),
  ]);

  // On a timeout or a crash here, every script file the page references counts
  // as skipped, so the DOM XSS finding says what it did not read.
  const referencedScripts = mainResponse
    ? externalScriptUrls(mainResponse.body, new URL(mainResponse.url))
    : [];
  const ownScripts =
    scriptsOutcome.status === 'fulfilled' && !('__timedOut' in scriptsOutcome.value)
      ? scriptsOutcome.value
      : { scripts: [], skipped: referencedScripts };

  const sections: ScanSections = {
    headers: settle('headers', headersOutcome),
    tls: settle('tls', tlsOutcome),
    dns: settle('dns', dnsOutcome),
    exposure: settle('exposure', exposureOutcome),
    fingerprint: mainResponse
      ? runFingerprintCheck(mainResponse)
      : errorSection('fingerprint', fetchError || 'the site did not respond'),
    content: mainResponse
      ? runContentCheck(mainResponse, ownScripts.scripts, ownScripts.skipped)
      : errorSection('content', fetchError || 'the site did not respond'),
  };

  if (fetchError) {
    notes.push(
      `The page itself could not be fetched (${fetchError}), so header, exposure and technology checks were skipped.`,
    );
  }
  if (mainResponse?.truncated) {
    notes.push(
      `Only the first ${Math.round(config.maxBodyBytes / 1024)} KB of the page was analysed.`,
    );
  }
  if (ownScripts.scripts.length > 0 || ownScripts.skipped.length > 0) {
    notes.push(
      `${ownScripts.scripts.length} of ${referencedScripts.length} same-origin script file${referencedScripts.length === 1 ? '' : 's'} were read for the DOM XSS check` +
        (ownScripts.skipped.length > 0
          ? `; the remaining ${ownScripts.skipped.length} ${ownScripts.skipped.length === 1 ? 'was' : 'were'} not, so that check does not cover ${ownScripts.skipped.length === 1 ? 'it' : 'them'}.`
          : '.'),
    );
  }
  if (sections.tls.status === 'pending') {
    notes.push(
      'The SSL Labs assessment is still running. The grade shown is provisional and will update when it finishes.',
    );
  }
  if (budget.refusedCount > 0) {
    notes.push(
      `The per-scan request allowance (${budget.limit}) was reached, so ${budget.refusedCount} check request${budget.refusedCount === 1 ? '' : 's'} were not made. The scanner caps how much traffic it will send to any one site.`,
    );
  }
  if (config.tlsLocalProbe !== 'on') {
    notes.push(`Local TLS protocol probing is set to "${config.tlsLocalProbe}".`);
  }
  notes.push(
    'All checks are passive: the scanner reads public responses only. It never attempts to exploit, authenticate, brute force, or scan ports.',
  );

  const overall = computeOverall(sections);

  // Three of the five sections depend on reading the page. If that failed, the
  // weighted score covers TLS and DNS only, and presenting it as a confident
  // grade for the site would be misleading.
  if (fetchError) {
    overall.provisional = true;
    overall.headline = `The page could not be fetched (${fetchError}) — this grade covers only the DNS and TLS checks.`;
  }

  const finishedAt = new Date();

  return {
    schemaVersion: SCHEMA_VERSION,
    scanId,
    target: {
      input,
      url: parsed.url.toString(),
      origin: parsed.url.origin,
      hostname: parsed.hostname,
      port: parsed.port,
      finalUrl: mainResponse?.url ?? null,
      resolvedIps,
    },
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    overall,
    sections,
    meta: {
      scanner: SCANNER_NAME,
      version: SCANNER_VERSION,
      passive: true,
      notes,
      requests: budget.snapshot(),
    },
  };
}
