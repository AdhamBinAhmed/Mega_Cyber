/**
 * Exposed-file check.
 *
 * One GET per well-known path, then a status code. The scanner never reads
 * further, never downloads a discovered repository, never follows anything it
 * finds — it tells you the door is open and leaves it alone.
 *
 * The awkward part of this check is false positives: plenty of sites answer
 * 200 with their SPA shell for every unknown path. So we first ask for a
 * guaranteed-nonexistent path to learn what "missing" looks like on this
 * server, and require a content signature before calling anything exposed.
 */

import { randomUUID } from 'node:crypto';

import type { ExposureData, ExposureResult, Finding, SectionReport, Severity } from '../types';
import { buildSection, sortFindings } from '../scoring';
import { rawRequest } from '../http';
import { config } from '../config';
import type { RequestBudget } from '../budget';
import { describeError } from '../errors';
import { EXPOSURE_PATHS, SENSITIVE_ROBOTS_PATTERNS, type ExposurePath } from '../data/exposure-paths';

/** Enough bytes to recognise a file; we deliberately do not read more. */
const PROBE_MAX_BYTES = 16 * 1024;

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: -60,
  high: -35,
  medium: -20,
  low: -10,
  info: 0,
  pass: 0,
};

/** Run tasks with a small concurrency cap so we stay polite. */
async function pool<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = cursor;
      cursor += 1;
      if (index >= items.length) return;
      results[index] = await worker(items[index]!);
    }
  });
  await Promise.all(runners);
  return results;
}

function looksLikeHtmlShell(contentType: string | null, body: string): boolean {
  if (contentType?.includes('text/html')) return true;
  return /^\s*(<!doctype html|<html[\s>])/i.test(body);
}

/** An ExposureResult plus the body we already read, for in-process reuse. */
interface ProbeOutcome {
  result: ExposureResult;
  body: string;
}

async function probe(
  base: URL,
  entry: ExposurePath,
  soft404: boolean,
  budget?: RequestBudget,
): Promise<ProbeOutcome> {
  const url = new URL(entry.path, base);
  let body = '';
  const result: ExposureResult = {
    path: entry.path,
    url: url.toString(),
    status: null,
    accessible: false,
    contentType: null,
    contentLength: null,
    signatureMatched: null,
    description: entry.description,
    severity: entry.severity,
  };

  try {
    const response = await rawRequest(url, {
      maxBytes: PROBE_MAX_BYTES,
      timeoutMs: Math.min(config.requestTimeoutMs, 6000),
      budget,
    });

    body = response.body;
    result.status = response.status;
    result.contentType = response.headers['content-type'] ?? null;
    const declaredLength = Number(response.headers['content-length']);
    result.contentLength = Number.isFinite(declaredLength) ? declaredLength : response.bodyBytes;

    if (response.status !== 200) return { result, body };

    if (entry.signatures) {
      result.signatureMatched = entry.signatures.some((pattern) => pattern.test(response.body));
      // A sensitive path answered with the site's HTML shell is a catch-all
      // route, not an exposed file.
      result.accessible =
        result.signatureMatched &&
        !(entry.severity !== 'info' && looksLikeHtmlShell(result.contentType, response.body) && !entry.positive);
    } else {
      result.accessible = !soft404;
    }
  } catch (err) {
    result.error = describeError(err);
  }

  return { result, body };
}

function parseRobots(body: string): { present: boolean; sensitiveDisallows: string[] } {
  const disallows = [...body.matchAll(/^\s*disallow\s*:\s*(\S+)/gim)]
    .map((match) => match[1]!)
    .filter((path) => path !== '/' && SENSITIVE_ROBOTS_PATTERNS.test(path));
  return { present: true, sensitiveDisallows: [...new Set(disallows)].slice(0, 20) };
}

export async function runExposureCheck(
  base: URL,
  budget?: RequestBudget,
): Promise<SectionReport<ExposureData>> {
  const startedAt = Date.now();
  const findings: Finding[] = [];

  // Learn what a 404 looks like here before trusting any 200.
  const baselinePath = `/mega-scan-probe-${randomUUID().slice(0, 12)}`;
  let baselineStatus: number | null = null;
  try {
    const baselineResponse = await rawRequest(new URL(baselinePath, base), {
      maxBytes: 4096,
      timeoutMs: Math.min(config.requestTimeoutMs, 6000),
      budget,
    });
    baselineStatus = baselineResponse.status;
  } catch {
    baselineStatus = null;
  }
  const soft404 = baselineStatus === 200;

  const outcomes = await pool(EXPOSURE_PATHS, config.exposureConcurrency, (entry) =>
    probe(base, entry, soft404, budget),
  );
  const results = outcomes.map((outcome) => outcome.result);

  if (soft404) {
    findings.push({
      id: 'exposure.soft404',
      title: 'Server answers 200 for paths that do not exist',
      severity: 'info',
      status: 'info',
      detail:
        'A request for a random path returned 200 instead of 404, which is normal for single-page apps. Results below were confirmed by matching file content, not by status code alone.',
      evidence: `GET ${baselinePath} -> 200`,
      scoreImpact: 0,
    });
  }

  for (const [index, result] of results.entries()) {
    const entry = EXPOSURE_PATHS[index]!;
    if (!result.accessible) continue;

    if (entry.positive) {
      findings.push({
        id: `exposure${entry.path.replace(/[^a-z0-9]+/gi, '.')}`,
        title: `${entry.description} is published`,
        severity: 'pass',
        status: 'pass',
        detail: 'Researchers have a documented way to report a vulnerability to you.',
        evidence: `GET ${entry.path} -> 200`,
        scoreImpact: 3,
      });
      continue;
    }

    if (entry.neutral) {
      findings.push({
        id: `exposure${entry.path.replace(/[^a-z0-9]+/gi, '.')}`,
        title: `${entry.description} is present`,
        severity: 'info',
        status: 'info',
        detail: `${entry.path} returned 200. This is expected and not a problem in itself.`,
        evidence: `GET ${entry.path} -> 200 (${result.contentType ?? 'unknown type'})`,
        scoreImpact: 0,
      });
      continue;
    }

    findings.push({
      id: `exposure${entry.path.replace(/[^a-z0-9]+/gi, '.')}`,
      title: `${entry.path} is publicly readable`,
      severity: entry.severity,
      status: 'fail',
      detail: `${entry.description}. The file returned HTTP 200 and its contents match the expected format, so it is genuinely being served.`,
      evidence: `GET ${entry.path} -> 200 (${result.contentType ?? 'unknown type'}, ${result.contentLength ?? '?'} bytes)`,
      recommendation: entry.recommendation,
      scoreImpact: SEVERITY_PENALTY[entry.severity],
      references: ['https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration'],
    });
  }

  // robots.txt detail, read from the response we already made.
  let robots: ExposureData['robots'] = null;
  const robotsIndex = EXPOSURE_PATHS.findIndex((entry) => entry.path === '/robots.txt');
  const robotsOutcome = robotsIndex >= 0 ? outcomes[robotsIndex] : undefined;
  if (robotsOutcome?.result.accessible) {
    robots = parseRobots(robotsOutcome.body);

    if (robots.sensitiveDisallows.length > 0) {
      findings.push({
        id: 'exposure.robots.sensitive',
        title: 'robots.txt advertises sensitive paths',
        severity: 'low',
        status: 'warn',
        detail:
          'Disallow entries are a public list of the paths you would rather people did not visit, which is exactly where an attacker starts looking.',
        evidence: robots.sensitiveDisallows.join(', '),
        recommendation:
          'Protect those paths with authentication instead of naming them in robots.txt.',
        scoreImpact: -5,
      });
    }
  } else {
    robots = { present: false, sensitiveDisallows: [] };
  }

  const securityTxtIndex = EXPOSURE_PATHS.findIndex(
    (entry) => entry.path === '/.well-known/security.txt',
  );
  const securityTxt = { present: securityTxtIndex >= 0 ? results[securityTxtIndex]?.accessible === true : false };

  const realExposures = results.filter((result, index) => {
    const entry = EXPOSURE_PATHS[index]!;
    return result.accessible && !entry.positive && !entry.neutral;
  });

  if (realExposures.length === 0) {
    findings.push({
      id: 'exposure.none',
      title: 'No sensitive files exposed at the well-known paths',
      severity: 'pass',
      status: 'pass',
      detail: `Checked ${EXPOSURE_PATHS.length} conventional locations; none returned readable content.`,
      scoreImpact: 0,
    });
  }

  const errored = results.filter((r) => r.error).length;
  const data: ExposureData = {
    baseline: { path: baselinePath, status: baselineStatus, soft404 },
    results,
    robots,
    securityTxt,
  };

  const summary =
    realExposures.length === 0
      ? `Clean: ${EXPOSURE_PATHS.length} well-known paths checked, nothing sensitive served.`
      : `${realExposures.length} sensitive file${realExposures.length === 1 ? '' : 's'} publicly readable.`;

  const section = buildSection(
    'exposure',
    data,
    sortFindings(findings),
    errored > 0 ? `${summary} (${errored} path${errored === 1 ? '' : 's'} could not be checked.)` : summary,
    Date.now() - startedAt,
  );
  return section;
}
