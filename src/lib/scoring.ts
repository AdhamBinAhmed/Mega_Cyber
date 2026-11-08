/**
 * Scoring and grading.
 *
 * Modelled on Mozilla Observatory: every section starts at 100 and each finding
 * applies a modifier. Sections are then combined into one weighted score, with
 * a hard cap so a single severe finding cannot be averaged away by an otherwise
 * tidy configuration.
 *
 * This module is isomorphic — the dashboard re-runs it when the deferred SSL
 * Labs result lands, so the grade it shows always matches the API's own maths.
 */

import type {
  Finding,
  Grade,
  ScanSections,
  SectionId,
  SectionReport,
  Severity,
  SeverityCounts,
} from './types';

/**
 * How much each section contributes to the overall score. Sums to 100.
 *
 * Reweighted when the content section landed. Page content takes 15, drawn
 * mostly from headers and exposure: a leaked credential or an unpinned
 * third-party script is a more direct path to compromise than a missing
 * Permissions-Policy, and the weights should say so.
 */
export const SECTION_WEIGHTS: Record<SectionId, number> = {
  headers: 24,
  tls: 22,
  exposure: 20,
  content: 15,
  dns: 9,
  fingerprint: 10,
};

export const SECTION_TITLES: Record<SectionId, string> = {
  headers: 'HTTP Security Headers',
  tls: 'SSL / TLS',
  dns: 'DNS & Email Authentication',
  exposure: 'Exposed Files',
  fingerprint: 'Technology & Known CVEs',
  content: 'Page Content & Supply Chain',
};

const GRADE_BANDS: Array<{ min: number; grade: Grade }> = [
  { min: 95, grade: 'A+' },
  { min: 85, grade: 'A' },
  { min: 75, grade: 'B' },
  { min: 65, grade: 'C' },
  { min: 50, grade: 'D' },
  { min: 0, grade: 'F' },
];

/**
 * A severe finding caps the overall grade. Without this, a site leaking its
 * .env could still score a B on the strength of good headers — which would be
 * an actively misleading result to hand a client.
 */
const SEVERITY_CAPS: Partial<Record<Severity, { score: number; label: string }>> = {
  critical: { score: 40, label: 'critical finding' },
  high: { score: 65, label: 'high-severity finding' },
};

/**
 * Coverage cap: a grade built from a minority of the checks is not a grade.
 *
 * Renormalising the weights keeps a failed section from costing points, which
 * is right — but taken alone it means a site whose page could not be fetched
 * is graded on DNS and TLS and can come back A+, which reads as "this site is
 * secure" when the honest answer is "we could not look". Below this much
 * coverage the number is capped and the reason is shown next to it.
 */
const MIN_COVERAGE = 0.5;
const COVERAGE_CAP = 65;

const TOTAL_WEIGHT = Object.values(SECTION_WEIGHTS).reduce((sum, weight) => sum + weight, 0);

export function clampScore(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

export function gradeFor(score: number): Grade {
  const clamped = clampScore(score);
  for (const band of GRADE_BANDS) {
    if (clamped >= band.min) return band.grade;
  }
  return 'F';
}

/**
 * How much credit going beyond the baseline can earn back. Uncapped, a site
 * with an excellent CSP could collect enough bonuses to hide a missing header
 * entirely and still show 100/100 — which reads as a contradiction next to a
 * summary saying a header is missing.
 */
export const MAX_BONUS = 10;

/** Section score: start at 100, apply every finding's modifier. */
export function scoreFindings(findings: Finding[]): number {
  let penalties = 0;
  let bonuses = 0;
  for (const finding of findings) {
    if (finding.scoreImpact < 0) penalties += finding.scoreImpact;
    else bonuses += finding.scoreImpact;
  }
  return clampScore(100 + penalties + Math.min(bonuses, MAX_BONUS));
}

export function emptyCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, pass: 0 };
}

export function countSeverities(findings: Finding[]): SeverityCounts {
  const counts = emptyCounts();
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

export function allFindings(sections: ScanSections): Finding[] {
  // Tolerates a sparse object: a report saved before a check existed has no
  // entry for it, and re-grading such a report must not throw.
  return Object.values(sections ?? {}).flatMap(
    (section) => (section as SectionReport | undefined)?.findings ?? [],
  );
}

export interface OverallResult {
  score: number;
  grade: Grade;
  provisional: boolean;
  counts: SeverityCounts;
  headline: string;
  capReason: string | null;
}

/**
 * Combine the sections. Sections that errored or were skipped are left out and
 * the remaining weights are renormalised, so a failed DNS lookup lowers
 * confidence rather than silently costing the site ten points.
 *
 * A pending section still counts: the TLS section is marked pending while SSL
 * Labs finishes, but its certificate and protocol findings are already final,
 * and dropping them would swing the grade more than the missing part ever
 * could. The result is flagged provisional instead.
 */
export function computeOverall(sections: ScanSections): OverallResult {
  const list = (Object.values(sections ?? {}) as Array<SectionReport | undefined>).filter(
    (section): section is SectionReport => Boolean(section),
  );
  const scored = list.filter(
    (section) => section.status === 'ok' || section.status === 'pending',
  );
  const provisional = list.some((section) => section.status === 'pending');

  const totalWeight = scored.reduce((sum, section) => sum + section.weight, 0);
  const weighted =
    totalWeight > 0
      ? scored.reduce((sum, section) => sum + section.score * section.weight, 0) / totalWeight
      : 0;

  let score = clampScore(weighted);
  const counts = countSeverities(allFindings(sections));

  let capReason: string | null = null;
  for (const severity of ['critical', 'high'] as const) {
    const cap = SEVERITY_CAPS[severity];
    if (cap && counts[severity] > 0 && score > cap.score) {
      score = cap.score;
      const plural = counts[severity] === 1 ? '' : 's';
      capReason = `Grade capped at ${gradeFor(cap.score)} by ${counts[severity]} ${cap.label}${plural}.`;
      break;
    }
  }

  const coverage = TOTAL_WEIGHT > 0 ? totalWeight / TOTAL_WEIGHT : 0;
  if (totalWeight > 0 && coverage < MIN_COVERAGE && score > COVERAGE_CAP) {
    score = COVERAGE_CAP;
    capReason = `Grade capped at ${gradeFor(COVERAGE_CAP)}: only ${Math.round(coverage * 100)}% of the checks could run, so there is not enough evidence for a higher grade.`;
  }

  const grade = totalWeight > 0 ? gradeFor(score) : 'F';

  return {
    score,
    grade,
    provisional,
    counts,
    capReason,
    headline: headlineFor(grade, counts, totalWeight === 0),
  };
}

function headlineFor(grade: Grade, counts: SeverityCounts, noData: boolean): string {
  if (noData) return 'No checks completed — the target could not be assessed.';
  if (counts.critical > 0) {
    return counts.critical === 1
      ? 'One critical issue needs attention right now.'
      : `${counts.critical} critical issues need attention right now.`;
  }
  if (counts.high > 0) {
    return `${counts.high} high-severity issue${counts.high === 1 ? '' : 's'} to fix soon.`;
  }
  switch (grade) {
    case 'A+':
      return 'Excellent posture — the fundamentals are all in place.';
    case 'A':
      return 'Strong posture with a few things left to tighten.';
    case 'B':
      return 'Reasonable baseline, with clear room to improve.';
    case 'C':
      return 'Several standard protections are missing.';
    case 'D':
      return 'Significant gaps across the basics.';
    default:
      return 'The essentials are largely absent.';
  }
}

/** Factory for a section that could not be run. */
export function errorSection(
  id: SectionId,
  message: string,
  durationMs = 0,
): SectionReport<null> {
  return {
    id,
    title: SECTION_TITLES[id],
    status: 'error',
    score: 0,
    grade: 'F',
    weight: SECTION_WEIGHTS[id],
    summary: `Not assessed: ${message}`,
    findings: [],
    data: null,
    durationMs,
    error: message,
  };
}

/** Assemble a finished section from its findings. */
export function buildSection<T>(
  id: SectionId,
  data: T,
  findings: Finding[],
  summary: string,
  durationMs: number,
  status: 'ok' | 'pending' = 'ok',
): SectionReport<T> {
  const score = scoreFindings(findings);
  return {
    id,
    title: SECTION_TITLES[id],
    status,
    score,
    grade: gradeFor(score),
    weight: SECTION_WEIGHTS[id],
    summary,
    findings,
    data,
    durationMs,
  };
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  pass: 5,
};

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.id.localeCompare(b.id),
  );
}
