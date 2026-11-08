import { describe, expect, it } from 'vitest';

import type { Finding, ScanSections, SectionReport } from '../types';
import {
  MAX_BONUS,
  buildSection,
  computeOverall,
  errorSection,
  gradeFor,
  scoreFindings,
} from '../scoring';
import { compareVersions, inRange, lessThan, parseVersion } from '../version';

function finding(impact: number, severity: Finding['severity'] = 'medium'): Finding {
  return {
    id: `test.${impact}.${severity}`,
    title: 'test',
    severity,
    status: severity === 'pass' ? 'pass' : 'fail',
    detail: 'test',
    scoreImpact: impact,
  };
}

describe('gradeFor', () => {
  it('maps the band boundaries', () => {
    expect(gradeFor(100)).toBe('A+');
    expect(gradeFor(95)).toBe('A+');
    expect(gradeFor(94)).toBe('A');
    expect(gradeFor(85)).toBe('A');
    expect(gradeFor(84)).toBe('B');
    expect(gradeFor(75)).toBe('B');
    expect(gradeFor(65)).toBe('C');
    expect(gradeFor(50)).toBe('D');
    expect(gradeFor(49)).toBe('F');
    expect(gradeFor(0)).toBe('F');
  });

  it('clamps out-of-range input', () => {
    expect(gradeFor(300)).toBe('A+');
    expect(gradeFor(-50)).toBe('F');
    expect(gradeFor(Number.NaN)).toBe('F');
  });
});

describe('scoreFindings', () => {
  it('starts at 100 and subtracts penalties', () => {
    expect(scoreFindings([])).toBe(100);
    expect(scoreFindings([finding(-30), finding(-10)])).toBe(60);
  });

  it('never goes below zero', () => {
    expect(scoreFindings([finding(-80), finding(-80)])).toBe(0);
  });

  it('caps how much bonuses can offset a penalty', () => {
    const bonuses = [finding(5, 'pass'), finding(5, 'pass'), finding(5, 'pass'), finding(5, 'pass')];
    // 20 points of bonus, but only MAX_BONUS of it counts.
    expect(scoreFindings([finding(-30), ...bonuses])).toBe(100 - 30 + MAX_BONUS);
  });
});

function sections(overrides: Partial<Record<keyof ScanSections, SectionReport<unknown>>>): ScanSections {
  const base = {
    headers: buildSection('headers', null, [], '', 0),
    tls: buildSection('tls', null, [], '', 0),
    dns: buildSection('dns', null, [], '', 0),
    exposure: buildSection('exposure', null, [], '', 0),
    fingerprint: buildSection('fingerprint', null, [], '', 0),
  };
  return { ...base, ...overrides } as ScanSections;
}

describe('computeOverall', () => {
  it('is a weighted mean of the section scores', () => {
    const result = computeOverall(sections({}));
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A+');
    expect(result.provisional).toBe(false);
  });

  it('renormalises weights when a section could not run', () => {
    // DNS errors out; the other four are perfect, so the score stays 100
    // rather than losing DNS's 10% outright.
    const result = computeOverall(sections({ dns: errorSection('dns', 'no nameserver') }));
    expect(result.score).toBe(100);
  });

  it('counts a pending section but flags the result provisional', () => {
    const tls = buildSection('tls', null, [finding(-50)], '', 0, 'pending');
    const result = computeOverall(sections({ tls }));
    expect(result.provisional).toBe(true);
    // 25% weight on a 50 means the overall drops, rather than ignoring TLS.
    expect(result.score).toBeLessThan(100);
  });

  it('caps the grade at F when anything is critical', () => {
    const exposure = buildSection('exposure', null, [finding(-60, 'critical')], '', 0);
    const result = computeOverall(sections({ exposure }));
    expect(result.grade).toBe('F');
    expect(result.capReason).toMatch(/critical/i);
    expect(result.headline).toMatch(/critical/i);
  });

  it('caps the grade at C for a high-severity finding', () => {
    const headers = buildSection('headers', null, [finding(-5, 'high')], '', 0);
    const result = computeOverall(sections({ headers }));
    expect(result.score).toBe(65);
    expect(result.grade).toBe('C');
  });

  it('never raises a score that is already below the cap', () => {
    // Every section at zero, with a high finding present. The cap must leave
    // the score alone rather than lifting it up to 65.
    const dead = (id: Parameters<typeof buildSection>[0]) =>
      buildSection(id, null, [finding(-100, 'high')], '', 0);
    const result = computeOverall(
      sections({
        headers: dead('headers'),
        tls: dead('tls'),
        dns: dead('dns'),
        exposure: dead('exposure'),
        fingerprint: dead('fingerprint'),
      }),
    );
    expect(result.score).toBe(0);
    expect(result.grade).toBe('F');
  });

  it('caps the grade when most of the checks could not run', () => {
    // The page could not be fetched: headers, exposure, fingerprint and
    // content all error out and only TLS and DNS are left. They are perfect,
    // but an A+ here would read as "this site is secure" when the honest
    // answer is "we could not look".
    const result = computeOverall(
      sections({
        headers: errorSection('headers', 'ETIMEDOUT'),
        exposure: errorSection('exposure', 'ETIMEDOUT'),
        fingerprint: errorSection('fingerprint', 'ETIMEDOUT'),
        content: errorSection('content', 'ETIMEDOUT'),
      }),
    );
    expect(result.score).toBe(65);
    expect(result.grade).toBe('C');
    expect(result.capReason).toMatch(/only 31% of the checks could run/i);
  });

  it('leaves a well-covered scan uncapped', () => {
    // Only DNS missing: 91% of the weight still ran, which is plenty.
    const result = computeOverall(
      sections({ content: buildSection('content', null, [], '', 0), dns: errorSection('dns', 'x') }),
    );
    expect(result.score).toBe(100);
    expect(result.grade).toBe('A+');
    expect(result.capReason).toBeNull();
  });

  it('does not lift a poor score up to the coverage cap', () => {
    const result = computeOverall(
      sections({
        headers: errorSection('headers', 'x'),
        exposure: errorSection('exposure', 'x'),
        fingerprint: errorSection('fingerprint', 'x'),
        content: errorSection('content', 'x'),
        tls: buildSection('tls', null, [finding(-80)], '', 0),
        dns: buildSection('dns', null, [finding(-80)], '', 0),
      }),
    );
    expect(result.score).toBe(20);
    expect(result.capReason).toBeNull();
  });

  it('reports F when nothing could be scored at all', () => {
    const all = sections({
      headers: errorSection('headers', 'x'),
      tls: errorSection('tls', 'x'),
      dns: errorSection('dns', 'x'),
      exposure: errorSection('exposure', 'x'),
      fingerprint: errorSection('fingerprint', 'x'),
    });
    const result = computeOverall(all);
    expect(result.grade).toBe('F');
    expect(result.headline).toMatch(/no checks completed/i);
  });
});

describe('version comparison', () => {
  it('parses loose version strings', () => {
    expect(parseVersion('v3.4.1')?.parts).toEqual([3, 4, 1]);
    expect(parseVersion('2.4')?.parts).toEqual([2, 4]);
    expect(parseVersion('4.0.0-beta.2')?.prerelease).toBe('beta.2');
    expect(parseVersion('not-a-version')).toBeNull();
  });

  it('orders versions numerically, not lexically', () => {
    expect(compareVersions('1.10.0', '1.9.0')).toBe(1);
    expect(compareVersions('2.4.49', '2.4.9')).toBe(1);
    expect(compareVersions('3.5.0', '3.5')).toBe(0);
    expect(lessThan('3.4.1', '3.5.0')).toBe(true);
    expect(lessThan('3.5.0', '3.5.0')).toBe(false);
  });

  it('sorts a pre-release below its release', () => {
    expect(compareVersions('4.0.0-beta.2', '4.0.0')).toBe(-1);
  });

  it('applies introduced/fixed ranges', () => {
    expect(inRange('3.4.1', '1.0.3', '3.5.0')).toBe(true);
    expect(inRange('3.5.0', '1.0.3', '3.5.0')).toBe(false);
    expect(inRange('1.0.0', '1.0.3', '3.5.0')).toBe(false);
    // fixedIn: null means every version in the line is affected (end of life).
    expect(inRange('1.8.3', undefined, null)).toBe(true);
    expect(inRange('garbage', undefined, null)).toBe(false);
  });
});
