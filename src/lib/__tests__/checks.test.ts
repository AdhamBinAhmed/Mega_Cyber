/**
 * Check logic that does not need the network: header parsing, certificate
 * hostname matching, and fingerprint/CVE correlation.
 */

import { describe, expect, it } from 'vitest';

import { hstsMaxAge, parseCsp, parseSetCookie } from '../checks/headers';
import { hostnameMatchesCert } from '../checks/tls';
import {
  detectTechnologies,
  matchVulnerabilities,
  runFingerprintCheck,
  versionFromScriptUrls,
} from '../checks/fingerprint';
import type { RawResponse } from '../http';

describe('parseCsp', () => {
  it('splits directives and their values', () => {
    const csp = parseCsp("default-src 'self'; script-src 'self' 'unsafe-inline' cdn.example.com");
    expect(csp.get('default-src')).toEqual(["'self'"]);
    expect(csp.get('script-src')).toEqual(["'self'", "'unsafe-inline'", 'cdn.example.com']);
  });

  it('handles a valueless directive and odd spacing', () => {
    const csp = parseCsp('  upgrade-insecure-requests ;   object-src   none  ');
    expect(csp.has('upgrade-insecure-requests')).toBe(true);
    expect(csp.get('object-src')).toEqual(['none']);
  });

  it('keeps the first occurrence of a repeated directive, as browsers do', () => {
    const csp = parseCsp("script-src 'self'; script-src 'none'");
    expect(csp.get('script-src')).toEqual(["'self'"]);
  });
});

describe('hstsMaxAge', () => {
  it('reads max-age in its common spellings', () => {
    expect(hstsMaxAge('max-age=31536000')).toBe(31536000);
    expect(hstsMaxAge('max-age=31536000; includeSubDomains; preload')).toBe(31536000);
    expect(hstsMaxAge('max-age = 600')).toBe(600);
    expect(hstsMaxAge('max-age="600"')).toBe(600);
    expect(hstsMaxAge('includeSubDomains')).toBeNull();
  });

  it('distinguishes a disabled policy from a missing one', () => {
    expect(hstsMaxAge('max-age=0')).toBe(0);
  });
});

describe('parseSetCookie', () => {
  it('reads the security attributes', () => {
    const cookies = parseSetCookie([
      'session=abc; Path=/; Secure; HttpOnly; SameSite=Lax',
      'tracking=xyz; Path=/',
    ]);
    expect(cookies[0]).toMatchObject({
      name: 'session',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
    });
    expect(cookies[1]).toMatchObject({
      name: 'tracking',
      secure: false,
      httpOnly: false,
      sameSite: null,
    });
  });
});

describe('hostnameMatchesCert', () => {
  it('matches exact names', () => {
    expect(hostnameMatchesCert('example.com', ['example.com', 'www.example.com'], null)).toBe(true);
    expect(hostnameMatchesCert('api.example.com', ['example.com'], null)).toBe(false);
  });

  it('matches a wildcard across exactly one label', () => {
    expect(hostnameMatchesCert('www.example.com', ['*.example.com'], null)).toBe(true);
    expect(hostnameMatchesCert('a.b.example.com', ['*.example.com'], null)).toBe(false);
    expect(hostnameMatchesCert('example.com', ['*.example.com'], null)).toBe(false);
  });

  it('falls back to the common name when there are no SANs', () => {
    expect(hostnameMatchesCert('example.com', [], 'example.com')).toBe(true);
    expect(hostnameMatchesCert('example.com', [], 'other.com')).toBe(false);
  });
});

describe('versionFromScriptUrls', () => {
  it('reads versions from the shapes real sites use', () => {
    expect(versionFromScriptUrls('<script src="/js/jquery-3.4.1.min.js">', 'jquery')).toBe('3.4.1');
    expect(
      versionFromScriptUrls('<script src="https://cdn.x.com/jquery/3.3.1/jquery.min.js">', 'jquery'),
    ).toBe('3.3.1');
    expect(
      versionFromScriptUrls('<script src="/wp-includes/js/jquery.js?ver=1.12.4">', 'jquery'),
    ).toBe('1.12.4');
  });

  it('returns null when no version is present', () => {
    expect(versionFromScriptUrls('<script src="/js/jquery.min.js">', 'jquery')).toBeNull();
  });
});

describe('detectTechnologies', () => {
  it('reads a CMS and version from the generator meta tag', () => {
    const html = '<meta name="generator" content="WordPress 5.8.1" />';
    const tech = detectTechnologies(html, {}, []);
    const wp = tech.find((t) => t.name === 'WordPress');
    expect(wp?.version).toBe('5.8.1');
    expect(wp?.category).toBe('cms');
  });

  it('reads the server and language from headers', () => {
    const tech = detectTechnologies('', {
      server: 'Apache/2.4.49 (Unix)',
      'x-powered-by': 'PHP/7.4.3',
    }, []);
    expect(tech.find((t) => t.name === 'Apache')?.version).toBe('2.4.49');
    expect(tech.find((t) => t.name === 'PHP')?.version).toBe('7.4.3');
  });

  it('identifies a framework from cookie names alone', () => {
    const tech = detectTechnologies('', {}, ['laravel_session', 'XSRF-TOKEN']);
    expect(tech.some((t) => t.name === 'Laravel')).toBe(true);
  });

  it('prefers the sighting that carries a version', () => {
    const html = '<div data-reactroot></div><script src="/react-17.0.2.min.js"></script>';
    const tech = detectTechnologies(html, {}, []);
    expect(tech.find((t) => t.name === 'React')?.version).toBe('17.0.2');
  });

  it('reads an Angular version from ng-version', () => {
    const tech = detectTechnologies('<app-root ng-version="16.2.0"></app-root>', {}, []);
    expect(tech.find((t) => t.name === 'Angular')?.version).toBe('16.2.0');
  });
});

describe('matchVulnerabilities', () => {
  it('flags a jQuery version inside a published range', () => {
    const matches = matchVulnerabilities([
      { name: 'jQuery', category: 'library', version: '1.12.4', evidence: 'test', confidence: 'high' },
    ]);
    const cves = matches.flatMap((m) => m.cves);
    expect(cves).toContain('CVE-2020-11022');
    expect(cves).toContain('CVE-2019-11358');
    expect(matches.some((m) => m.endOfLife)).toBe(true);
  });

  it('does not flag a patched version', () => {
    const matches = matchVulnerabilities([
      { name: 'jQuery', category: 'library', version: '3.7.1', evidence: 'test', confidence: 'high' },
    ]);
    expect(matches).toHaveLength(0);
  });

  it('respects the introducedIn bound', () => {
    // CVE-2021-41773 applies to 2.4.49/2.4.50 only, not to 2.4.41.
    const vulnerable = matchVulnerabilities([
      { name: 'Apache', category: 'server', version: '2.4.49', evidence: 't', confidence: 'high' },
    ]);
    expect(vulnerable.flatMap((m) => m.cves)).toContain('CVE-2021-41773');

    const older = matchVulnerabilities([
      { name: 'Apache', category: 'server', version: '2.4.41', evidence: 't', confidence: 'high' },
    ]);
    expect(older.flatMap((m) => m.cves)).not.toContain('CVE-2021-41773');
  });

  it('ignores components with no detected version', () => {
    expect(
      matchVulnerabilities([
        { name: 'jQuery', category: 'library', version: null, evidence: 't', confidence: 'low' },
      ]),
    ).toHaveLength(0);
  });
});

function fakeResponse(html: string, headers: Record<string, string> = {}): RawResponse {
  return {
    url: 'https://target.test/',
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

describe('runFingerprintCheck', () => {
  it('reports a vulnerable stack and drops the section score', () => {
    const html = [
      '<meta name="generator" content="WordPress 5.8.1">',
      '<script src="/wp-includes/js/jquery/jquery.js?ver=1.12.4"></script>',
      // lodash 4.17.11 carries CVE-2019-10744, published as critical.
      '<script src="https://cdn.example.com/lodash/4.17.11/lodash.min.js"></script>',
    ].join('\n');

    const section = runFingerprintCheck(fakeResponse(html, { 'x-powered-by': 'PHP/7.4.3' }));

    expect(section.status).toBe('ok');
    expect(section.score).toBeLessThan(60);
    expect(section.data.vulnerabilities.length).toBeGreaterThan(2);
    expect(section.data.generatorMeta).toBe('WordPress 5.8.1');
    expect(section.findings.some((f) => f.id === 'fingerprint.generator-disclosed')).toBe(true);

    // A version-string match is strong evidence, not proof, so nothing is
    // reported above "high" even when the published CVSS is critical.
    expect(section.findings.every((f) => f.severity !== 'critical')).toBe(true);
    expect(section.data.vulnerabilities.some((v) => v.severity === 'critical')).toBe(true);
  });

  it('passes a clean modern stack', () => {
    const section = runFingerprintCheck(
      fakeResponse('<div id="__next"></div><script src="/_next/static/chunks/main.js"></script>'),
    );
    expect(section.score).toBe(100);
    expect(section.data.vulnerabilities).toHaveLength(0);
    expect(section.data.technologies.some((t) => t.name === 'Next.js')).toBe(true);
  });
});

describe('WordPress version detection', () => {
  it('prefers the generator tag and keeps a pre-release suffix', () => {
    const tech = detectTechnologies(
      '<meta name="generator" content="WordPress 7.2-beta4-65268" />',
      {},
      [],
    );
    expect(tech.find((t) => t.name === 'WordPress')?.version).toBe('7.2-beta4-65268');
  });

  it('does not mistake a bundled library version for the core version', () => {
    // jQuery 3.7.1 also lives under /wp-includes/ with a ?ver= parameter. A
    // loose rule reads that as "WordPress 3.7.1" and then matches it against
    // the wrong advisories entirely.
    const html =
      '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>' +
      '<link href="/wp-includes/css/dashicons.min.css?ver=6.4.2" rel="stylesheet">';
    const tech = detectTechnologies(html, {}, []);
    expect(tech.find((t) => t.name === 'WordPress')?.version).toBe('6.4.2');
    expect(tech.find((t) => t.name === 'jQuery')?.version).toBe('3.7.1');
  });

  it('still detects WordPress with no version when only generic paths are present', () => {
    const tech = detectTechnologies('<img src="/wp-content/uploads/a.png">', {}, []);
    const wp = tech.find((t) => t.name === 'WordPress');
    expect(wp).toBeDefined();
    expect(wp?.version).toBeNull();
  });
});
