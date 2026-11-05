/**
 * Content checks, redaction and the request budget.
 *
 * The redaction tests matter most. This scanner now looks for credentials in
 * public pages, and its reports get downloaded, emailed and pasted into
 * tickets. If a found secret were echoed back verbatim, the scanner would be
 * spreading the leak it just reported.
 */

import { describe, expect, it } from 'vitest';

import { entropy, looksLikeRealSecret, maskValue, redact } from '../redact';
import { RequestBudget, BudgetExhaustedError } from '../budget';
import { findSecrets, runContentCheck } from '../checks/content';
import type { RawResponse } from '../http';

/* -------------------------------------------------------------------------- */

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const STRIPE_SECRET = 'sk_live_51H8xQ2abcdefGHIJKLmnop';

function page(html: string, headers: Record<string, string> = {}, url = 'https://target.test/'): RawResponse {
  return {
    url,
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

/* ------------------------------- redaction -------------------------------- */

describe('maskValue', () => {
  it('keeps the ends and hides the middle', () => {
    const masked = maskValue(AWS_KEY);
    expect(masked.startsWith('AKIA')).toBe(true);
    expect(masked.endsWith('MPLE')).toBe(true);
    expect(masked).not.toContain('IOSFODNN7EXA');
  });

  it('hides short values almost entirely', () => {
    expect(maskValue('abc12345')).toBe('••••••••');
    expect(maskValue('short')).not.toContain('hor');
  });
});

describe('redact', () => {
  it('masks credentials that appear in arbitrary text', () => {
    const output = redact(`error: using key ${AWS_KEY} failed`)!;
    expect(output).not.toContain(AWS_KEY);
    expect(output).toContain('AKIA');
  });

  it('masks prefixed provider tokens', () => {
    for (const token of [
      STRIPE_SECRET,
      'ghp_abcdefghijklmnopqrstuvwxyz0123456789',
      'xoxb-123456789012-abcdefghijkl',
      'npm_abcdefghijklmnopqrstuvwxyz0123456789',
    ]) {
      const output = redact(`value=${token}`)!;
      expect(output, token).not.toContain(token);
    }
  });

  it('collapses a private key block entirely', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC\n-----END RSA PRIVATE KEY-----';
    expect(redact(pem)).toBe('[private key redacted]');
  });

  it('masks Authorization and Cookie header values', () => {
    const output = redact('authorization: Bearer abcdef123456789012345')!;
    expect(output).not.toContain('abcdef123456789012345');
  });

  it('truncates very long evidence', () => {
    const output = redact('x'.repeat(5000))!;
    expect(output.length).toBeLessThan(700);
    expect(output).toContain('truncated');
  });

  it('passes undefined through', () => {
    expect(redact(undefined)).toBeUndefined();
  });
});

describe('entropy and placeholder rejection', () => {
  it('scores random strings above prose', () => {
    expect(entropy('aaaaaaaaaaaa')).toBeLessThan(1);
    expect(entropy('G7xK2pQ9zR4mT8vB')).toBeGreaterThan(3.5);
  });

  it('rejects template and placeholder values', () => {
    for (const value of [
      'YOUR_API_KEY',
      'changeme',
      'xxxxxxxxxxxx',
      '${API_KEY}',
      '{{ secret }}',
      'placeholder',
      '000000000000',
      '$API_TOKEN',
    ]) {
      expect(looksLikeRealSecret(value), value).toBe(false);
    }
  });

  it('accepts a high-entropy value', () => {
    expect(looksLikeRealSecret('G7xK2pQ9zR4mT8vB1nL6wC3j')).toBe(true);
  });
});

/* -------------------------------- secrets ---------------------------------- */

describe('findSecrets', () => {
  it('finds an AWS key and a Stripe secret key', () => {
    const hits = findSecrets(`<script>const k="${AWS_KEY}";const s="${STRIPE_SECRET}";</script>`);
    const ids = hits.map((h) => h.patternId);
    expect(ids).toContain('aws.access-key-id');
    expect(ids).toContain('stripe.secret');
    expect(hits.every((h) => h.severity === 'critical')).toBe(true);
  });

  it('never returns the raw value', () => {
    const hits = findSecrets(`key = "${AWS_KEY}"`);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.masked).not.toBe(AWS_KEY);
    expect(JSON.stringify(hits)).not.toContain(AWS_KEY);
  });

  it('classifies public-by-design keys instead of calling them leaks', () => {
    const hits = findSecrets('<script>Stripe("pk_live_51H8xQ2abcdefGHIJKL")</script>');
    expect(hits).toHaveLength(1);
    expect(hits[0]!.publicByDesign).toBe(true);
    expect(hits[0]!.severity).toBe('info');
  });

  it('treats an unrestricted-capable Google browser key as low, not critical', () => {
    const hits = findSecrets('<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyA1234567890abcdefghijklmnopqrstuv"></script>');
    expect(hits[0]?.publicByDesign).toBe(true);
    expect(hits[0]?.severity).toBe('low');
  });

  it('ignores documentation and placeholder values', () => {
    const html = [
      'apiKey = "YOUR_API_KEY_HERE"',
      'secret_key = "changeme"',
      'api_key = "${process.env.KEY}"',
      '// see https://example.com for your api_key = "abc123def456"',
    ].join('\n');
    const generic = findSecrets(html).filter((h) => h.patternId === 'generic.assignment');
    expect(generic).toHaveLength(0);
  });

  it('flags a high-entropy generic assignment', () => {
    const hits = findSecrets('const client_secret = "G7xK2pQ9zR4mT8vB1nL6wC3jX5yH0dF2"');
    expect(hits.some((h) => h.patternId === 'generic.assignment')).toBe(true);
  });

  it('caps repeats of the same pattern', () => {
    const many = Array.from({ length: 10 }, (_, i) => `AKIAIOSFODNN7EXAMPL${i}`).join('\n');
    const hits = findSecrets(many).filter((h) => h.patternId === 'aws.access-key-id');
    expect(hits.length).toBeLessThanOrEqual(3);
  });
});

/* ----------------------------- content section ----------------------------- */

describe('runContentCheck', () => {
  it('reports a leaked credential as critical and masks it in the report', () => {
    const section = runContentCheck(page(`<script>AWS="${AWS_KEY}"</script>`));
    const serialised = JSON.stringify(section);

    expect(section.findings.some((f) => f.severity === 'critical')).toBe(true);
    expect(section.score).toBeLessThan(50);
    // The whole point: the report must not carry the secret.
    expect(serialised).not.toContain(AWS_KEY);
    expect(serialised).toContain('AKIA');
  });

  it('flags third-party script without integrity', () => {
    const section = runContentCheck(
      page('<script src="https://cdn.other.test/lib.js"></script>'),
    );
    expect(section.findings.some((f) => f.id === 'content.sri.missing')).toBe(true);
    expect(section.data.scriptsWithoutIntegrity).toBe(1);
    expect(section.data.thirdPartyOrigins).toContain('https://cdn.other.test');
  });

  it('does not flag same-origin or integrity-pinned scripts', () => {
    const section = runContentCheck(
      page(
        '<script src="/local.js"></script>' +
          '<script src="https://cdn.other.test/x.js" integrity="sha384-abc" crossorigin="anonymous"></script>',
      ),
    );
    expect(section.findings.some((f) => f.id === 'content.sri.missing')).toBe(false);
    expect(section.findings.some((f) => f.id === 'content.sri.present')).toBe(true);
  });

  it('separates active from passive mixed content', () => {
    const section = runContentCheck(
      page('<script src="http://cdn.test/a.js"></script><img src="http://cdn.test/b.png">'),
    );
    const active = section.findings.find((f) => f.id === 'content.mixed.active');
    const passive = section.findings.find((f) => f.id === 'content.mixed.passive');
    expect(active?.severity).toBe('high');
    expect(passive?.severity).toBe('medium');
  });

  it('does not report mixed content on an http page', () => {
    const section = runContentCheck(
      page('<script src="http://cdn.test/a.js"></script>', {}, 'http://target.test/'),
    );
    expect(section.findings.some((f) => f.id.startsWith('content.mixed'))).toBe(false);
  });

  it('flags external target=_blank without noopener, and ignores same-origin', () => {
    const section = runContentCheck(
      page(
        '<a href="https://other.test/x" target="_blank">out</a>' +
          '<a href="/in" target="_blank">in</a>' +
          '<a href="https://ok.test/y" target="_blank" rel="noopener">safe</a>',
      ),
    );
    const finding = section.findings.find((f) => f.id === 'content.tabnabbing');
    expect(finding?.title).toContain('1 external link');
  });

  it('flags a password field served over http', () => {
    const section = runContentCheck(
      page('<form><input type="password" name="p"></form>', {}, 'http://target.test/'),
    );
    expect(
      section.findings.some((f) => f.id === 'content.form.password-over-http' && f.severity === 'critical'),
    ).toBe(true);
  });

  it('flags a form posting to plain http', () => {
    const section = runContentCheck(page('<form action="http://target.test/login"></form>'));
    expect(section.findings.some((f) => f.id === 'content.form.insecure-action')).toBe(true);
  });

  it('detects source map references', () => {
    const section = runContentCheck(page('<script>//# sourceMappingURL=/app.js.map</script>'));
    expect(section.data.sourceMaps).toContain('/app.js.map');
  });

  it('flags internal detail in HTML comments', () => {
    const section = runContentCheck(
      page('<!-- deploy target: 10.0.4.17, see staging-api.internal.test -->'),
    );
    expect(section.findings.some((f) => f.id === 'content.comments.internal')).toBe(true);
  });

  it('passes a clean page', () => {
    const section = runContentCheck(page('<html><body><h1>hello</h1></body></html>'));
    expect(section.score).toBe(100);
    expect(section.status).toBe('ok');
    expect(section.findings.every((f) => f.scoreImpact >= 0)).toBe(true);
  });
});

/* -------------------------------- budget ---------------------------------- */

describe('RequestBudget', () => {
  it('allows up to the limit then throws', () => {
    const budget = new RequestBudget(3);
    budget.claim();
    budget.claim();
    budget.claim();
    expect(() => budget.claim()).toThrow(BudgetExhaustedError);
    expect(budget.used).toBe(3);
    expect(budget.remaining).toBe(0);
    expect(budget.exhausted).toBe(true);
    expect(budget.refusedCount).toBe(1);
  });

  it('reports a snapshot for the report', () => {
    const budget = new RequestBudget(10);
    budget.claim();
    expect(budget.snapshot()).toEqual({ used: 1, limit: 10, refused: 0 });
  });
});
