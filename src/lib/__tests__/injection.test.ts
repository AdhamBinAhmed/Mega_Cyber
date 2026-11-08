/**
 * Client-side injection checks.
 *
 * These checks guess at data flow from a regex, so the tests that matter most
 * are the negative ones: a scanner that cries DOM XSS over `el.innerHTML =
 * '<b>hi</b>'` is worse than one that says nothing, because every real finding
 * it reports afterwards gets ignored.
 */

import { describe, expect, it } from 'vitest';

import {
  analyseInjection,
  cspBlocksInjectedScript,
  externalScriptUrls,
  inlineScripts,
} from '../checks/injection';
import { runContentCheck } from '../checks/content';
import type { RawResponse } from '../http';

const URL_PLAIN = new URL('https://target.test/');

function run(html: string, url: URL = URL_PLAIN, csp: string | null = null) {
  return analyseInjection(html, url, csp);
}

function ids(html: string, url?: URL, csp?: string | null): string[] {
  return run(html, url, csp).findings.map((finding) => finding.id);
}

function script(code: string): string {
  return `<html><body><script>${code}</script></body></html>`;
}

/* ------------------------------ script slicing ---------------------------- */

describe('inlineScripts', () => {
  it('ignores external scripts and data blocks', () => {
    const html =
      '<script src="/app.js"></script>' +
      '<script type="application/ld+json">{"a":1}</script>' +
      '<script type="text/template"><div></div></script>' +
      '<script>var real = 1;</script>';
    const scripts = inlineScripts(html);
    expect(scripts).toHaveLength(1);
    expect(scripts[0]!.code).toContain('var real');
  });

  it('keeps module scripts and records their offset', () => {
    const html = '<p>hi</p><script type="module">import "./a.js";</script>';
    const [found] = inlineScripts(html);
    expect(found!.code).toContain('import');
    expect(html.slice(found!.offset, found!.offset + 6)).toBe('import');
  });
});

/* -------------------------------- DOM XSS --------------------------------- */

describe('DOM sink detection', () => {
  it('flags a URL source feeding innerHTML', () => {
    const findings = run(
      script('document.getElementById("out").innerHTML = location.hash.slice(1);'),
    ).findings;
    const finding = findings.find((entry) => entry.id.startsWith('injection.dom.xss'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
    expect(finding!.title).toContain('location.hash');
    expect(finding!.scoreImpact).toBeLessThan(0);
  });

  it('catches the source when it arrives through a variable', () => {
    const findings = ids(
      script('var raw = location.search; var el = document.body; el.innerHTML = raw;'),
    );
    expect(findings.some((id) => id.startsWith('injection.dom.xss'))).toBe(true);
  });

  it('treats location assignment as an open redirect, not XSS', () => {
    const findings = run(
      script('location.href = new URLSearchParams(location.search).get("next");'),
    ).findings;
    const finding = findings.find((entry) => entry.id.startsWith('injection.dom.redirect'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('medium');
  });

  it('does not accuse a sink with a static value', () => {
    const findings = ids(script('document.getElementById("out").innerHTML = "<b>hello</b>";'));
    expect(findings).toContain('injection.dom.sinks-present');
    expect(findings.some((id) => id.startsWith('injection.dom.xss'))).toBe(false);
  });

  it('downgrades to a pointer when source and sink share only a script', () => {
    const distance = '\n'.repeat(40) + 'var x = 1;'.repeat(60);
    const findings = ids(
      script(`var from = document.referrer;${distance}document.body.innerHTML = "static";`),
    );
    expect(findings).toContain('injection.dom.sink-and-source');
    expect(findings.some((id) => id.startsWith('injection.dom.xss'))).toBe(false);
  });

  it('passes a page whose inline script has no sinks', () => {
    const findings = ids(script('document.body.textContent = location.hash;'));
    expect(findings).toContain('injection.dom.none');
  });

  it('collapses repeated use of one sink into a single finding', () => {
    const line = 'row.innerHTML = location.hash;\n';
    const xss = ids(script(line.repeat(8))).filter((id) => id.startsWith('injection.dom.xss'));
    expect(xss).toHaveLength(1);
  });

  it('does not match eval on a property named eval', () => {
    const findings = ids(script('var out = api.eval(location.hash); out.toString();'));
    expect(findings.some((id) => id.includes('eval'))).toBe(false);
  });
});

/* ----------------------------- CSP mitigation ----------------------------- */

describe('cspBlocksInjectedScript', () => {
  it('accepts a nonce policy and rejects an unsafe-inline one', () => {
    expect(cspBlocksInjectedScript("script-src 'nonce-abc123'")).toBe(true);
    expect(cspBlocksInjectedScript("script-src 'sha256-abc' 'strict-dynamic'")).toBe(true);
    expect(cspBlocksInjectedScript("script-src 'nonce-abc' 'unsafe-inline'")).toBe(false);
    expect(cspBlocksInjectedScript("script-src 'self'")).toBe(false);
    expect(cspBlocksInjectedScript(null)).toBe(false);
  });

  it('falls back to default-src', () => {
    expect(cspBlocksInjectedScript("default-src 'nonce-xyz'")).toBe(true);
  });

  it('demotes DOM findings one level and says why', () => {
    const html = script('document.body.innerHTML = location.hash;');
    const finding = run(html, URL_PLAIN, "script-src 'nonce-abc'").findings.find((entry) =>
      entry.id.startsWith('injection.dom.xss'),
    )!;
    expect(finding.severity).toBe('medium');
    expect(finding.detail).toContain('nonce');
    expect(run(html, URL_PLAIN, "script-src 'nonce-abc'").data.cspMitigates).toBe(true);
  });
});

/* ------------------------------- postMessage ------------------------------ */

describe('postMessage listeners', () => {
  it('flags a handler that never looks at the origin', () => {
    const findings = run(
      script('window.addEventListener("message", function (e) { render(e.data); });'),
    ).findings;
    const finding = findings.find((entry) => entry.id === 'injection.postmessage.no-origin-check');
    expect(finding?.severity).toBe('medium');
  });

  it('passes a handler that checks the origin', () => {
    const findings = ids(
      script(
        'window.addEventListener("message", function (e) {' +
          ' if (e.origin !== "https://trusted.test") return; render(e.data); });',
      ),
    );
    expect(findings).toContain('injection.postmessage.checked');
    expect(findings).not.toContain('injection.postmessage.no-origin-check');
  });
});

/* ------------------------- markup-level observations ---------------------- */

describe('markup observations', () => {
  it('reports javascript: URIs but ignores void(0) placeholders', () => {
    expect(ids('<a href="javascript:doThing(1)">x</a>')).toContain('injection.javascript-uri');
    expect(ids('<a href="javascript:void(0)">x</a>')).not.toContain('injection.javascript-uri');
  });

  it('does not read javascript: out of inline script bodies', () => {
    expect(ids(script('var tpl = \'<a href="javascript:x()">\';'))).not.toContain(
      'injection.javascript-uri',
    );
  });

  it('counts inline event handlers once there are enough to matter', () => {
    const few = '<button onclick="a()">x</button>'.repeat(3);
    const many = '<button onclick="a()">x</button>'.repeat(6);
    expect(ids(few)).not.toContain('injection.inline-handlers');
    expect(ids(many)).toContain('injection.inline-handlers');
  });

  it('flags document.domain writes', () => {
    expect(ids(script('document.domain = "target.test";'))).toContain(
      'injection.document-domain',
    );
  });
});

/* --------------------------- reflected parameters ------------------------- */

describe('reflected parameters', () => {
  const withQuery = (query: string) => new URL(`https://target.test/search?${query}`);

  it('proves missing encoding when special characters come back intact', () => {
    const value = '"><b>test';
    const url = withQuery(`q=${encodeURIComponent(value)}`);
    const finding = run(`<p>No results for ${value}</p>`, url).findings.find(
      (entry) => entry.id === 'injection.reflected.unencoded',
    );
    expect(finding?.severity).toBe('medium');
  });

  it('raises severity when the reflection lands inside script', () => {
    const value = '";alert(1);//';
    const url = withQuery(`q=${encodeURIComponent(value)}`);
    const finding = run(script(`var q = "${value}";`), url).findings.find(
      (entry) => entry.id === 'injection.reflected.unencoded',
    );
    expect(finding?.severity).toBe('high');
  });

  it('only notes a benign reflection, without claiming a bug', () => {
    const findings = run('<p>No results for widgets</p>', withQuery('q=widgets')).findings;
    const finding = findings.find((entry) => entry.id === 'injection.reflected.observed');
    expect(finding?.severity).toBe('info');
    expect(finding?.scoreImpact).toBe(0);
  });

  it('ignores parameters that are not reflected, numeric, or too short', () => {
    expect(ids('<p>nothing here</p>', withQuery('page=2&id=12345&q=absent'))).not.toContain(
      'injection.reflected.observed',
    );
  });
});

/* ------------------------------- CSRF tokens ------------------------------ */

describe('CSRF token presence', () => {
  const form = (inner: string, method = 'post') =>
    `<form method="${method}" action="/do">${inner}<button>go</button></form>`;

  it('flags a POST form with no hidden token', () => {
    const findings = ids(form('<input name="email">'));
    expect(findings).toContain('injection.csrf.no-token');
  });

  it('accepts a recognised token field', () => {
    expect(ids(form('<input type="hidden" name="csrf_token" value="x">'))).not.toContain(
      'injection.csrf.no-token',
    );
    expect(ids(form('<input type="hidden" name="authenticity_token" value="x">'))).not.toContain(
      'injection.csrf.no-token',
    );
  });

  it('ignores GET forms', () => {
    expect(ids(form('<input name="q">', 'get'))).not.toContain('injection.csrf.no-token');
  });
});

/* ------------------------- integration with the section ------------------- */

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

describe('content section integration', () => {
  it('carries injection findings and data into the content section', () => {
    const section = runContentCheck(
      page(script('document.body.innerHTML = location.hash;')),
    );
    expect(section.findings.some((finding) => finding.id.startsWith('injection.dom.xss'))).toBe(
      true,
    );
    expect(section.data.injection.inlineScriptCount).toBe(1);
    expect(section.data.injection.cspMitigates).toBe(false);
    expect(section.summary).toContain('DOM XSS');
    expect(section.score).toBeLessThan(100);
  });

  it('reads the CSP off the response it already has', () => {
    const section = runContentCheck(
      page(script('document.body.innerHTML = location.hash;'), {
        'content-security-policy': "script-src 'nonce-abc'",
      }),
    );
    expect(section.data.injection.cspMitigates).toBe(true);
  });

  it('leaves a clean page with a clean summary', () => {
    const section = runContentCheck(page(script('document.body.textContent = "hi";')));
    expect(section.summary).toContain('No credential leaks');
    expect(section.findings.some((finding) => finding.severity === 'high')).toBe(false);
  });
});

/* ------------------------- external script files -------------------------- */

describe('externalScriptUrls', () => {
  it('collects same-origin script files, deduplicated and in order', () => {
    const html =
      '<script src="/a.js"></script>' +
      '<script src="https://target.test/b.js"></script>' +
      '<script src="/a.js"></script>';
    expect(externalScriptUrls(html, URL_PLAIN)).toEqual([
      'https://target.test/a.js',
      'https://target.test/b.js',
    ]);
  });

  it('leaves third-party, inline, data: and non-JavaScript tags alone', () => {
    const html =
      '<script src="https://cdn.other.test/x.js"></script>' +
      '<script src="data:text/javascript,alert(1)"></script>' +
      '<script type="application/ld+json" src="/ld.json"></script>' +
      '<script>var inline = 1;</script>';
    expect(externalScriptUrls(html, URL_PLAIN)).toEqual([]);
  });
});

describe('DOM sinks in the site’s own script files', () => {
  const page = '<html><body><script src="/static/app.js"></script></body></html>';

  it('finds a sink that only exists in a fetched script file', () => {
    const result = analyseInjection(page, URL_PLAIN, null, [
      {
        url: 'https://target.test/static/app.js',
        code: 'function boot() {\n  document.body.innerHTML = location.hash.slice(1);\n}',
      },
    ]);
    const finding = result.findings.find((entry) => entry.id.startsWith('injection.dom.xss'));
    expect(finding).toBeDefined();
    expect(finding!.severity).toBe('high');
    // Named by file and line, or the developer cannot find it.
    expect(finding!.evidence).toContain('app.js line ~2');
    expect(result.data.domSinks[0]!.file).toBe('https://target.test/static/app.js');
    expect(result.data.domSinks[0]!.line).toBe(2);
    expect(result.data.externalScriptsAnalysed).toBe(1);
    expect(result.data.externalScriptBytes).toBeGreaterThan(0);
  });

  it('still numbers inline sinks against the document', () => {
    const html = '<html>\n<body>\n<script>\ndocument.body.innerHTML = location.hash;\n</script>';
    const sink = analyseInjection(html, URL_PLAIN, null).data.domSinks[0]!;
    expect(sink.file).toBeNull();
    expect(sink.line).toBe(4);
  });

  it('reads postMessage listeners and document.domain writes out of script files', () => {
    const ids = analyseInjection(page, URL_PLAIN, null, [
      {
        url: 'https://target.test/static/app.js',
        code: 'window.addEventListener("message", function (e) { render(e.data); });\ndocument.domain = "target.test";',
      },
    ]).findings.map((finding) => finding.id);
    expect(ids).toContain('injection.postmessage.no-origin-check');
    expect(ids).toContain('injection.document-domain');
  });

  it('counts the bytes it read in the passing finding', () => {
    const result = analyseInjection(page, URL_PLAIN, null, [
      { url: 'https://target.test/static/app.js', code: 'export const safe = 1;' },
    ]);
    const pass = result.findings.find((finding) => finding.id === 'injection.dom.none')!;
    expect(pass.severity).toBe('pass');
    expect(pass.detail).toContain('same-origin script file');
    expect(pass.scoreImpact).toBeGreaterThan(0);
  });
});

describe('coverage honesty when script files were not read', () => {
  const page =
    '<html><body><script src="/a.js"></script><script src="/b.js"></script></body></html>';

  it('says which files it did not read', () => {
    const result = analyseInjection(page, URL_PLAIN, null, [], [
      'https://target.test/a.js',
      'https://target.test/b.js',
    ]);
    const note = result.findings.find((finding) => finding.id === 'injection.dom.not-analysed');
    expect(note).toBeDefined();
    expect(note!.evidence).toContain('https://target.test/a.js');
    expect(result.data.externalScriptsSkipped).toBe(2);
  });

  it('awards no pass credit for a clean result over part of the code', () => {
    const partial = analyseInjection(
      page,
      URL_PLAIN,
      null,
      [{ url: 'https://target.test/a.js', code: 'export const safe = 1;' }],
      ['https://target.test/b.js'],
    );
    const pass = partial.findings.find((finding) => finding.id === 'injection.dom.none')!;
    expect(pass.scoreImpact).toBe(0);
    expect(pass.title).toContain('script that was read');
  });

  it('claims nothing at all when there was no script to read', () => {
    const result = analyseInjection(page, URL_PLAIN, null, [], [
      'https://target.test/a.js',
      'https://target.test/b.js',
    ]);
    expect(result.findings.map((finding) => finding.id)).not.toContain('injection.dom.none');
  });
});

/* --------------------- precision against bundled code --------------------- */

describe('false positives that minified bundles produce', () => {
  const page = '<html><body><script src="/app.js"></script></body></html>';

  function bundle(code: string) {
    return analyseInjection(page, URL_PLAIN, null, [
      { url: 'https://target.test/app.js', code },
    ]);
  }

  it('does not read a location assignment as its own source', () => {
    // location.href is both sink and source. Matching the sink text as the
    // source turns every static redirect in the codebase into a finding.
    const result = bundle('function go(){ window.location.href = "/palestine"; }');
    const redirect = result.findings.find((finding) => finding.id.includes('dom.redirect'));
    expect(redirect).toBeUndefined();
    expect(result.data.domSinks[0]!.proximity).not.toBe('expression');
  });

  it('still flags a navigation target that really is built from the URL', () => {
    const result = bundle('location.href = location.hash.slice(1);');
    expect(result.findings.some((finding) => finding.id.includes('dom.redirect'))).toBe(true);
    expect(result.data.domSinks.some((sink) => sink.proximity === 'expression')).toBe(true);
  });

  it('drops the same-script tier inside a minified file', () => {
    // A framework runtime: a sink and a URL read, tens of kilobytes apart on
    // one line. Reporting that as a lead means reporting it for every site
    // that ships React.
    const filler = 'var a=1;'.repeat(4000);
    const result = bundle(`${filler}e.innerHTML=t;${filler}var u=location.href;${filler}`);
    expect(result.findings.map((finding) => finding.id)).not.toContain(
      'injection.dom.sink-and-source',
    );
    expect(result.data.domSinks.every((sink) => sink.proximity !== 'script')).toBe(true);
  });

  it('keeps the same-script tier in readable code', () => {
    // Far enough apart not to share an expression, but readable code, so
    // "same script" is still a pointer worth tracing.
    const gap = Array.from({ length: 40 }, (_, i) => `var pad${i} = ${i};`).join('\n');
    const result = bundle(
      `var raw = location.search;\n${gap}\nfunction render(v) {\n  document.body.innerHTML = v;\n}\n`,
    );
    expect(result.findings.map((finding) => finding.id)).toContain(
      'injection.dom.sink-and-source',
    );
  });

  it('ignores a MessageChannel port, which no other window can post to', () => {
    const result = bundle(
      'var ch = new MessageChannel(), p = ch.port2; ch.port1.onmessage = flush;',
    );
    expect(result.findings.map((finding) => finding.id)).not.toContain(
      'injection.postmessage.no-origin-check',
    );
    expect(result.data.postMessageListeners).toBe(0);
  });

  it('still flags a real window message listener', () => {
    const result = bundle('window.addEventListener("message", function (e) { use(e.data); });');
    expect(result.findings.map((finding) => finding.id)).toContain(
      'injection.postmessage.no-origin-check',
    );
  });
});
