/**
 * Fetching the site's own script files for the DOM XSS scan.
 *
 * This exists because the check it feeds was previously blind to every
 * bundled app: all of their client code lives in files, so an inline-only
 * scan reported "no DOM XSS sinks" after reading nothing. The tests below
 * drive a real HTTP server, because the parts worth getting wrong are the
 * boundaries — the file cap, the request reserve, and what counts as script.
 */

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

let server: Server;
let origin: string;
/** Paths requested, so the tests can assert what was and was not fetched. */
let requested: string[] = [];

const SCRIPT_BODY = 'document.body.innerHTML = location.hash.slice(1);';

beforeAll(async () => {
  server = createServer((req, res) => {
    requested.push(req.url ?? '');
    if (req.url === '/missing.js') {
      res.writeHead(404, { 'content-type': 'text/html' });
      res.end('<html>not found</html>');
      return;
    }
    if (req.url === '/not-script.js') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end('<html>an error page under a .js name</html>');
      return;
    }
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end(SCRIPT_BODY);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
});

afterEach(() => {
  requested = [];
  vi.unstubAllEnvs();
  vi.resetModules();
});

/** Load scan.ts with the given environment, since config reads env on import. */
async function load(env: Record<string, string>) {
  // The SSRF guard refuses loopback unless development explicitly allows it,
  // and the test server is on 127.0.0.1.
  vi.stubEnv('ALLOW_PRIVATE_TARGETS', '1');
  for (const [key, value] of Object.entries(env)) vi.stubEnv(key, value);
  vi.resetModules();
  const [{ fetchOwnScripts }, { RequestBudget }] = await Promise.all([
    import('../scan'),
    import('../budget'),
  ]);
  return { fetchOwnScripts, RequestBudget };
}

function page(...srcs: string[]): string {
  return `<html><body>${srcs.map((src) => `<script src="${src}"></script>`).join('')}</body></html>`;
}

describe('fetchOwnScripts', () => {
  it('reads the code of same-origin script files', async () => {
    const { fetchOwnScripts, RequestBudget } = await load({ SCAN_SCRIPT_FETCH_RESERVE: '0' });
    const result = await fetchOwnScripts(
      page('/app.js', '/vendor.js'),
      new URL(`${origin}/`),
      new RequestBudget(10),
    );
    expect(result.scripts.map((file) => file.url)).toEqual([
      `${origin}/app.js`,
      `${origin}/vendor.js`,
    ]);
    expect(result.scripts[0]!.code).toBe(SCRIPT_BODY);
    expect(result.skipped).toEqual([]);
  });

  it('never touches a third-party script host', async () => {
    const { fetchOwnScripts, RequestBudget } = await load({ SCAN_SCRIPT_FETCH_RESERVE: '0' });
    const result = await fetchOwnScripts(
      page('https://cdn.example.test/analytics.js'),
      new URL(`${origin}/`),
      new RequestBudget(10),
    );
    expect(result.scripts).toEqual([]);
    expect(result.skipped).toEqual([]);
    expect(requested).toEqual([]);
  });

  it('stops at the per-scan file cap and names what it left', async () => {
    const { fetchOwnScripts, RequestBudget } = await load({
      SCAN_MAX_SCRIPT_FILES: '2',
      SCAN_SCRIPT_FETCH_RESERVE: '0',
    });
    const result = await fetchOwnScripts(
      page('/a.js', '/b.js', '/c.js'),
      new URL(`${origin}/`),
      new RequestBudget(10),
    );
    expect(result.scripts).toHaveLength(2);
    expect(result.skipped).toEqual([`${origin}/c.js`]);
    expect(requested).toEqual(['/a.js', '/b.js']);
  });

  it('leaves the request reserve for the checks that follow', async () => {
    const { fetchOwnScripts, RequestBudget } = await load({ SCAN_SCRIPT_FETCH_RESERVE: '20' });
    // Exactly the reserve left: nothing may be spent on script files.
    const budget = new RequestBudget(20);
    const result = await fetchOwnScripts(page('/a.js'), new URL(`${origin}/`), budget);
    expect(result.scripts).toEqual([]);
    expect(result.skipped).toEqual([`${origin}/a.js`]);
    expect(requested).toEqual([]);
    expect(budget.used).toBe(0);
  });

  it('does not treat an error page or an HTML response as script', async () => {
    const { fetchOwnScripts, RequestBudget } = await load({ SCAN_SCRIPT_FETCH_RESERVE: '0' });
    const result = await fetchOwnScripts(
      page('/missing.js', '/not-script.js', '/real.js'),
      new URL(`${origin}/`),
      new RequestBudget(10),
    );
    expect(result.scripts.map((file) => file.url)).toEqual([`${origin}/real.js`]);
    expect(result.skipped).toEqual([`${origin}/missing.js`, `${origin}/not-script.js`]);
  });

  it('hands the fetched code to the DOM XSS check, which names the file', async () => {
    const { fetchOwnScripts, RequestBudget } = await load({ SCAN_SCRIPT_FETCH_RESERVE: '0' });
    const { runContentCheck } = await import('../checks/content');

    const html = page('/app.js');
    const fetched = await fetchOwnScripts(html, new URL(`${origin}/`), new RequestBudget(10));
    const section = runContentCheck(
      {
        url: `${origin}/`,
        status: 200,
        statusText: 'OK',
        headers: {},
        rawHeaders: {},
        body: html,
        bodyBytes: html.length,
        truncated: false,
        remoteAddress: '127.0.0.1',
        tls: null,
        durationMs: 5,
      },
      fetched.scripts,
      fetched.skipped,
    );

    const finding = section.findings.find((entry) => entry.id.startsWith('injection.dom.xss'));
    expect(finding).toBeDefined();
    expect(finding!.evidence).toContain('app.js line ~1');
    expect(section.data.injection.externalScriptsAnalysed).toBe(1);
    expect(section.data.injection.externalScriptsSkipped).toBe(0);
  });
});
