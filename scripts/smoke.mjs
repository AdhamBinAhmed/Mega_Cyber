/**
 * Browser smoke test: drives the real UI in Chromium.
 *
 * This exists because of a bug that every other kind of test missed. The app's
 * own Content-Security-Policy blocked 'unsafe-eval', which Next's dev server
 * needs, so React never hydrated: the page rendered perfectly, the API worked
 * perfectly under curl, every unit test passed — and the scan button stayed
 * disabled no matter what you typed. Only a real browser sees that class of
 * failure, so it gets a real browser.
 *
 *   node scripts/smoke.mjs [baseUrl] [--scan]
 */

import { chromium } from 'playwright';

const baseUrl = process.argv.find((a) => a.startsWith('http')) ?? 'http://127.0.0.1:3000/';
const doScan = process.argv.includes('--scan');

const failures = [];
const check = (label, pass, detail = '') => {
  console.log(`  ${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`);
  if (!pass) failures.push(label);
};

const browser = await chromium.launch();
const page = await browser.newPage();

const consoleProblems = [];
page.on('console', (m) => {
  if (m.type() === 'error') consoleProblems.push(`[console] ${m.text()}`);
});
page.on('pageerror', (e) => consoleProblems.push(`[pageerror] ${e.message}`));
page.on('requestfailed', (r) =>
  consoleProblems.push(`[requestfailed] ${r.url()} :: ${r.failure()?.errorText}`),
);

console.log(`\nSmoke test against ${baseUrl}\n`);
await page.goto(baseUrl, { waitUntil: 'networkidle' });

const button = page.locator('button.shiny-cta');
const input = page.locator('input[aria-label="Website URL to scan"]');
const consent = page.locator('.consent input[type="checkbox"]');

check('button starts disabled with an empty field', await button.isDisabled());

await input.click();
await input.type('example.com', { delay: 20 });
await page.waitForTimeout(300);

// The decisive assertion: React received the keystrokes.
check('typing reaches React state', (await input.inputValue()) === 'example.com');
check('button enables once a URL is entered', !(await button.isDisabled()));

// Interactivity beyond the one control, i.e. hydration really happened.
await page.locator('button.tab', { hasText: 'Load a report' }).click();
await page.waitForTimeout(250);
check('tab switching works (page is hydrated)', await page.locator('textarea').isVisible());
await page.locator('button.tab', { hasText: 'Scan a URL' }).click();
await page.waitForTimeout(250);

// The consent gate must explain itself rather than silently doing nothing.
await button.click();
await page.waitForTimeout(350);
const alertText = await page.locator('.alert').innerText().catch(() => '');
check('submitting without consent explains why', /permission/i.test(alertText), alertText.split('\n')[0]);
check('consent box is highlighted', await page.locator('.consent-error').count() > 0);

await consent.check();
await page.waitForTimeout(200);
check('ticking consent clears the warning', (await page.locator('.alert').count()) === 0);

if (doScan) {
  await button.click();
  await page.locator('.report', { timeout: 120_000 }).waitFor({ timeout: 120_000 });
  const grade = (await page.locator('.ring-grade').innerText()).trim();
  check('a scan completes and renders a report', grade.length > 0, `grade ${grade}`);

  // Assert the sections by name rather than by count, so adding a check does
  // not fail the smoke test for the wrong reason.
  const titles = (await page.locator('.section-info h3').allInnerTexts()).map((t) =>
    t.split('\n')[0].trim(),
  );
  const expected = [
    'HTTP Security Headers',
    'SSL / TLS',
    'Page Content & Supply Chain',
    'Exposed Files',
    'DNS & Email Authentication',
    'Technology & Known CVEs',
  ];
  const missing = expected.filter((name) => !titles.includes(name));
  check('every section card renders', missing.length === 0, missing.length ? `missing: ${missing.join(', ')}` : `${titles.length} cards`);
}

check('no console errors or failed requests', consoleProblems.length === 0, consoleProblems[0] ?? '');
if (consoleProblems.length) consoleProblems.slice(0, 10).forEach((p) => console.log(`        ${p}`));

await browser.close();

console.log(
  failures.length ? `\n${failures.length} check(s) failed\n` : '\nAll checks passed\n',
);
process.exit(failures.length ? 1 : 0);
