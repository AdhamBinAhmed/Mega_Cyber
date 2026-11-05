# MEGA Devs — Passive Website Security Scanner

A free, read-only security assessment that MEGA Devs Cyber Team can embed in its
own site as a first-touch service. A visitor submits a URL they own; the scanner
reads what that site already tells the public internet and returns one graded
JSON report plus a dashboard that renders it.

Built with Next.js 15 (App Router) + TypeScript, no runtime dependencies beyond
React, and deployable to Vercel as-is.

## Brand assets

| File | Role |
|---|---|
| `public/megadevs-logo.png` | Wordmark, 1600x605 transparent PNG. Nav, footer, Open Graph image, `Organization` logo |
| `src/app/icon.png` | Favicon, 480x480 square. Next's file convention emits the `<link rel="icon">` |
| `src/app/apple-icon.png` | 180x180 touch icon |
| `public/dark_mode_img.jpg` | The original supplied file — **actually a PNG** despite the extension; kept only so the original name still resolves |

Two things worth knowing about those assets:

- **The supplied `dark_mode_img.jpg` is a PNG.** Served under a `.jpg` name it
  goes out as `Content-Type: image/jpeg`, and because this app sends
  `X-Content-Type-Options: nosniff`, a browser is entitled to refuse to render
  it. `megadevs-logo.png` is the same bytes under the correct extension, and is
  what the site references.
- **The logo needs height to stay legible.** It is a two-line lockup
  ("MEGADevs." over "Engineering Studio") at a 2.6:1 ratio, so below about 32px
  tall the tagline turns to mush. The nav uses 40px, the footer 58px.

For the logo to appear beside the site in Google results, set
`NEXT_PUBLIC_SITE_URL` to the real origin. The favicon covers the small icon
next to a result; the `Organization` JSON-LD in `src/app/layout.tsx` is what
Google reads for the larger logo in a knowledge panel. Both need absolute URLs,
which is what that variable provides.

## Design

"Red noir": pure black ground, a dark red wash, one hot accent (`#ef233c`),
Manrope for display and Inter for body, with a drifting starfield, a masked
grid, and a conic-gradient spinning border on the primary action.

Everything is self-contained by necessity, not preference. The style reference
this was built from loads Tailwind, Iconify and Google Fonts from CDNs; this app
ships a strict `default-src 'self'` CSP, and a tool whose job is to tell people
their CSP is weak cannot be the thing weakening its own. So:

- the design tokens and components live in hand-written CSS (`src/app/globals.css`)
- `next/font` downloads Manrope and Inter at **build time** and self-hosts them
  under `/_next/static`, so `font-src 'self'` holds
- icons are inline SVG (`src/components/icons.tsx`), no icon runtime

The rendered page references zero external hosts. Grades and severities keep
their own distinct scale (green → lime → amber → orange → red) so a brand-red
button is never confused with a red critical finding; `F` and `critical` share
the accent red, which in this palette simply means bad.

All of the motion is disabled under `prefers-reduced-motion`.

---

## What it checks

| Section | Weight | What it looks at |
|---|---|---|
| **HTTP security headers** | 24% | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy — plus cookie flags, version-disclosing headers, and whether HTTP redirects to HTTPS |
| **SSL / TLS** | 22% | Certificate validity, expiry, hostname coverage, chain trust, key strength; which TLS versions are accepted (1.0/1.1 flagged as weak); the Qualys SSL Labs grade |
| **Exposed files** | 20% | A GET of 12 well-known paths (`/.env`, `/.git/config`, `/wp-config.php.bak`, `/robots.txt`, …) reporting only whether each is readable |
| **DNS & email authentication** | 9% | SPF, DKIM, DMARC and CAA records via Node's built-in `dns` |
| **Technology & known CVEs** | 10% | CMS/framework/library fingerprint from meta tags, headers, cookies and script URLs, correlated against a static advisory table |
| **Page content & supply chain** | 15% | Credentials leaked in page source, Subresource Integrity gaps, mixed content, third-party script inventory, source maps, insecure forms, internal detail in comments |

## What it deliberately does not do

The scanner is passive. It issues ordinary HTTP GETs and TLS handshakes to the
public ports a browser would use, and nothing else:

- **no port scanning** — only 80/443 (or the submitted 8080/8443)
- **no exploitation** — no payloads, no injection, no traversal
- **no brute force** — no credential, directory or parameter guessing
- **no authentication** — it never logs in or submits a form
- **no action on what it finds** — a readable `/.git/config` is reported as a
  status code; the repository is never cloned, and no discovered file is read
  beyond the first 16 KB needed to confirm the file type

One nuance worth stating plainly: to report which TLS versions a server accepts
(a requirement of the TLS check) the scanner opens up to four short handshakes
to port 443 — the same connection any browser makes, to a port it already uses.
Set `TLS_LOCAL_PROBE=cert` to read only the certificate, or `off` to skip direct
connections entirely and rely on SSL Labs.

Every scan requires the submitter to confirm they own the target or have
permission to assess it, and the scanner identifies itself honestly in its
`User-Agent` so the request is recognisable in the target's access logs.

---

## Quick start

```bash
npm install
npm run dev          # http://localhost:3000
```

```bash
npm run verify       # tsc --noEmit && vitest run
npm run build        # production build
```

No configuration is required — every environment variable has a working
default. Copy `.env.example` to `.env.local` to change anything.

### Scanning your own site on localhost

The SSRF guard refuses private, loopback and link-local targets, so pointing the
scanner at `localhost:3000` fails with `blocked_target` by design. For local
development, enable the escape hatch in `.env.local`:

```bash
ALLOW_PRIVATE_TARGETS=1
```

That also lifts the port allow-list, so `http://127.0.0.1:4000` works. It is
**ignored when `NODE_ENV=production`** — setting it on a deployed instance does
nothing, which is enforced by tests.

## Deploying to Vercel

```bash
vercel          # preview
vercel --prod   # production
```

Two things matter for this project specifically:

- **The API routes must run on the Node.js runtime**, not the edge — they use
  `node:dns`, `node:tls` and `node:http`. Both scan routes already declare
  `export const runtime = 'nodejs'`.
- **SSL Labs scans outlive a short invocation.** `vercel.json` raises
  `maxDuration` to 60s for the scan routes. A cold SSL Labs assessment still
  takes longer than that, which is why the TLS section can come back `pending`
  and the dashboard polls for it (see below).

---

## Embedding in the MEGA Devs site

Set the origins allowed to frame the scanner, then point an iframe at it with
`?embed=1`, which hides the scanner's own header and footer:

```bash
EMBED_ANCESTORS="https://megadevs.example https://www.megadevs.example"
```

```html
<iframe
  src="https://scanner.megadevs.example/?embed=1"
  title="Free passive security scan"
  style="width:100%;height:1400px;border:0"
  loading="lazy"
></iframe>
```

`?url=example.com` pre-fills the input. `?embed=1` also hides the starfield
backdrop chrome, so the panel drops into a host page cleanly.

The design is committed dark — pure black with a red wash — because the look
depends on it; there is no light palette. On a light host page, give the iframe
its own dark container rather than expecting the scanner to adapt.

Without `EMBED_ANCESTORS` the scanner sends `frame-ancestors 'none'` and refuses
to be framed at all, which is the safe default.

---

## API

### `POST /api/scan`

```bash
curl -X POST https://scanner.megadevs.example/api/scan \
  -H 'content-type: application/json' \
  -d '{"url":"example.com","consent":true}'
```

`consent` must be `true`. Returns a `ScanReport` (see
[`src/lib/types.ts`](src/lib/types.ts) for the full schema):

```jsonc
{
  "schemaVersion": "1.1",
  "scanId": "…",
  "target": { "input": "example.com", "url": "https://example.com/", "finalUrl": "…", "resolvedIps": ["…"] },
  "overall": {
    "score": 72,
    "grade": "B",
    "provisional": false,
    "capReason": null,
    "counts": { "critical": 0, "high": 0, "medium": 3, "low": 2, "info": 1, "pass": 14 },
    "headline": "Reasonable baseline, with clear room to improve."
  },
  "sections": {
    "headers": {
      "id": "headers",
      "status": "ok",
      "score": 65,
      "grade": "C",
      "weight": 30,
      "summary": "2 of 6 graded security headers are missing.",
      "findings": [
        {
          "id": "headers.csp.missing",
          "title": "Content-Security-Policy is missing",
          "severity": "medium",
          "status": "fail",
          "detail": "…",
          "recommendation": "…",
          "scoreImpact": -30,
          "references": ["…"]
        }
      ],
      "data": { /* raw observations: every header, the redirect chain, cookies … */ }
    }
    // tls, dns, exposure, fingerprint
  },
  "meta": { "passive": true, "notes": ["…"] }
}
```

`GET /api/scan?url=example.com&consent=1` does the same thing, for quick manual
testing.

**Errors** return an `ApiError` with a 4xx/5xx status and a machine-readable
`code`: `invalid_url`, `blocked_target`, `consent_required`, `rate_limited`,
`unreachable`, `internal`.

### `GET /api/scan/tls?host=example.com`

Re-runs the TLS section alone and returns just that section. When a scan returns
`sections.tls.status === "pending"`, the SSL Labs assessment was still running;
the dashboard polls this endpoint, merges the finished section into the report it
already holds, and re-grades locally. The scoring module is isomorphic, so the
grade the browser shows always matches what the API would have computed.

### `GET /api/health`

Liveness plus the active configuration (SSL Labs API version, probe mode).

---

## How grading works

Modelled on Mozilla Observatory: each section starts at **100**, and every
finding applies a modifier recorded in its own `scoreImpact` — so any score in
the report can be traced back to the findings that produced it.

- Going beyond the baseline earns bonuses (a nonce-based CSP, `includeSubDomains`,
  TLS 1.3), but **bonuses are capped at +10** per section. Uncapped, a strong CSP
  could fully mask a missing header and still show 100/100 next to a summary
  saying a header is missing.
- The overall score is the weighted mean of the sections. Sections that **errored
  or were skipped are excluded and the remaining weights renormalised** — a dead
  nameserver reduces confidence rather than silently costing the site 10 points.
  A **pending** section still counts, because its local findings are already
  final; the result is flagged `provisional` instead.
- **Severe findings cap the overall grade**: any `critical` caps it at F, any
  `high` caps it at C. Without this, a site leaking its `.env` could still score
  a B on the strength of good headers, which would be an actively misleading
  result to hand a client. `overall.capReason` says when a cap was applied.

| Grade | A+ | A | B | C | D | F |
|---|---|---|---|---|---|---|
| Score | ≥95 | ≥85 | ≥75 | ≥65 | ≥50 | <50 |

### Credential detection and redaction

The content check looks for credential shapes in page source — AWS keys, Stripe
secret keys, GitHub and Slack tokens, private keys, and high-entropy generic
assignments. Two rules govern it:

- **No credential value is ever serialised.** Everything that reaches a report
  goes through `src/lib/redact.ts`, which masks all but the first and last four
  characters. Reports get downloaded, emailed and pasted into tickets; a scanner
  that echoed the secret it found would be spreading the leak. There is a test
  asserting a known AWS key never appears whole in output.
- **Keys that are public by design are classified, not condemned.** A Stripe
  `pk_live_` publishable key, a Firebase `apiKey`, a Google browser key — these
  belong in page source. They are reported as information with advice to confirm
  the restrictions, never as leaks. Candidates must also clear a Shannon entropy
  bar and dodge a placeholder blocklist (`YOUR_API_KEY`, `changeme`, `${...}`),
  because the generic pattern would otherwise fire on every minified bundle.

### Request budget

A scan makes around 15 requests to the target against a ceiling of 40, enforced
in the HTTP client rather than per check, and reported in `meta.requests`. The
ceiling exists because "passive" is a claim about volume as much as intent:
without it, every added check quietly raises the load an anonymous visitor can
aim at someone else's site through an embedded form. Checks that run out report
"not assessed" rather than silently skipping.

### Avoiding false positives

Several places needed deliberate care, because a confident wrong answer is worse
than no answer:

- **Exposed files.** Plenty of sites answer `200` with their SPA shell for every
  unknown path. The scanner first requests a random path to learn what "missing"
  looks like on that server, then requires the response body to match a content
  signature for the file type before calling anything exposed.
- **Own CDN vs third party.** A cross-origin asset host sharing the site's
  registrable domain (`static.example.com`) is reported separately from a
  genuinely external one. Calling a site's own CDN "a separate company that can
  change your site" overstates the risk and makes the finding easy to dismiss.
- **CVE matching.** Matches come from a version string in a public page, which is
  strong evidence but not proof. The published severity is preserved in
  `vulnerabilities[].severity`, but the corresponding *finding* is reported one
  step below `critical`, and says so. Version detection is correspondingly
  conservative: WordPress's version is read from its generator tag, and the
  `?ver=` fallback is restricted to core assets, because a looser rule happily
  reads jQuery's `3.7.1` and reports it as the WordPress version.

---

## Safety of the scanner itself

The scanner accepts a URL from anonymous visitors, which makes it a
server-side request forgery engine if built carelessly. The defences:

- **Every address is classified before connection.** Private, loopback,
  link-local, CGNAT, multicast and reserved ranges are refused for both IPv4 and
  IPv6 — including IPv4-mapped and NAT64-embedded forms, so `::ffff:169.254.169.254`
  does not slip past a v4-only check. Cloud instance metadata is the specific
  thing this exists to stop.
- **The approved address is pinned to the socket.** Outbound connections use a
  custom `lookup` (`src/lib/lookup.ts`), so the address the socket connects to is
  the one the guard approved. Re-resolving would leave a DNS-rebinding window.
- **Redirects are followed manually**, so every hop is re-validated and
  credentials cannot be smuggled in through an open redirect.
- **Bounded reads**: per-request timeouts, a 512 KB body cap, a separate cap on
  compressed bytes to stop decompression bombs, and a total scan budget.
- **Scheme, port and host allow-lists**: `http`/`https` only; ports 80, 443,
  8080, 8443; no credentials in the URL; no single-label or `.local`-style names.
- **Rate limiting** per client IP, applied *after* validation so a typo does not
  cost a visitor one of their scans. It is **inactive outside production**: a
  direct localhost request carries no `x-forwarded-for`, so every local caller
  would share one bucket and anyone testing the scanner would lock themselves
  out of it within a minute.
- The one relaxation, `ALLOW_PRIVATE_TARGETS`, is **structurally impossible to
  enable in production** — it is gated on `NODE_ENV !== 'production'`, not on
  trusting whoever sets the variable.

Certificate verification is intentionally disabled for the HTTP fetches: a
broken chain is a finding to report, not a reason to stop scanning. No secrets
are ever sent to the target, and the certificate is validated separately and
reported in the TLS section.

> The in-memory rate limiter is per serverless instance, so it is a speed bump
> rather than a guarantee. Put a shared store (Upstash or similar) behind
> `src/lib/ratelimit.ts` before advertising the service widely.

---

## Configuration

All optional; see [`.env.example`](.env.example).

| Variable | Default | Purpose |
|---|---|---|
| `EMBED_ANCESTORS` | *(none)* | Space-separated origins allowed to iframe the scanner |
| `ALLOW_PRIVATE_TARGETS` | `off` | **Development only** — permit private/loopback targets and any port. Inert when `NODE_ENV=production` |
| `SSLLABS_ENABLED` | `on` | Set `off` to skip SSL Labs entirely |
| `SSLLABS_API_VERSION` | `v3` | `v4` requires `SSLLABS_EMAIL` (free registration) |
| `SSLLABS_MAX_AGE_HOURS` | `24` | Accept a cached SSL Labs result this old |
| `SSLLABS_INITIAL_WAIT_MS` | `6000` | How long a scan waits before returning `pending` |
| `TLS_LOCAL_PROBE` | `on` | `on` \| `cert` (certificate only) \| `off` |
| `RATE_LIMIT_MAX` | `30` | Scans per window per IP. `0` disables it. Only active when `NODE_ENV=production` |
| `RATE_LIMIT_WINDOW_SECONDS` | `600` | Window length |
| `SCAN_REQUEST_TIMEOUT_MS` | `8000` | Per-request timeout |
| `SCAN_TOTAL_BUDGET_MS` | `25000` | Ceiling per check |

### A note on the SSL Labs API

API **v3** needs no key and works today, which is what the default uses. Qualys
has announced its retirement in favour of **v4**, which is still free but
requires a one-time email registration. When v3 stops answering, register at
`https://api.ssllabs.com/api/v4/register` and set:

```bash
SSLLABS_API_VERSION=v4
SSLLABS_EMAIL=you@megadevs.example
```

The scanner degrades gracefully either way: if SSL Labs is unavailable, rate
limiting, or refuses the host, the TLS section still reports the certificate and
protocol support from its own handshake and says why the grade is missing.

---

## Project layout

```
src/
  app/
    page.tsx                 dashboard (scan a URL, or paste a report)
    api/scan/route.ts        POST/GET — run a scan
    api/scan/tls/route.ts    GET — re-run the TLS section (polling)
    api/health/route.ts
  components/                ReportView, SectionCard, SectionDetails, FindingItem
  lib/
    types.ts                 the report schema — start here
    scan.ts                  orchestration
    scoring.ts               grading (isomorphic: used by API and dashboard)
    target.ts                URL parsing + validation
    ip.ts  lookup.ts         SSRF classification and the pinned DNS lookup
    http.ts                  the HTTP client
    errors.ts                turning thrown values into readable reasons
    checks/                  headers, tls, dns, exposure, fingerprint
    data/                    cves.ts, exposure-paths.ts  ← extend these first
```

To add a check: write `src/lib/checks/<name>.ts` returning a `SectionReport` via
`buildSection`, add its id to `SectionId`, give it a weight in `SECTION_WEIGHTS`,
and call it from `runScan`. The dashboard picks up anything in `sections`;
`SectionDetails` renders the structured `data` payload per section.

## Tests

```bash
npm run verify      # tsc --noEmit && vitest run
npm run smoke       # drives the real UI in Chromium (needs a server running)
npm run smoke:scan  # ...and runs a full scan through the browser
```

### Why there is a browser smoke test

A bug got through everything else: the app's own Content-Security-Policy
blocked `'unsafe-eval'`, which **Next's dev server requires** for its
eval-based HMR and source maps. React never hydrated. The page rendered
perfectly, the API answered perfectly under `curl`, every unit test passed —
and the scan button stayed disabled no matter what you typed, because the
keystrokes never reached React state.

Only a real browser sees that, so `scripts/smoke.mjs` drives one: it asserts
that typing reaches React state, that the button enables, that a second control
responds (proving hydration rather than luck), that the consent gate explains
itself, and that the console is clean. Run it against a dev **and** a
production server — the two have different CSPs, and that difference is exactly
what bit.

```bash
npm run build && npm start &   # production, strict CSP
npm run smoke:scan http://127.0.0.1:3000/
```

124 unit tests across the SSRF guard (including the IPv4-mapped bypasses and proof
that the development escape hatch stays shut in production), grading and
version comparison, header/CSP/cookie parsing, certificate hostname matching,
fingerprint and CVE correlation, error description, credential redaction, the request budget, and the dashboard
rendered against real captured reports — a healthy site, one where the page
could not be fetched (which exercises error sections and null data), and a
schema 1.0 report captured before the content section existed, proving an
archived report still renders rather than crashing the dashboard.

---

## Limitations

Worth being upfront about with clients:

- **No JavaScript execution.** Technologies loaded only at runtime are invisible,
  and SPA-heavy sites expose less to fingerprinting. Only the first 512 KB of
  HTML is analysed.
- **DKIM absence is inconclusive.** Selectors are chosen by the sender and cannot
  be enumerated from DNS; the scanner probes 19 common ones and labels a miss as
  inconclusive rather than failing.
- **The CVE table is small and hand-curated**, not a vulnerability database. A
  match means a version is *published as affected* — never that the site is
  exploitable. It needs periodic review; entries carry a `reference` URL.
- **The registrable-domain helper is a heuristic**, not the full Public Suffix
  List. It covers the common multi-label suffixes (`co.uk`, `com.au`, …).
- **One page, one host.** No crawling, no subdomain enumeration.
- **A passive scan is a starting point, not a penetration test**, and the
  dashboard says so.

## License

Internal to MEGA Devs Cyber Team.
