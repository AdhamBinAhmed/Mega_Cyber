'use client';

import { useCallback, useEffect, useRef, useState } from 'react';

import type { ApiError, ScanReport, SectionReport } from '@/lib/types';
import { computeOverall } from '@/lib/scoring';
import { ReportView } from '@/components/ReportView';
import {
  ArrowRight,
  Ban,
  Eye,
  FileSearch,
  Globe,
  Layers,
  Lock,
  ShieldCheck,
} from '@/components/icons';

type Mode = 'scan' | 'json';

const CHECKS = [
  'Fetching the page and reading response headers',
  'Inspecting the TLS certificate and protocol support',
  'Looking up SPF, DKIM, DMARC and CAA records',
  'Requesting well-known paths for exposed files',
  'Fingerprinting components and matching advisories',
];

const STRIP = [
  { label: 'Security headers', Icon: ShieldCheck },
  { label: 'SSL / TLS', Icon: Lock },
  { label: 'Exposed files', Icon: FileSearch },
  { label: 'DNS & email auth', Icon: Globe },
  { label: 'Known CVEs', Icon: Layers },
];

/** SSL Labs cold scans take minutes; poll patiently, then give up gracefully. */
const POLL_INTERVAL_MS = 20_000;
const POLL_MAX_ATTEMPTS = 6;

export default function Page() {
  const [mode, setMode] = useState<Mode>('scan');
  const [url, setUrl] = useState('');
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [pasted, setPasted] = useState('');
  const [pollingTls, setPollingTls] = useState(false);
  const [consentError, setConsentError] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  const pollTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const attempts = useRef(0);

  // Embed mode and ?url= prefill, read from the URL without a Suspense bailout.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('embed') === '1') document.body.dataset.embed = 'true';
    const prefill = params.get('url');
    if (prefill) setUrl(prefill);
  }, []);

  const stopPolling = useCallback(() => {
    if (pollTimer.current) clearTimeout(pollTimer.current);
    pollTimer.current = null;
    setPollingTls(false);
  }, []);

  useEffect(() => stopPolling, [stopPolling]);

  // A rate-limit response is the one error with a defined end, so show it
  // ticking away rather than as a dead red box the user has to guess about.
  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => {
      setCooldown((seconds) => {
        const next = seconds - 1;
        if (next <= 0) setError(null);
        return next;
      });
    }, 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  /** Fold a freshly finished TLS section into the report and re-grade. */
  const pollTls = useCallback(
    async (host: string) => {
      attempts.current += 1;
      try {
        const response = await fetch(`/api/scan/tls?host=${encodeURIComponent(host)}`);
        if (response.ok) {
          const section = (await response.json()) as SectionReport<unknown>;
          setReport((current) => {
            if (!current) return current;
            const sections = { ...current.sections, tls: section as ScanReport['sections']['tls'] };
            return { ...current, sections, overall: computeOverall(sections) };
          });
          if (section.status !== 'pending') {
            stopPolling();
            return;
          }
        }
      } catch {
        // A failed poll is not worth surfacing; the next one may succeed.
      }

      if (attempts.current >= POLL_MAX_ATTEMPTS) {
        stopPolling();
        return;
      }
      pollTimer.current = setTimeout(() => void pollTls(host), POLL_INTERVAL_MS);
    },
    [stopPolling],
  );

  const startPollingIfPending = useCallback(
    (fresh: ScanReport) => {
      if (fresh.sections.tls.status !== 'pending') return;
      attempts.current = 0;
      setPollingTls(true);
      pollTimer.current = setTimeout(() => void pollTls(fresh.target.hostname), POLL_INTERVAL_MS);
    },
    [pollTls],
  );

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy) return;

    // The permission box is a real gate, so it has to explain itself. Leaving
    // the button disabled until it is ticked just looks like a broken scanner.
    if (!consent) {
      setConsentError(true);
      setError({
        error: 'Confirm you have permission to scan this site.',
        code: 'consent_required',
        detail: 'Tick the checkbox below, then run the scan again.',
      });
      return;
    }

    setConsentError(false);
    stopPolling();
    setError(null);
    setCooldown(0);
    setReport(null);
    setBusy(true);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url, consent }),
      });
      const payload = await response.json();

      if (!response.ok) {
        const apiError = payload as ApiError;
        setError(apiError);
        if (apiError.code === 'rate_limited' && apiError.retryAfterSeconds) {
          setCooldown(apiError.retryAfterSeconds);
        }
        return;
      }

      const fresh = payload as ScanReport;
      setReport(fresh);
      startPollingIfPending(fresh);
    } catch (err) {
      // fetch() only rejects on a transport failure, which almost always means
      // the server is down or restarting rather than anything about the target.
      setError({
        error: 'Could not reach the scanner API.',
        code: 'internal',
        detail: `The request never got a response (${(err as Error).message}). The scanner may be restarting — wait a moment and try again.`,
      });
    } finally {
      setBusy(false);
    }
  };

  const loadJson = (event: React.FormEvent) => {
    event.preventDefault();
    stopPolling();
    setError(null);
    try {
      const parsed = JSON.parse(pasted) as ScanReport;
      if (!parsed.schemaVersion || !parsed.sections || !parsed.overall) {
        throw new Error('That JSON is not a scanner report (missing schemaVersion/sections).');
      }
      setReport(parsed);
    } catch (err) {
      setReport(null);
      setError({
        error: 'Could not read that report.',
        code: 'invalid_url',
        detail: (err as Error).message,
      });
    }
  };

  return (
    <>
      <div className="nav-wrap">
        <div className="shell">
          <nav className="nav">
            <div className="brand">
              {/* Transparent PNG, so it sits on the black ground directly. */}
              <img
                className="brand-logo"
                src="/megadevs-logo.png"
                width={1600}
                height={605}
                alt="MEGADevs"
                decoding="async"
              />
              <span className="brand-divider" aria-hidden />
              <span className="brand-text">
                <strong>Cyber Team</strong>
                <span>Passive Security Scanner</span>
              </span>
            </div>
            <div className="nav-right">
              <a className="nav-link" href="/api/health">
                API
              </a>
              <span className="pill-free">Free</span>
            </div>
          </nav>
        </div>
      </div>

      <main className="shell">
        <section className="hero">
          <div className="hero-badge">
            <span className="ping" aria-hidden />
            Passive by design — read-only, nothing exploited
          </div>

          <h1>
            <span className="line">See what your site</span>
            <span className="line">
              already tells an{' '}
              <span className="accent-word">
                attacker
                <svg viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden>
                  <path d="M0 5 Q 50 10 100 5" stroke="currentColor" strokeWidth="2" fill="none" />
                </svg>
              </span>
            </span>
          </h1>

          <p className="hero-lede">
            A read-only assessment of everything the public internet can already check: your
            security headers, TLS configuration, DNS and email authentication, publicly readable
            files, and the component versions you advertise. No ports are scanned, no credentials
            are tried, and nothing is exploited.
          </p>
        </section>

        <div className="tabs" role="tablist" aria-label="Input mode">
          <button
            type="button"
            role="tab"
            className="tab"
            aria-selected={mode === 'scan'}
            onClick={() => setMode('scan')}
          >
            Scan a URL
          </button>
          <button
            type="button"
            role="tab"
            className="tab"
            aria-selected={mode === 'json'}
            onClick={() => setMode('json')}
          >
            Load a report
          </button>
        </div>

        {mode === 'scan' ? (
          <form className="panel" onSubmit={submit}>
            <div className="scan-row">
              <input
                className="input"
                type="text"
                inputMode="url"
                autoComplete="url"
                placeholder="example.com"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                disabled={busy}
                aria-label="Website URL to scan"
              />
              <button
                className="shiny-cta"
                type="submit"
                disabled={busy || !url.trim() || cooldown > 0}
              >
                <span>
                  {busy ? 'Scanning…' : cooldown > 0 ? `Wait ${cooldown}s` : 'Run free scan'}
                  {!busy && cooldown === 0 && <ArrowRight />}
                </span>
              </button>
            </div>

            <label className={consentError ? 'consent consent-error' : 'consent'}>
              <input
                type="checkbox"
                checked={consent}
                onChange={(event) => {
                  setConsent(event.target.checked);
                  if (event.target.checked) {
                    setConsentError(false);
                    setError(null);
                  }
                }}
                disabled={busy}
              />
              <span>
                I own this website or have permission from its owner to assess it. I understand the
                scan sends a small number of ordinary requests from MEGADevs infrastructure, and
                that those requests will appear in the site&rsquo;s access logs.
              </span>
            </label>

            <div className="examples">
              <span>Try</span>
              {['github.com', 'mozilla.org', 'example.com'].map((sample) => (
                <button
                  key={sample}
                  type="button"
                  className="chip"
                  onClick={() => setUrl(sample)}
                  disabled={busy}
                >
                  {sample}
                </button>
              ))}
            </div>

            {busy && (
              <div className="progress">
                {CHECKS.map((label) => (
                  <div className="progress-step" key={label}>
                    <span className="spinner" />
                    {label}
                  </div>
                ))}
              </div>
            )}

            {error && (
              <div
                className={error.code === 'rate_limited' ? 'alert alert-wait' : 'alert'}
                role="alert"
              >
                <strong>{error.error}</strong>
                {error.code === 'rate_limited' && cooldown > 0 ? (
                  <span>
                    The limit protects the sites being scanned, not you. Ready again in{' '}
                    <b>{cooldown}s</b>.
                  </span>
                ) : (
                  error.detail && <span>{error.detail}</span>
                )}
              </div>
            )}
          </form>
        ) : (
          <form className="panel" onSubmit={loadJson}>
            <p style={{ margin: '0 0 14px', fontSize: 13, color: 'var(--text-faint)' }}>
              Paste a report produced by <code>/api/scan</code> to render it here. Useful for
              sharing results, re-reading an archived scan, or driving the dashboard from your own
              pipeline.
            </p>
            <textarea
              className="input"
              value={pasted}
              onChange={(event) => setPasted(event.target.value)}
              placeholder='{ "schemaVersion": "1.0", "scanId": "…", … }'
              aria-label="Scan report JSON"
            />
            <div style={{ marginTop: 14 }}>
              <button className="btn" type="submit" disabled={!pasted.trim()}>
                Render report
              </button>
            </div>

            {error && (
              <div className="alert" role="alert">
                <strong>{error.error}</strong>
                {error.detail && <span>{error.detail}</span>}
              </div>
            )}
          </form>
        )}

        {report && <ReportView report={report} pollingTls={pollingTls} />}
      </main>

      {!report && (
        <>
          <div className="strip">
            <div className="strip-inner">
              <span className="strip-label">Five checks</span>
              {STRIP.map(({ label, Icon }) => (
                <span className="strip-item" key={label}>
                  <Icon />
                  {label}
                </span>
              ))}
            </div>
          </div>

          <section className="shell band" style={{ paddingTop: 96 }}>
            <div style={{ textAlign: 'center', maxWidth: '46rem', margin: '0 auto 44px' }}>
              <div className="section-head-label">What gets assessed</div>
              <h2 className="display-h2">
                One report, <em>five angles</em> of attack surface
              </h2>
              <p className="hero-lede">
                Each section is graded on its own, then combined into one weighted score. Every
                point of every grade traces back to a specific finding.
              </p>
            </div>

            <div className="bento">
              <article className="cell cell-wide">
                <span className="cell-glow" aria-hidden />
                <span className="cell-icon">
                  <ShieldCheck />
                </span>
                <h3>HTTP security headers</h3>
                <p>
                  Content-Security-Policy, Strict-Transport-Security, X-Frame-Options,
                  X-Content-Type-Options, Referrer-Policy and Permissions-Policy — scored
                  individually, with credit for going beyond the baseline. Also reads cookie flags,
                  version-disclosing headers, and whether plain HTTP redirects to HTTPS.
                </p>
                <span className="cell-weight">30% of score</span>
              </article>

              <article className="cell cell-wide">
                <span className="cell-glow" aria-hidden />
                <span className="cell-icon">
                  <Lock />
                </span>
                <h3>SSL / TLS</h3>
                <p>
                  Certificate validity, expiry, hostname coverage, chain trust and key strength,
                  plus which protocol versions the server accepts — TLS 1.0 and 1.1 flagged as
                  weak. Cross-checked against the Qualys SSL Labs grade.
                </p>
                <span className="cell-weight">25% of score</span>
              </article>

              <article className="cell">
                <span className="cell-glow" aria-hidden />
                <span className="cell-icon">
                  <FileSearch />
                </span>
                <h3>Exposed files</h3>
                <p>
                  Twelve well-known paths checked for readability — and confirmed by content, not
                  just a 200.
                </p>
                <span className="cell-weight">25%</span>
              </article>

              <article className="cell">
                <span className="cell-glow" aria-hidden />
                <span className="cell-icon">
                  <Globe />
                </span>
                <h3>DNS &amp; email auth</h3>
                <p>SPF, DKIM, DMARC and CAA records, with the policy strength of each.</p>
                <span className="cell-weight">10%</span>
              </article>

              <article className="cell">
                <span className="cell-glow" aria-hidden />
                <span className="cell-icon">
                  <Layers />
                </span>
                <h3>Known CVEs</h3>
                <p>
                  CMS, framework and library versions matched against a curated advisory table.
                </p>
                <span className="cell-weight">10%</span>
              </article>

              <article className="cell">
                <span className="cell-glow" aria-hidden />
                <span className="cell-icon">
                  <Eye />
                </span>
                <h3>Full evidence</h3>
                <p>
                  Every finding carries what we observed, why it matters and how to fix it. Export
                  the raw JSON.
                </p>
                <span className="cell-weight">Included</span>
              </article>
            </div>
          </section>

          <div className="banner">
            <div className="banner-inner">
              <div className="banner-eyebrow">Scope</div>
              <h2>
                This is a passive assessment. It reads what is already public and stops there.
              </h2>
              <ul className="banner-list">
                <li>
                  <Ban />
                  No port scanning
                </li>
                <li>
                  <Ban />
                  No exploitation
                </li>
                <li>
                  <Ban />
                  No brute force
                </li>
                <li>
                  <Ban />
                  No authentication
                </li>
                <li>
                  <Ban />
                  No action on what it finds
                </li>
              </ul>
            </div>
          </div>
        </>
      )}

      <footer className="sitefoot">
        <div className="foot-grid">
          <div>
            <img
              className="brand-logo brand-logo-lg"
              src="/megadevs-logo.png"
              width={1600}
              height={605}
              alt="MEGADevs"
              loading="lazy"
              decoding="async"
            />
            <p>
              A passive assessment is a starting point, not a penetration test. It tells you what
              an attacker learns for free, before they try anything at all.
            </p>
          </div>

          <div className="foot-col">
            <h4>Checks</h4>
            <ul>
              <li>
                <span>Security headers</span>
              </li>
              <li>
                <span>SSL / TLS</span>
              </li>
              <li>
                <span>Exposed files</span>
              </li>
              <li>
                <span>DNS &amp; email auth</span>
              </li>
              <li>
                <span>Known CVEs</span>
              </li>
            </ul>
          </div>

          <div className="foot-col">
            <h4>Service</h4>
            <ul>
              <li>
                <a href="/api/health">API status</a>
              </li>
              <li>
                <span>Passive only</span>
              </li>
              <li>
                <span>Permission required</span>
              </li>
            </ul>
          </div>
        </div>

        <div className="wordmark" aria-hidden>
          <span>MEGA DEVS</span>
        </div>

        <div className="foot-bottom">
          <span>&copy; {new Date().getFullYear()} MEGADevs Engineering Studio</span>
          <span>Read-only · results are a starting point, not a penetration test</span>
        </div>
      </footer>
    </>
  );
}
