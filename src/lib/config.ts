/** Runtime configuration. Everything has a working default. */

function num(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Like num(), for settings where zero is a meaningful value rather than unset. */
function count(value: string | undefined, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function flag(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return ['1', 'on', 'true', 'yes'].includes(value.trim().toLowerCase());
}

export const SCANNER_NAME = 'MEGA Devs Passive Scanner';
export const SCANNER_VERSION = '1.0.0';

/**
 * Identify ourselves honestly. A site owner reading their access log should be
 * able to tell who hit them and why.
 */
export const USER_AGENT =
  'MEGADevs-PassiveScanner/1.0 (+https://github.com/megadevs/passive-scanner; passive security assessment)';

/**
 * Development-only escape hatch for scanning your own machine.
 *
 * The SSRF guard refuses private, loopback and link-local targets, which is
 * correct for a public service but makes it impossible to point the scanner at
 * a site you are building on localhost. This relaxes the guard — and it is
 * deliberately impossible to turn on in production, so setting the variable on
 * a deployed instance does nothing at all.
 */
export const allowPrivateTargets =
  process.env.NODE_ENV !== 'production' && flag(process.env.ALLOW_PRIVATE_TARGETS, false);

export const config = {
  allowPrivateTargets,
  requestTimeoutMs: num(process.env.SCAN_REQUEST_TIMEOUT_MS, 8_000),
  totalBudgetMs: num(process.env.SCAN_TOTAL_BUDGET_MS, 25_000),

  /** Hard cap on how much of any response body we read into memory. */
  maxBodyBytes: num(process.env.SCAN_MAX_BODY_BYTES, 512 * 1024),

  /** Redirects we follow manually, re-validating the target at every hop. */
  maxRedirects: num(process.env.SCAN_MAX_REDIRECTS, 5),

  /**
   * Same-origin script files read per scan for the DOM XSS check.
   *
   * A bundled app keeps all of its client code in files, so scanning only
   * inline <script> means reporting "no DOM XSS sinks" without having read the
   * code. These bound how much of the bundle one scan will pull: enough to
   * cover a typical entry chunk or two, not enough to become a crawl.
   */
  maxScriptFiles: num(process.env.SCAN_MAX_SCRIPT_FILES, 5),
  maxScriptBytes: num(process.env.SCAN_MAX_SCRIPT_BYTES, 512 * 1024),
  scriptTimeoutMs: num(process.env.SCAN_SCRIPT_TIMEOUT_MS, 6_000),
  /**
   * Requests left untouched for the checks that run after this one. Without a
   * reserve, a page listing forty bundles would spend the whole allowance on
   * script files and the exposed-files sweep would report "not assessed".
   */
  scriptFetchReserve: count(process.env.SCAN_SCRIPT_FETCH_RESERVE, 20),

  /** Parallel requests during the exposed-files sweep. Deliberately gentle. */
  exposureConcurrency: num(process.env.SCAN_EXPOSURE_CONCURRENCY, 3),

  /**
   * Hard ceiling on requests made to the target in one scan, enforced in the
   * HTTP client. Checks that run out report "not assessed" rather than
   * silently skipping, so the report stays honest about its own coverage.
   */
  requestBudget: num(process.env.SCAN_REQUEST_BUDGET, 50),

  rateLimit: {
    /**
     * Off in development. Throttling the person building the scanner just
     * locks them out of their own tool — and because a direct localhost
     * request carries no x-forwarded-for, every local caller shares one
     * bucket, so the lockout arrives within a minute of testing.
     *
     * Also off when RATE_LIMIT_MAX=0, for a deployment that fronts this with
     * its own limiter.
     */
    enabled:
      process.env.NODE_ENV === 'production' && process.env.RATE_LIMIT_MAX?.trim() !== '0',
    max: num(process.env.RATE_LIMIT_MAX, 30),
    windowMs: num(process.env.RATE_LIMIT_WINDOW_SECONDS, 600) * 1000,
  },

  sslLabs: {
    enabled: flag(process.env.SSLLABS_ENABLED, true),
    version: process.env.SSLLABS_API_VERSION?.trim() === 'v4' ? 'v4' : 'v3',
    email: process.env.SSLLABS_EMAIL?.trim() || '',
    apiKey: process.env.SSLLABS_API_KEY?.trim() || '',
    maxAgeHours: num(process.env.SSLLABS_MAX_AGE_HOURS, 24),
    /**
     * How long the initial scan waits for SSL Labs before handing the client a
     * "poll me" token. SSL Labs cold scans routinely take 90-180s, which is far
     * longer than a serverless invocation should hold open.
     */
    initialWaitMs: num(process.env.SSLLABS_INITIAL_WAIT_MS, 6_000),
  },

  /**
   * "on"   - read the certificate and probe which TLS versions are negotiated
   * "cert" - certificate only (single handshake, same as any browser)
   * "off"  - no direct TLS connection
   */
  tlsLocalProbe: (() => {
    const raw = process.env.TLS_LOCAL_PROBE?.trim().toLowerCase();
    if (raw === 'off' || raw === 'cert') return raw;
    return 'on' as const;
  })() as 'on' | 'cert' | 'off',
} as const;
