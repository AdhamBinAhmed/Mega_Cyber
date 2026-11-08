/**
 * MEGA Devs Passive Scanner — report schema.
 *
 * Everything the API emits is described here. The schema is versioned so the
 * dashboard (and any consumer embedding the JSON) can detect breaking changes.
 */

/**
 * 1.1 added the `content` section, `meta.requests`, cross-origin header and
 * cookie-scope observations. 1.2 added `content.data.injection`, the
 * client-side injection surface (DOM XSS sinks, reflected parameters,
 * postMessage listeners, CSRF tokens). 1.3 added `content.data.apiSurface`
 * (CORS policy, API endpoint inventory, decoded JWT claims, credentials in
 * URLs) and the API documentation paths in the exposure sweep. All additive: a
 * 1.0 consumer still works, and the dashboard renders an older report by
 * simply omitting the parts it lacks.
 */
export const SCHEMA_VERSION = '1.4' as const;

export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';

/** How bad a finding is. "pass" is a finding we are happy about. */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'pass';

/** What happened with an individual check. */
export type FindingStatus = 'pass' | 'fail' | 'warn' | 'info' | 'error';

export type SectionId =
  | 'headers'
  | 'tls'
  | 'dns'
  | 'exposure'
  | 'fingerprint'
  | 'content';

export type SectionStatus = 'ok' | 'pending' | 'error' | 'skipped';

export interface Finding {
  /** Stable machine-readable id, e.g. "headers.csp.missing". */
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  /** Human readable explanation of what we observed. */
  detail: string;
  /** Raw observed value (header contents, record text, status code...). */
  evidence?: string;
  /** What to do about it. */
  recommendation?: string;
  /** Points added to (positive) or removed from (negative) the section score. */
  scoreImpact: number;
  references?: string[];
}

export interface SectionReport<TData = unknown> {
  id: SectionId;
  title: string;
  status: SectionStatus;
  /** 0-100 within this section. */
  score: number;
  grade: Grade;
  /** Relative contribution to the overall score. */
  weight: number;
  summary: string;
  findings: Finding[];
  /** Structured observations; shape depends on the section. */
  data: TData;
  durationMs: number;
  /** Populated when status is "error". */
  error?: string;
}

/* -------------------------------------------------------------------------- */
/* Section payloads                                                           */
/* -------------------------------------------------------------------------- */

export interface CookieObservation {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  /** Explicit Domain attribute, which widens the cookie to subdomains. */
  domain: string | null;
  /** __Host- or __Secure- prefix, which browsers enforce. */
  prefix: '__Host-' | '__Secure-' | null;
  maxAgeSeconds: number | null;
}

export interface HeadersData {
  finalUrl: string;
  statusCode: number;
  /** Lower-cased header name to value. Multi-value headers are joined. */
  headers: Record<string, string>;
  /** The six headers this scanner grades, normalised. */
  securityHeaders: Record<string, string | null>;
  redirectChain: Array<{ url: string; status: number; location: string | null }>;
  httpsRedirect: {
    tested: boolean;
    redirectsToHttps: boolean | null;
    note?: string;
  };
  cookies: CookieObservation[];
  /** Headers that leak stack/version information. */
  informationDisclosure: Array<{ header: string; value: string }>;
  /** COOP / COEP / CORP, the cross-origin isolation trio. */
  crossOrigin: Record<string, string | null>;
  cacheControl: string | null;
}

export type TlsProtocolName = 'TLS 1.0' | 'TLS 1.1' | 'TLS 1.2' | 'TLS 1.3';

export interface TlsProtocolSupport {
  protocol: TlsProtocolName;
  supported: boolean | null;
  /** Why we could not determine support, when "supported" is null. */
  note?: string;
}

export interface TlsCertificate {
  subject: string | null;
  issuer: string | null;
  altNames: string[];
  validFrom: string | null;
  validTo: string | null;
  daysUntilExpiry: number | null;
  expired: boolean | null;
  /** Hostname matched the certificate (SAN or CN). */
  hostnameMatch: boolean | null;
  /** Node accepted the chain against the system trust store. */
  chainTrusted: boolean | null;
  chainError?: string;
  keyType: string | null;
  keyBits: number | null;
  serialNumber: string | null;
  fingerprintSha256: string | null;
}

export type SslLabsStatus =
  | 'READY'
  | 'IN_PROGRESS'
  | 'DNS'
  | 'ERROR'
  | 'SKIPPED'
  | 'UNAVAILABLE';

export interface SslLabsSummary {
  enabled: boolean;
  status: SslLabsStatus;
  grade: string | null;
  /** Grade before the "ignore trust issues" adjustment. */
  gradeTrustIgnored: string | null;
  endpointCount: number;
  endpoints: Array<{ ipAddress: string; grade: string | null; statusMessage: string }>;
  testTime: string | null;
  message: string | null;
  /** True when the client should poll /api/scan/tls for a finished result. */
  pollable: boolean;
}

export interface TlsData {
  host: string;
  httpsAvailable: boolean;
  certificate: TlsCertificate | null;
  negotiated: { protocol: string | null; cipher: string | null } | null;
  protocols: TlsProtocolSupport[];
  sslLabs: SslLabsSummary;
}

export interface DnsRecordCheck {
  type: 'SPF' | 'DKIM' | 'DMARC' | 'CAA';
  present: boolean;
  /** Raw record values we found. */
  records: string[];
  /** Names we queried. */
  queried: string[];
  note?: string;
}

export interface DnsData {
  domain: string;
  /** Registrable domain the email-policy lookups ran against. */
  baseDomain: string;
  a: string[];
  aaaa: string[];
  mx: Array<{ exchange: string; priority: number }>;
  ns: string[];
  checks: DnsRecordCheck[];
  /** DKIM selectors we probed. */
  dkimSelectorsTried: string[];
}

export interface ExposureResult {
  path: string;
  url: string;
  status: number | null;
  /** 200 AND the body looks like the real thing (not a catch-all route). */
  accessible: boolean;
  contentType: string | null;
  contentLength: number | null;
  /** Body matched a known signature for this file type. */
  signatureMatched: boolean | null;
  description: string;
  severity: Severity;
  error?: string;
}

export interface ExposureData {
  /** A random path, used to detect servers that answer 200 to everything. */
  baseline: { path: string; status: number | null; soft404: boolean };
  results: ExposureResult[];
  robots: { present: boolean; sensitiveDisallows: string[] } | null;
  securityTxt: { present: boolean } | null;
}

export interface SecretObservation {
  type: string;
  /** Masked by the scanner; the raw value is never serialised. */
  masked: string;
  line: number;
  severity: Severity;
  /** Key types that belong in page source (publishable keys, Firebase config). */
  publicByDesign: boolean;
}

export interface ContentData {
  bytesAnalysed: number;
  truncated: boolean;
  secrets: SecretObservation[];
  /** Distinct cross-origin hosts serving script or CSS to the page. */
  thirdPartyOrigins: string[];
  scriptCount: number;
  scriptsWithoutIntegrity: number;
  /** http:// subresources referenced from an https:// page. */
  mixedContent: string[];
  sourceMaps: string[];
  formCount: number;
  insecureFormCount: number;
  /**
   * Client-side injection surface. Absent on reports produced before schema
   * 1.2, so consumers should treat it as optional at runtime.
   */
  injection: InjectionData;
  /** API surface leakage. Absent before schema 1.3. */
  apiSurface: ApiSurfaceData;
}

/** A JWT found in page source, described by its own (unverified) claims. */
export interface JwtObservation {
  /** Masked by the scanner; the raw token is never serialised. */
  masked: string;
  alg: string | null;
  /** role / roles / scope / permissions claim, whichever was present. */
  role: string | null;
  issuer: string | null;
  subject: string | null;
  expiresAt: string | null;
  /** Null when the token carries no exp claim. */
  expired: boolean | null;
  /** No expiry, or a lifetime longer than a year. */
  longLived: boolean;
  /** Claims a role that bypasses per-user authorisation (service_role, admin). */
  privileged: boolean;
  /** An anon/public key that platforms expect you to publish. */
  publicByDesign: boolean;
  line: number;
}

export interface ApiEndpointObservation {
  /** Origin plus path; query strings are dropped. */
  url: string;
  kind: 'rest' | 'graphql' | 'storage' | 'other';
  crossOrigin: boolean;
  /** Different registrable domain, so genuinely someone else's API. */
  thirdParty: boolean;
}

export interface ApiSurfaceData {
  /** CORS headers on the HTML response — not necessarily the API's own. */
  cors: {
    allowOrigin: string | null;
    allowCredentials: boolean;
    allowMethods: string | null;
    allowHeaders: string | null;
    exposeHeaders: string | null;
  };
  endpoints: ApiEndpointObservation[];
  /** localhost, private addresses, internal suffixes, staging hosts. */
  internalEndpoints: string[];
  /** Cloud instance metadata services referenced from the page. */
  metadataEndpoints: string[];
  /** Credential-bearing URLs, with the credential masked. */
  credentialBearingUrls: string[];
  hardcodedAuthHeaders: number;
  jwts: JwtObservation[];
}

export interface DomSinkObservation {
  /** Sink label, e.g. ".innerHTML assignment". */
  sink: string;
  /** URL-derived source found near the sink, when there was one. */
  source: string | null;
  /** "expression": the source sits beside the sink. "script": same script only. */
  proximity: 'expression' | 'script' | 'none';
  line: number;
  snippet: string;
  /**
   * Script file the sink was found in, or null for an inline <script>. Line
   * numbers are relative to whichever of the two it is.
   */
  file: string | null;
}

export interface ReflectedParamObservation {
  param: string;
  /** Where in the document the value came back. */
  context: 'script' | 'attribute' | 'html';
  /** True when the value was reflected with its special characters intact. */
  rawSpecialChars: boolean;
}

/** Client-side injection surface, all of it read from the served HTML. */
export interface InjectionData {
  inlineScriptCount: number;
  inlineScriptBytes: number;
  /** Same-origin script files fetched and scanned for sinks. */
  externalScriptsAnalysed: number;
  externalScriptBytes: number;
  /**
   * Same-origin script files referenced by the page but not scanned, because
   * the per-scan file cap, request budget or time budget ran out. Reported, so
   * "no DOM XSS sinks" never means "we did not look".
   */
  externalScriptsSkipped: number;
  inlineEventHandlers: number;
  domSinks: DomSinkObservation[];
  postMessageListeners: number;
  /** Listeners that compare event.origin against something. */
  postMessageOriginChecks: number;
  javascriptUris: string[];
  reflectedParams: ReflectedParamObservation[];
  postFormCount: number;
  postFormsWithoutToken: number;
  documentDomainWrites: number;
  /** A nonce/hash CSP was in force, so the DOM findings were demoted. */
  cspMitigates: boolean;
}

export type TechCategory =
  | 'cms'
  | 'framework'
  | 'library'
  | 'server'
  | 'language'
  | 'analytics'
  | 'cdn'
  | 'ecommerce';

export interface TechnologyMatch {
  name: string;
  category: TechCategory;
  version: string | null;
  /** How we spotted it, e.g. "meta[generator]" or "header:x-powered-by". */
  evidence: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface VulnerabilityMatch {
  product: string;
  detectedVersion: string;
  fixedIn: string | null;
  cves: string[];
  severity: Severity;
  cvss: number | null;
  title: string;
  reference: string;
  /** Version line is past end-of-life, regardless of a specific CVE. */
  endOfLife: boolean;
}

export interface FingerprintData {
  technologies: TechnologyMatch[];
  vulnerabilities: VulnerabilityMatch[];
  /** Bytes of HTML we analysed (we never execute JavaScript). */
  htmlBytesAnalysed: number;
  generatorMeta: string | null;
}

/* -------------------------------------------------------------------------- */
/* Report envelope                                                            */
/* -------------------------------------------------------------------------- */

export interface ScanTarget {
  /** Exactly what the user typed. */
  input: string;
  /** Normalised absolute URL we scanned. */
  url: string;
  origin: string;
  hostname: string;
  port: number | null;
  /** URL after following redirects (may differ from "url"). */
  finalUrl: string | null;
  /** Addresses resolved during the SSRF safety check. */
  resolvedIps: string[];
}

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  pass: number;
}

export interface ScanSections {
  headers: SectionReport<HeadersData | null>;
  tls: SectionReport<TlsData | null>;
  dns: SectionReport<DnsData | null>;
  exposure: SectionReport<ExposureData | null>;
  fingerprint: SectionReport<FingerprintData | null>;
  content: SectionReport<ContentData | null>;
}

export interface ScanReport {
  schemaVersion: typeof SCHEMA_VERSION;
  scanId: string;
  target: ScanTarget;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  overall: {
    score: number;
    grade: Grade;
    /** True while a section is still pending, so the grade may still move. */
    provisional: boolean;
    counts: SeverityCounts;
    /** Short plain-language verdict for the dashboard header. */
    headline: string;
    /** Set when a severe finding capped the grade below the weighted average. */
    capReason: string | null;
  };
  sections: ScanSections;
  meta: {
    scanner: string;
    version: string;
    passive: true;
    /** Caveats worth showing the user. */
    notes: string[];
    /** Requests actually made to the target, against the per-scan ceiling. */
    requests: { used: number; limit: number; refused: number };
  };
}

export type ApiErrorCode =
  | 'invalid_url'
  | 'blocked_target'
  | 'rate_limited'
  | 'consent_required'
  | 'unreachable'
  | 'internal';

export interface ApiError {
  error: string;
  code: ApiErrorCode;
  detail?: string;
  /** Present on a rate_limited response: seconds until the window resets. */
  retryAfterSeconds?: number;
}
