/** Per-section structured data, rendered under the findings list. */

import type {
  ContentData,
  DnsData,
  ExposureData,
  FingerprintData,
  ApiSurfaceData,
  HeadersData,
  InjectionData,
  SectionReport,
  TlsData,
} from '@/lib/types';
import { SEVERITY_COLOR, tint } from '@/lib/ui';

function Fact({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="fact">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

/** Script URL reduced to its filename, which is what the report has room for. */
function fileName(url: string): string {
  try {
    return new URL(url).pathname.split('/').filter(Boolean).pop() ?? url;
  } catch {
    return url;
  }
}

function Yes() {
  return <span style={{ color: 'var(--sev-pass)' }}>yes</span>;
}
function No() {
  return <span style={{ color: 'var(--sev-high)' }}>no</span>;
}
function Unknown() {
  return <span style={{ color: 'var(--text-faint)' }}>unknown</span>;
}

function Tri({ value }: { value: boolean | null }) {
  if (value === null) return <Unknown />;
  return value ? <Yes /> : <No />;
}

/* ------------------------------- headers --------------------------------- */

const HEADER_LABELS: Record<string, string> = {
  'content-security-policy': 'Content-Security-Policy',
  'strict-transport-security': 'Strict-Transport-Security',
  'x-frame-options': 'X-Frame-Options',
  'x-content-type-options': 'X-Content-Type-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
};

function HeadersDetails({ data }: { data: HeadersData }) {
  return (
    <>
      <div className="subhead">Graded headers</div>
      <dl className="facts">
        {Object.entries(HEADER_LABELS).map(([key, label]) => {
          const value = data.securityHeaders[key];
          return (
            <Fact
              key={key}
              label={label}
              value={
                value ? (
                  <span title={value}>{value.length > 64 ? `${value.slice(0, 64)}…` : value}</span>
                ) : (
                  <span style={{ color: 'var(--sev-high)' }}>not set</span>
                )
              }
            />
          );
        })}
      </dl>

      <div className="subhead">Response</div>
      <dl className="facts">
        <Fact label="Final URL" value={data.finalUrl} />
        <Fact label="Status" value={data.statusCode} />
        <Fact
          label="HTTP → HTTPS redirect"
          value={data.httpsRedirect.tested ? <Tri value={data.httpsRedirect.redirectsToHttps} /> : 'not tested'}
        />
        <Fact label="Redirect hops" value={data.redirectChain.length} />
      </dl>

      <div className="subhead">Cross-origin isolation</div>
      <dl className="facts">
        {Object.entries(data.crossOrigin ?? {}).map(([name, value]) => (
          <Fact
            key={name}
            label={name.replace(/^cross-origin-/, 'COOP/COEP/CORP: ').replace('policy', '')}
            value={value ?? <span style={{ color: 'var(--text-ghost)' }}>not set</span>}
          />
        ))}
        <Fact label="Cache-Control" value={data.cacheControl ?? 'not set'} />
      </dl>

      {data.cookies.length > 0 && (
        <>
          <div className="subhead">Cookies</div>
          <div className="evidence">
            {data.cookies.map((cookie) => (
              <div key={cookie.name}>
                {cookie.name} — Secure: {cookie.secure ? 'yes' : 'no'}, HttpOnly:{' '}
                {cookie.httpOnly ? 'yes' : 'no'}, SameSite: {cookie.sameSite ?? 'not set'}
                {cookie.domain ? `, Domain: ${cookie.domain}` : ''}
                {cookie.prefix ? `, prefix: ${cookie.prefix}` : ''}
              </div>
            ))}
          </div>
        </>
      )}
    </>
  );
}

/* --------------------------------- TLS ----------------------------------- */

function TlsDetails({ data }: { data: TlsData }) {
  const cert = data.certificate;
  return (
    <>
      {cert && (
        <>
          <div className="subhead">Certificate</div>
          <dl className="facts">
            <Fact label="Subject" value={cert.subject ?? '—'} />
            <Fact label="Issuer" value={cert.issuer ?? '—'} />
            <Fact label="Valid from" value={cert.validFrom ?? '—'} />
            <Fact
              label="Expires"
              value={
                <span
                  style={{
                    color:
                      cert.expired || (cert.daysUntilExpiry ?? 99) < 15
                        ? 'var(--sev-high)'
                        : undefined,
                  }}
                >
                  {cert.validTo ?? '—'}
                  {cert.daysUntilExpiry !== null && ` (${cert.daysUntilExpiry}d)`}
                </span>
              }
            />
            <Fact label="Covers hostname" value={<Tri value={cert.hostnameMatch} />} />
            <Fact label="Chain trusted" value={<Tri value={cert.chainTrusted} />} />
            <Fact
              label="Key"
              value={cert.keyType ? `${cert.keyType}${cert.keyBits ? ` ${cert.keyBits} bits` : ''}` : '—'}
            />
            <Fact label="SANs" value={cert.altNames.length > 0 ? cert.altNames.join(', ') : '—'} />
          </dl>
        </>
      )}

      {data.protocols.length > 0 && (
        <>
          <div className="subhead">Protocol support</div>
          <dl className="facts">
            {data.protocols.map((entry) => (
              <Fact
                key={entry.protocol}
                label={entry.protocol}
                value={
                  entry.supported === null ? (
                    <span title={entry.note} style={{ color: 'var(--text-faint)' }}>
                      not determined
                    </span>
                  ) : entry.supported ? (
                    <span
                      style={{
                        color:
                          entry.protocol === 'TLS 1.0' || entry.protocol === 'TLS 1.1'
                            ? 'var(--sev-medium)'
                            : 'var(--sev-pass)',
                      }}
                    >
                      accepted
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)' }}>refused</span>
                  )
                }
              />
            ))}
          </dl>
        </>
      )}

      <div className="subhead">Qualys SSL Labs</div>
      <dl className="facts">
        <Fact label="Status" value={data.sslLabs.status} />
        <Fact label="Grade" value={data.sslLabs.grade ?? '—'} />
        <Fact label="Endpoints" value={data.sslLabs.endpointCount || '—'} />
        <Fact label="Tested" value={data.sslLabs.testTime?.slice(0, 19).replace('T', ' ') ?? '—'} />
      </dl>
      {data.sslLabs.endpoints.length > 0 && (
        <div className="evidence">
          {data.sslLabs.endpoints.map((endpoint) => (
            <div key={endpoint.ipAddress}>
              {endpoint.ipAddress} → {endpoint.grade ?? '—'} ({endpoint.statusMessage})
            </div>
          ))}
        </div>
      )}
      {data.negotiated && (
        <div className="evidence">
          Negotiated: {data.negotiated.protocol ?? '?'} / {data.negotiated.cipher ?? '?'}
        </div>
      )}
    </>
  );
}

/* --------------------------------- DNS ----------------------------------- */

function DnsDetails({ data }: { data: DnsData }) {
  return (
    <>
      <div className="subhead">Email & certificate policy ({data.baseDomain})</div>
      <dl className="facts">
        {data.checks.map((check) => (
          <Fact
            key={check.type}
            label={check.type}
            value={
              check.present ? (
                <span style={{ color: 'var(--sev-pass)' }}>published</span>
              ) : (
                <span style={{ color: 'var(--sev-high)' }}>
                  {check.type === 'DKIM' ? 'not found' : 'missing'}
                </span>
              )
            }
          />
        ))}
      </dl>

      {data.checks.some((check) => check.records.length > 0) && (
        <div className="evidence">
          {data.checks
            .filter((check) => check.records.length > 0)
            .map((check) =>
              check.records.map((record, index) => (
                <div key={`${check.type}-${index}`}>
                  {check.type}: {record}
                </div>
              )),
            )}
        </div>
      )}

      <div className="subhead">Zone</div>
      <dl className="facts">
        <Fact label="A" value={data.a.join(', ') || '—'} />
        <Fact label="AAAA" value={data.aaaa.join(', ') || '—'} />
        <Fact
          label="MX"
          value={data.mx.map((mx) => `${mx.priority} ${mx.exchange}`).join(', ') || '—'}
        />
        <Fact label="NS" value={data.ns.join(', ') || '—'} />
      </dl>
    </>
  );
}

/* ------------------------------- exposure -------------------------------- */

function ExposureDetails({ data }: { data: ExposureData }) {
  return (
    <>
      <div className="subhead">Paths checked</div>
      <div className="evidence">
        {data.results.map((result) => {
          const color = result.accessible ? SEVERITY_COLOR[result.severity] : 'var(--text-faint)';
          return (
            <div key={result.path} style={{ color }}>
              {String(result.status ?? 'ERR').padEnd(4)} {result.path}
              {result.accessible ? '  ← readable' : ''}
              {result.error ? `  (${result.error})` : ''}
            </div>
          );
        })}
      </div>
      <dl className="facts">
        <Fact
          label="404 baseline"
          value={data.baseline.soft404 ? 'returns 200 (catch-all)' : `returns ${data.baseline.status ?? 'n/a'}`}
        />
        <Fact label="robots.txt" value={data.robots?.present ? 'present' : 'absent'} />
        <Fact label="security.txt" value={data.securityTxt?.present ? 'present' : 'absent'} />
      </dl>
    </>
  );
}

/* ----------------------------- fingerprint -------------------------------- */

function FingerprintDetails({ data }: { data: FingerprintData }) {
  return (
    <>
      {data.technologies.length > 0 && (
        <>
          <div className="subhead">Detected components</div>
          <div className="evidence">
            {data.technologies.map((tech) => (
              <div key={`${tech.name}-${tech.evidence}`}>
                {tech.name}
                {tech.version ? ` ${tech.version}` : ''} — {tech.category}, {tech.confidence}{' '}
                confidence ({tech.evidence})
              </div>
            ))}
          </div>
        </>
      )}

      {data.vulnerabilities.length > 0 && (
        <>
          <div className="subhead">Advisory matches</div>
          <div className="evidence">
            {data.vulnerabilities.map((vuln, index) => (
              <div
                key={`${vuln.product}-${vuln.cves[0] ?? index}`}
                style={{ color: SEVERITY_COLOR[vuln.severity] }}
              >
                {vuln.product} {vuln.detectedVersion} →{' '}
                {vuln.cves.length > 0 ? vuln.cves.join(', ') : 'end of life'}
                {vuln.cvss ? ` (CVSS ${vuln.cvss})` : ''}
                {vuln.fixedIn ? ` — fixed in ${vuln.fixedIn}` : ''}
              </div>
            ))}
          </div>
        </>
      )}

      <dl className="facts">
        <Fact label="Generator meta" value={data.generatorMeta ?? 'not present'} />
        <Fact label="HTML analysed" value={`${(data.htmlBytesAnalysed / 1024).toFixed(1)} KB`} />
      </dl>
    </>
  );
}

/* ------------------------------- content ---------------------------------- */

function ContentDetails({ data }: { data: ContentData }) {
  // Reports produced before schema 1.2 have no injection payload.
  const injection = data.injection as InjectionData | undefined;
  const taintedSinks =
    injection?.domSinks.filter((sink) => sink.proximity === 'expression').length ?? 0;
  // Reports produced before schema 1.3 have no API surface payload.
  const api = data.apiSurface as ApiSurfaceData | undefined;

  return (
    <>
      {data.secrets.length > 0 && (
        <>
          <div className="subhead">Credential-shaped values found</div>
          <div className="evidence">
            {data.secrets.map((secret, index) => (
              <div
                key={`${secret.type}-${index}`}
                style={{ color: secret.publicByDesign ? undefined : SEVERITY_COLOR[secret.severity] }}
              >
                line ~{secret.line} · {secret.type} · {secret.masked}
                {secret.publicByDesign ? '  (public by design)' : ''}
              </div>
            ))}
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-ghost)', margin: '8px 0 0' }}>
            Values are masked by the scanner and never stored in full.
          </p>
        </>
      )}

      {data.thirdPartyOrigins.length > 0 && (
        <>
          <div className="subhead">Third-party origins ({data.thirdPartyOrigins.length})</div>
          <div className="evidence">
            {data.thirdPartyOrigins.map((origin) => (
              <div key={origin}>{origin}</div>
            ))}
          </div>
        </>
      )}

      {data.mixedContent.length > 0 && (
        <>
          <div className="subhead">Plain-HTTP subresources</div>
          <div className="evidence">
            {data.mixedContent.map((url) => (
              <div key={url} style={{ color: SEVERITY_COLOR.high }}>
                {url}
              </div>
            ))}
          </div>
        </>
      )}

      {data.sourceMaps.length > 0 && (
        <>
          <div className="subhead">Source maps referenced</div>
          <div className="evidence">
            {data.sourceMaps.map((map) => (
              <div key={map}>{map}</div>
            ))}
          </div>
        </>
      )}

      {injection && injection.domSinks.length > 0 && (
        <>
          <div className="subhead">
            Client-side sinks ({injection.domSinks.length})
          </div>
          <div className="evidence">
            {injection.domSinks.slice(0, 10).map((sink, index) => (
              <div
                key={`${sink.sink}-${sink.line}-${index}`}
                style={{
                  color:
                    sink.proximity === 'expression'
                      ? SEVERITY_COLOR.high
                      : sink.proximity === 'script'
                        ? SEVERITY_COLOR.low
                        : undefined,
                }}
              >
                {sink.file ? `${fileName(sink.file)} ` : ''}line ~{sink.line} · {sink.sink}
                {sink.source ? ` ← ${sink.source}` : ''}
                {sink.proximity === 'script' ? '  (same script, not same expression)' : ''}
              </div>
            ))}
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-ghost)', margin: '8px 0 0' }}>
            Read from source without executing it — a sanitiser between source and sink is
            invisible here, so confirm each lead by hand.
          </p>
        </>
      )}

      {injection && injection.reflectedParams.length > 0 && (
        <>
          <div className="subhead">Reflected URL parameters</div>
          <div className="evidence">
            {injection.reflectedParams.map((entry) => (
              <div
                key={`${entry.param}-${entry.context}`}
                style={{ color: entry.rawSpecialChars ? SEVERITY_COLOR.high : undefined }}
              >
                {entry.param} → {entry.context} context
                {entry.rawSpecialChars ? '  (special characters unescaped)' : ''}
              </div>
            ))}
          </div>
        </>
      )}

      {api && api.jwts.length > 0 && (
        <>
          <div className="subhead">Tokens found in page source</div>
          <div className="evidence">
            {api.jwts.map((jwt, index) => (
              <div
                key={`${jwt.masked}-${index}`}
                style={{
                  color: jwt.privileged
                    ? SEVERITY_COLOR.critical
                    : jwt.publicByDesign || jwt.expired
                      ? undefined
                      : SEVERITY_COLOR.medium,
                }}
              >
                line ~{jwt.line} · {jwt.masked}
                {jwt.role ? ` · role ${jwt.role}` : ''}
                {jwt.expiresAt ? ` · exp ${jwt.expiresAt.slice(0, 10)}` : ' · no expiry'}
                {jwt.expired ? '  (expired)' : ''}
                {jwt.publicByDesign ? '  (public by design)' : ''}
              </div>
            ))}
          </div>
          <p style={{ fontSize: 12, color: 'var(--text-ghost)', margin: '8px 0 0' }}>
            Claims are read without verifying the signature; tokens are masked by the scanner.
          </p>
        </>
      )}

      {api && api.credentialBearingUrls.length > 0 && (
        <>
          <div className="subhead">Credentials carried in URLs</div>
          <div className="evidence">
            {api.credentialBearingUrls.map((url) => (
              <div key={url} style={{ color: SEVERITY_COLOR.high }}>
                {url}
              </div>
            ))}
          </div>
        </>
      )}

      {api && (api.internalEndpoints.length > 0 || api.metadataEndpoints.length > 0) && (
        <>
          <div className="subhead">Internal endpoints referenced</div>
          <div className="evidence">
            {[...api.metadataEndpoints, ...api.internalEndpoints].map((endpoint) => (
              <div key={endpoint} style={{ color: SEVERITY_COLOR.medium }}>
                {endpoint}
              </div>
            ))}
          </div>
        </>
      )}

      {api && api.endpoints.length > 0 && (
        <>
          <div className="subhead">API endpoints ({api.endpoints.length})</div>
          <div className="evidence">
            {api.endpoints.map((endpoint) => (
              <div key={endpoint.url}>
                {endpoint.kind} · {endpoint.url}
                {endpoint.thirdParty ? '  (third party)' : ''}
              </div>
            ))}
          </div>
        </>
      )}

      <div className="subhead">Summary</div>
      <dl className="facts">
        <Fact label="External scripts" value={data.scriptCount} />
        <Fact
          label="Without integrity"
          value={
            data.scriptsWithoutIntegrity > 0 ? (
              <span style={{ color: SEVERITY_COLOR.medium }}>{data.scriptsWithoutIntegrity}</span>
            ) : (
              0
            )
          }
        />
        <Fact label="Third-party origins" value={data.thirdPartyOrigins.length} />
        <Fact label="Forms" value={`${data.formCount} (${data.insecureFormCount} insecure)`} />
        {injection && (
          <>
            <Fact
              label="Inline scripts"
              value={`${injection.inlineScriptCount} (${(injection.inlineScriptBytes / 1024).toFixed(1)} KB)`}
            />
            <Fact
              label="DOM sinks fed from URL"
              value={
                taintedSinks > 0 ? (
                  <span style={{ color: SEVERITY_COLOR.high }}>{taintedSinks}</span>
                ) : (
                  0
                )
              }
            />
            <Fact
              label="postMessage listeners"
              value={`${injection.postMessageListeners} (${injection.postMessageOriginChecks} check origin)`}
            />
            <Fact
              label="POST forms without token"
              value={`${injection.postFormsWithoutToken} of ${injection.postFormCount}`}
            />
            <Fact label="Inline event handlers" value={injection.inlineEventHandlers} />
            <Fact
              label="Script files read"
              value={`${injection.externalScriptsAnalysed ?? 0} (${((injection.externalScriptBytes ?? 0) / 1024).toFixed(1)} KB)`}
            />
            {(injection.externalScriptsSkipped ?? 0) > 0 && (
              <Fact
                label="Script files not read"
                value={
                  <span style={{ color: SEVERITY_COLOR.low }}>
                    {injection.externalScriptsSkipped}
                  </span>
                }
              />
            )}
          </>
        )}
        {api && (
          <>
            <Fact
              label="CORS allow-origin"
              value={
                api.cors.allowOrigin === '*' ? (
                  <span style={{ color: SEVERITY_COLOR.low }}>*</span>
                ) : (
                  (api.cors.allowOrigin ?? 'not set')
                )
              }
            />
            <Fact label="CORS credentials" value={api.cors.allowCredentials ? 'allowed' : 'no'} />
            <Fact
              label="Hard-coded auth headers"
              value={
                api.hardcodedAuthHeaders > 0 ? (
                  <span style={{ color: SEVERITY_COLOR.high }}>{api.hardcodedAuthHeaders}</span>
                ) : (
                  0
                )
              }
            />
          </>
        )}
        <Fact label="HTML analysed" value={`${(data.bytesAnalysed / 1024).toFixed(1)} KB`} />
        <Fact label="Truncated" value={data.truncated ? 'yes' : 'no'} />
      </dl>
    </>
  );
}

/* -------------------------------------------------------------------------- */

export function SectionDetails({ section }: { section: SectionReport<unknown> }) {
  if (!section.data) {
    return section.error ? (
      <div
        className="evidence"
        style={{ color: 'var(--sev-high)', borderColor: tint('var(--sev-high)', 30) }}
      >
        {section.error}
      </div>
    ) : null;
  }

  switch (section.id) {
    case 'headers':
      return <HeadersDetails data={section.data as HeadersData} />;
    case 'tls':
      return <TlsDetails data={section.data as TlsData} />;
    case 'dns':
      return <DnsDetails data={section.data as DnsData} />;
    case 'exposure':
      return <ExposureDetails data={section.data as ExposureData} />;
    case 'fingerprint':
      return <FingerprintDetails data={section.data as FingerprintData} />;
    case 'content':
      return <ContentDetails data={section.data as ContentData} />;
    default:
      return null;
  }
}
