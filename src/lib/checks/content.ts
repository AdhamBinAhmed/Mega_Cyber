/**
 * Page content analysis.
 *
 * Everything here reads the document the scanner already fetched — no extra
 * request to the target, no JavaScript executed. It is the cheapest tier of
 * check in the whole scanner and, because leaked credentials and unpinned
 * third-party script live here, among the most valuable.
 *
 * Accuracy discipline: a confident wrong "you are leaking an AWS key" costs
 * more trust than ten missed findings, so candidates must clear an entropy
 * bar, dodge a placeholder blocklist, and keys that are public by design are
 * classified as such rather than reported as leaks.
 *
 * The client-side injection surface (DOM XSS, reflected parameters,
 * postMessage, CSRF tokens) and the API surface it leaks (CORS, endpoint
 * inventory, tokens, internal hosts) are analysed from the same document by
 * ./injection and ./api, and folded in here, so they cost no extra request.
 */

import type { ContentData, Finding, SectionReport, Severity } from '../types';
import { buildSection, sortFindings } from '../scoring';
import type { RawResponse } from '../http';
import { entropy, looksLikeRealSecret, maskValue, redact } from '../redact';
import { EXAMPLE_MARKERS, SECRET_PATTERNS } from '../data/secrets';
import { analyseInjection } from './injection';
import { analyseApiSurface } from './api';
import { registrableDomain } from '../target';

/** Attribute value extractor that tolerates single, double or no quotes. */
function attr(tag: string, name: string): string | null {
  const match = tag.match(new RegExp(`\\b${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return match?.[2] ?? match?.[3] ?? match?.[4] ?? null;
}

function tagsOf(html: string, tagName: string): string[] {
  return html.match(new RegExp(`<${tagName}\\b[^>]*>`, 'gi')) ?? [];
}

function originOf(url: string, base: URL): string | null {
  try {
    return new URL(url, base).origin;
  } catch {
    return null;
  }
}

function isCrossOrigin(url: string, base: URL): boolean {
  const origin = originOf(url, base);
  return origin !== null && origin !== base.origin;
}

/**
 * Is this origin plausibly the site's own asset host?
 *
 * Plenty of sites serve static files from a different origin they control
 * (static.example.com, cdn.example.com). Calling those "a third party who can
 * change your site" overstates the risk and makes the whole finding easy to
 * dismiss. Comparing registrable domains catches the common case; a separate
 * brand-owned domain (github.com serving from githubassets.com) cannot be
 * told apart from a genuine third party without an affiliate list, so the
 * wording stays honest about that limit.
 */
function isLikelyOwnHost(origin: string, base: URL): boolean {
  try {
    return registrableDomain(new URL(origin).hostname) === registrableDomain(base.hostname);
  } catch {
    return false;
  }
}

/* -------------------------------------------------------------------------- */
/* Secrets                                                                    */
/* -------------------------------------------------------------------------- */

interface SecretHit {
  patternId: string;
  name: string;
  severity: Severity;
  publicByDesign: boolean;
  /** Already masked. The raw value never leaves this function. */
  masked: string;
  /** Where in the document, as a rough line number. */
  line: number;
  recommendation: string;
}

function lineOf(html: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < html.length; i += 1) {
    if (html[i] === '\n') line += 1;
  }
  return line;
}

export function findSecrets(html: string): SecretHit[] {
  const hits: SecretHit[] = [];
  const seen = new Set<string>();

  for (const spec of SECRET_PATTERNS) {
    // Patterns are module-level and global, so reset lastIndex per document.
    const pattern = new RegExp(spec.pattern.source, spec.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(html)) !== null) {
      const value = match[1];
      if (!value) continue;

      // Documentation values are not leaks. Judge the whole line, not just the
      // matched text: "see https://example.com for your api_key = ..." puts the
      // marker outside the match entirely.
      const lineStart = html.lastIndexOf('\n', match.index) + 1;
      const lineEnd = html.indexOf('\n', match.index);
      const contextLine = html.slice(lineStart, lineEnd === -1 ? html.length : lineEnd);
      if (EXAMPLE_MARKERS.test(contextLine)) continue;

      // Shape alone is proof for prefixed tokens (AKIA…, sk_live_…). The
      // generic "something = <string>" pattern needs the entropy bar, or it
      // fires on every minified variable assignment on the internet.
      if (spec.minEntropy !== undefined && !looksLikeRealSecret(value, spec.minEntropy)) {
        continue;
      }

      const key = `${spec.id}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);

      hits.push({
        patternId: spec.id,
        name: spec.name,
        severity: spec.severity,
        publicByDesign: spec.publicByDesign === true,
        masked: maskValue(value),
        line: lineOf(html, match.index),
        recommendation: spec.recommendation,
      });

      // One example per pattern is enough to act on; more just bloats reports.
      if (hits.filter((h) => h.patternId === spec.id).length >= 3) break;
    }
  }

  return hits;
}

const SECRET_PENALTY: Record<Severity, number> = {
  critical: -60,
  high: -35,
  medium: -15,
  low: -5,
  info: 0,
  pass: 0,
};

/* -------------------------------------------------------------------------- */
/* Section                                                                    */
/* -------------------------------------------------------------------------- */

export function runContentCheck(
  response: RawResponse,
): SectionReport<ContentData> {
  const startedAt = Date.now();
  const findings: Finding[] = [];
  const html = response.body;
  const base = new URL(response.url);
  const isHttps = base.protocol === 'https:';

  /* ------------------------------ secrets -------------------------------- */
  const secrets = findSecrets(html);
  const leaks = secrets.filter((hit) => !hit.publicByDesign);
  const publicKeys = secrets.filter((hit) => hit.publicByDesign);

  for (const hit of leaks) {
    findings.push({
      id: `content.secret.${hit.patternId}`,
      title: `${hit.name} exposed in page source`,
      severity: hit.severity,
      status: 'fail',
      detail:
        `A value matching the format of a ${hit.name.toLowerCase()} is served in the public page. ` +
        'Anything in page source is readable by every visitor, and is already in search and archive caches. Treat it as compromised.',
      evidence: `line ~${hit.line}: ${hit.masked} (value masked by the scanner)`,
      recommendation: hit.recommendation,
      scoreImpact: SECRET_PENALTY[hit.severity],
      references: [
        'https://owasp.org/www-project-top-ten/2021/A02_2021-Cryptographic_Failures',
      ],
    });
  }

  for (const hit of publicKeys) {
    findings.push({
      id: `content.public-key.${hit.patternId}`,
      title: `${hit.name} present (public by design)`,
      severity: hit.severity,
      status: 'info',
      detail:
        `This key type belongs in page source, so its presence is not a leak. ` +
        'What matters is whether it is restricted.',
      evidence: `line ~${hit.line}: ${hit.masked}`,
      recommendation: hit.recommendation,
      scoreImpact: hit.severity === 'low' ? -5 : 0,
    });
  }

  if (leaks.length === 0) {
    findings.push({
      id: 'content.secret.none',
      title: 'No credentials found in page source',
      severity: 'pass',
      status: 'pass',
      detail: `Checked ${SECRET_PATTERNS.length} credential formats against the served HTML and inline script.`,
      scoreImpact: 0,
    });
  }

  /* ----------------------- scripts, SRI, third parties -------------------- */
  const scriptTags = tagsOf(html, 'script');
  const linkTags = tagsOf(html, 'link');

  const externalScripts = scriptTags
    .map((tag) => ({ tag, src: attr(tag, 'src') }))
    .filter((entry): entry is { tag: string; src: string } => Boolean(entry.src));

  const crossOriginScripts = externalScripts.filter((entry) => isCrossOrigin(entry.src, base));
  const unpinned = crossOriginScripts.filter((entry) => !attr(entry.tag, 'integrity'));

  const stylesheets = linkTags
    .map((tag) => ({ tag, href: attr(tag, 'href'), rel: (attr(tag, 'rel') ?? '').toLowerCase() }))
    .filter((entry): entry is { tag: string; href: string; rel: string } =>
      Boolean(entry.href) && entry.rel.includes('stylesheet'),
    );
  const unpinnedStyles = stylesheets.filter(
    (entry) => isCrossOrigin(entry.href, base) && !attr(entry.tag, 'integrity'),
  );

  const allCrossOrigins = [
    ...new Set(
      [
        ...crossOriginScripts.map((entry) => originOf(entry.src, base)),
        ...stylesheets
          .filter((entry) => isCrossOrigin(entry.href, base))
          .map((entry) => originOf(entry.href, base)),
      ].filter((origin): origin is string => origin !== null),
    ),
  ].sort();

  // Split the site's own asset hosts from genuinely external ones.
  const ownHosts = allCrossOrigins.filter((origin) => isLikelyOwnHost(origin, base));
  const thirdPartyOrigins = allCrossOrigins.filter((origin) => !isLikelyOwnHost(origin, base));

  if (unpinned.length > 0) {
    findings.push({
      id: 'content.sri.missing',
      title: `${unpinned.length} cross-origin script${unpinned.length === 1 ? '' : 's'} loaded without integrity checking`,
      severity: 'medium',
      status: 'fail',
      detail:
        'These scripts run with full access to your pages, and nothing verifies that the file served is the file you expect. Whoever controls that host — or anyone who compromises it — controls your site. That applies to your own CDN as much as to a third party.',
      evidence: unpinned
        .slice(0, 6)
        .map((entry) => entry.src)
        .join('\n'),
      recommendation:
        'Add an integrity="sha384-…" attribute plus crossorigin="anonymous" to each third-party tag, or self-host the file so you control what ships.',
      scoreImpact: -15,
      references: ['https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity'],
    });
  } else if (crossOriginScripts.length > 0) {
    findings.push({
      id: 'content.sri.present',
      title: 'Third-party scripts are integrity-pinned',
      severity: 'pass',
      status: 'pass',
      detail: 'Every cross-origin script carries an integrity hash.',
      scoreImpact: 3,
    });
  }

  if (unpinnedStyles.length > 0) {
    findings.push({
      id: 'content.sri.missing-style',
      title: `${unpinnedStyles.length} cross-origin stylesheet${unpinnedStyles.length === 1 ? '' : 's'} without integrity checking`,
      severity: 'low',
      status: 'warn',
      detail:
        'CSS can exfiltrate data and reshape the page. A tampered stylesheet from a third party is a real, if quieter, risk than script.',
      evidence: unpinnedStyles
        .slice(0, 5)
        .map((entry) => entry.href)
        .join('\n'),
      recommendation: 'Add integrity hashes, or self-host the stylesheet.',
      scoreImpact: -5,
    });
  }

  if (thirdPartyOrigins.length > 0) {
    const many = thirdPartyOrigins.length >= 8;
    findings.push({
      id: 'content.third-party.inventory',
      title: `${thirdPartyOrigins.length} external origin${thirdPartyOrigins.length === 1 ? '' : 's'} can execute on your pages`,
      severity: many ? 'low' : 'info',
      status: many ? 'warn' : 'info',
      detail:
        'Each of these is a different registrable domain serving code into your pages, so each is a party that can change what your site does. This is your live supply chain, and most owners are surprised by the number.',
      evidence: thirdPartyOrigins.join('\n'),
      recommendation: many
        ? 'Review whether each is still needed and remove what is not. Every origin removed is one less party who can compromise you.'
        : undefined,
      scoreImpact: many ? -5 : 0,
    });
  }

  if (ownHosts.length > 0) {
    findings.push({
      id: 'content.own-hosts',
      title: `${ownHosts.length} asset host${ownHosts.length === 1 ? '' : 's'} on your own domain`,
      severity: 'info',
      status: 'info',
      detail:
        'These are cross-origin but share your registrable domain, so they are most likely your own CDN. Listed for completeness — integrity hashes still protect you if one of them is compromised.',
      evidence: ownHosts.join('\n'),
      scoreImpact: 0,
    });
  }

  /* ---------------------------- mixed content ---------------------------- */
  const insecureRefs: string[] = [];
  if (isHttps) {
    const patterns: Array<{ re: RegExp; active: boolean }> = [
      { re: /<script\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi, active: true },
      { re: /<iframe\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi, active: true },
      { re: /<link\b[^>]*\bhref\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi, active: true },
      { re: /<img\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi, active: false },
      { re: /<(?:video|audio|source)\b[^>]*\bsrc\s*=\s*["']?(http:\/\/[^"'\s>]+)/gi, active: false },
    ];

    let activeCount = 0;
    let passiveCount = 0;
    for (const { re, active } of patterns) {
      for (const match of html.matchAll(re)) {
        const url = match[1];
        if (!url) continue;
        insecureRefs.push(url);
        if (active) activeCount += 1;
        else passiveCount += 1;
      }
    }

    if (activeCount > 0) {
      findings.push({
        id: 'content.mixed.active',
        title: `${activeCount} script, frame or stylesheet loaded over plain HTTP`,
        severity: 'high',
        status: 'fail',
        detail:
          'Active mixed content lets anyone on the network path replace code running inside your HTTPS page, which defeats the certificate entirely. Browsers block most of it, so these resources are probably also broken for users.',
        evidence: insecureRefs.slice(0, 6).join('\n'),
        recommendation:
          'Serve these over https://, or use protocol-agnostic absolute URLs. Add upgrade-insecure-requests to your CSP as a safety net.',
        scoreImpact: -30,
        references: ['https://developer.mozilla.org/docs/Web/Security/Mixed_content'],
      });
    }

    if (passiveCount > 0) {
      findings.push({
        id: 'content.mixed.passive',
        title: `${passiveCount} image or media file loaded over plain HTTP`,
        severity: 'medium',
        status: 'warn',
        detail:
          'Passive mixed content can be swapped in transit and causes browsers to drop the secure padlock.',
        evidence: insecureRefs.slice(0, 6).join('\n'),
        recommendation: 'Serve these assets over HTTPS.',
        scoreImpact: -10,
      });
    }

    if (activeCount === 0 && passiveCount === 0) {
      findings.push({
        id: 'content.mixed.none',
        title: 'No mixed content',
        severity: 'pass',
        status: 'pass',
        detail: 'Every subresource referenced in the page is loaded over HTTPS.',
        scoreImpact: 0,
      });
    }
  }

  /* --------------------------- reverse tabnabbing ------------------------- */
  const blankLinks = (html.match(/<a\b[^>]*target\s*=\s*["']?_blank[^>]*>/gi) ?? []).filter(
    (tag) => {
      const href = attr(tag, 'href');
      if (!href || !isCrossOrigin(href, base)) return false;
      const rel = (attr(tag, 'rel') ?? '').toLowerCase();
      return !rel.includes('noopener') && !rel.includes('noreferrer');
    },
  );

  if (blankLinks.length > 0) {
    findings.push({
      id: 'content.tabnabbing',
      title: `${blankLinks.length} external link${blankLinks.length === 1 ? ' opens' : 's open'} a new tab without rel="noopener"`,
      severity: 'low',
      status: 'warn',
      detail:
        'The opened page gets a handle back to yours and can redirect it to a phishing copy while the user is looking at the other tab. Current browsers imply noopener for target=_blank, so this is hygiene rather than an active hole.',
      evidence: blankLinks
        .slice(0, 4)
        .map((tag) => attr(tag, 'href') ?? tag)
        .join('\n'),
      recommendation: 'Add rel="noopener noreferrer" to external target="_blank" links.',
      scoreImpact: -3,
    });
  }

  /* ----------------------------- source maps ----------------------------- */
  const sourceMaps = [
    ...new Set(
      [...html.matchAll(/\/[/*]#\s*sourceMappingURL\s*=\s*([^\s*'"<>]+)/gi)]
        .map((match) => match[1])
        .filter((value): value is string => Boolean(value)),
    ),
  ];

  if (sourceMaps.length > 0) {
    findings.push({
      id: 'content.sourcemap',
      title: 'Source map references found',
      severity: 'low',
      status: 'warn',
      detail:
        'A source map reconstructs your original, unminified source — including comments and file layout. If these maps are reachable, your front-end source is effectively public.',
      evidence: sourceMaps.slice(0, 5).join('\n'),
      recommendation:
        'Stop publishing maps to production, or restrict them to authenticated access. Upload them to your error tracker instead.',
      scoreImpact: -5,
    });
  }

  /* -------------------- internal detail in comments ---------------------- */
  const comments = [...html.matchAll(/<!--([\s\S]{0,2000}?)-->/g)]
    .map((match) => match[1] ?? '')
    .filter((text) => text.trim().length > 0);

  const INTERNAL = [
    { re: /\b(?:10\.\d{1,3}|192\.168\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3})\.\d{1,3}\b/, what: 'internal IP address' },
    { re: /\b(?:staging|uat|preprod|pre-prod|dev|test|internal|intranet)[.-][a-z0-9.-]+\.[a-z]{2,}\b/i, what: 'non-production hostname' },
    { re: /\b[a-z]:\\(?:users|inetpub|xampp|wamp)\\[^\s"'<]+/i, what: 'filesystem path' },
    { re: /\/(?:var\/www|home\/[a-z0-9_-]+|usr\/local)\/[^\s"'<]+/i, what: 'filesystem path' },
    { re: /\b(?:TODO|FIXME|HACK|XXX)\b[^\n]{0,80}\b(?:auth|password|secret|token|security|login)\b/i, what: 'developer note about security' },
    { re: /\b(?:mysql|postgres|mongodb|redis):\/\/[^\s"'<]+/i, what: 'database connection string' },
  ];

  const commentLeaks: string[] = [];
  for (const comment of comments) {
    for (const { re, what } of INTERNAL) {
      const match = comment.match(re);
      if (match) {
        commentLeaks.push(`${what}: ${match[0].slice(0, 90)}`);
        break;
      }
    }
    if (commentLeaks.length >= 6) break;
  }

  if (commentLeaks.length > 0) {
    findings.push({
      id: 'content.comments.internal',
      title: 'HTML comments disclose internal detail',
      severity: 'low',
      status: 'warn',
      detail:
        'Comments ship to every visitor. Internal hostnames, paths and notes give an attacker a map of your infrastructure for free.',
      evidence: commentLeaks.join('\n'),
      recommendation: 'Strip comments in your production build.',
      scoreImpact: -5,
    });
  }

  /* -------------------------------- forms -------------------------------- */
  const forms = tagsOf(html, 'form');
  const insecureForms = forms.filter((tag) => {
    const action = attr(tag, 'action');
    if (!action) return false;
    try {
      return new URL(action, base).protocol === 'http:';
    } catch {
      return false;
    }
  });
  const hasPasswordField = /<input\b[^>]*type\s*=\s*["']?password/i.test(html);

  if (insecureForms.length > 0) {
    findings.push({
      id: 'content.form.insecure-action',
      title: `${insecureForms.length} form${insecureForms.length === 1 ? '' : 's'} submit over plain HTTP`,
      severity: 'high',
      status: 'fail',
      detail:
        'Whatever the user types is sent unencrypted, regardless of the page itself being served over HTTPS. Browsers warn on this.',
      evidence: insecureForms
        .slice(0, 4)
        .map((tag) => attr(tag, 'action') ?? tag)
        .join('\n'),
      recommendation: 'Point every form action at an https:// URL.',
      scoreImpact: -30,
    });
  }

  if (hasPasswordField && !isHttps) {
    findings.push({
      id: 'content.form.password-over-http',
      title: 'Password field served over plain HTTP',
      severity: 'critical',
      status: 'fail',
      detail:
        'Credentials typed into this page travel in clear text and can be read by anyone on the network path.',
      recommendation: 'Serve the login page over HTTPS and redirect all HTTP traffic to it.',
      scoreImpact: -60,
    });
  }

  /* -------------------- client-side injection surface -------------------- */
  // Same document, no extra request. A nonce-based CSP softens the DOM
  // findings, so the policy is passed in rather than looked up again.
  const injection = analyseInjection(
    html,
    base,
    response.headers['content-security-policy'] ??
      response.headers['content-security-policy-report-only'] ??
      null,
  );
  findings.push(...injection.findings);

  /* ---------------------------- API surface ------------------------------ */
  const apiSurface = analyseApiSurface(html, base, response.headers);
  findings.push(...apiSurface.findings);

  /* ------------------------------- assemble ------------------------------ */
  const data: ContentData = {
    bytesAnalysed: response.bodyBytes,
    truncated: response.truncated,
    secrets: secrets.map((hit) => ({
      type: hit.name,
      masked: hit.masked,
      line: hit.line,
      severity: hit.severity,
      publicByDesign: hit.publicByDesign,
    })),
    thirdPartyOrigins,
    scriptCount: externalScripts.length,
    scriptsWithoutIntegrity: unpinned.length,
    mixedContent: [...new Set(insecureRefs)].slice(0, 25),
    sourceMaps,
    formCount: forms.length,
    insecureFormCount: insecureForms.length,
    injection: injection.data,
    apiSurface: apiSurface.data,
  };

  const taintedSinks = injection.data.domSinks.filter(
    (sink) => sink.proximity === 'expression',
  ).length;
  const unencodedReflections = injection.data.reflectedParams.filter(
    (entry) => entry.rawSpecialChars,
  ).length;

  const apiLeaks = findings.filter(
    (finding) =>
      finding.id.startsWith('api.') &&
      (finding.severity === 'critical' || finding.severity === 'high'),
  ).length;

  const summary =
    apiLeaks > 0 && leaks.length === 0
      ? `${apiLeaks} API credential or endpoint leak${apiLeaks === 1 ? '' : 's'} in page source.`
      : leaks.length > 0
      ? `${leaks.length} credential${leaks.length === 1 ? '' : 's'} exposed in page source.`
      : unpinned.length > 0
        ? `${unpinned.length} third-party script${unpinned.length === 1 ? '' : 's'} loaded without integrity checking.`
        : insecureRefs.length > 0
          ? `${insecureRefs.length} subresource${insecureRefs.length === 1 ? '' : 's'} loaded over plain HTTP.`
          : unencodedReflections > 0
            ? `${unencodedReflections} URL parameter${unencodedReflections === 1 ? '' : 's'} reflected into the page unencoded.`
            : taintedSinks > 0
              ? `${taintedSinks} possible DOM XSS sink${taintedSinks === 1 ? '' : 's'} fed from the URL.`
              : 'No credential leaks, mixed content, unpinned third-party script or DOM injection leads.';

  const section = buildSection(
    'content',
    data,
    sortFindings(findings),
    response.truncated ? `${summary} (Only the first part of the page was analysed.)` : summary,
    Date.now() - startedAt,
  );

  // Backstop: no finding leaves this section with an unmasked credential in it,
  // whatever produced the text.
  for (const finding of section.findings) {
    finding.evidence = redact(finding.evidence);
  }

  return section;
}

/** Exposed for tests. */
export { entropy };
