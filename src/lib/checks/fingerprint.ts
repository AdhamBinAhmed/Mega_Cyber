/**
 * Passive technology fingerprinting.
 *
 * Reads only what the server already handed us: response headers, cookie
 * names, meta tags and script URLs in the HTML. No JavaScript is executed, no
 * extra paths are requested, and no version claim is ever verified against the
 * live site — a CVE match here means "this version is published as affected",
 * which is a prompt to check, not proof of exploitability.
 */

import type {
  Finding,
  FingerprintData,
  SectionReport,
  Severity,
  TechCategory,
  TechnologyMatch,
  VulnerabilityMatch,
} from '../types';
import { buildSection, sortFindings } from '../scoring';
import type { RawResponse } from '../http';
import { CVE_TABLE } from '../data/cves';
import { inRange } from '../version';

interface HtmlRule {
  pattern: RegExp;
  /** Capture group holding the version, if the pattern finds one. */
  versionGroup?: number;
  evidence: string;
  confidence?: TechnologyMatch['confidence'];
}

interface HeaderRule {
  header: string;
  pattern: RegExp;
  versionGroup?: number;
  confidence?: TechnologyMatch['confidence'];
}

interface Detector {
  name: string;
  category: TechCategory;
  html?: HtmlRule[];
  headers?: HeaderRule[];
  cookies?: RegExp[];
  /**
   * URL token for the generic "library-with-a-version-in-its-path" matcher,
   * e.g. "jquery" matches jquery-3.4.1.min.js and /jquery/3.4.1/jquery.js.
   */
  scriptToken?: string;
  /** Version banner left in a minified bundle, e.g. "jQuery v3.4.1". */
  banner?: RegExp;
}

const DETECTORS: Detector[] = [
  /* ------------------------------- CMS ----------------------------------- */
  {
    name: 'WordPress',
    category: 'cms',
    html: [
      {
        pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s*(\d[\w.+-]*)?/i,
        versionGroup: 1,
        evidence: 'meta[generator]',
      },
      {
        // Only the core assets whose ?ver= really is the core version. Matching
        // any wp-includes asset would happily read jQuery's 3.7.1 and report it
        // as the WordPress version.
        pattern:
          /\/wp-includes\/(?:css\/dashicons\.min\.css|js\/wp-emoji-release\.min\.js|css\/dist\/block-library\/style(?:\.min)?\.css)\?(?:[^"'<>]*&)?ver=(\d[\w.+-]*)/i,
        versionGroup: 1,
        evidence: 'wp-includes core asset version',
        confidence: 'medium',
      },
      { pattern: /\/wp-content\//i, evidence: '/wp-content/ asset path', confidence: 'medium' },
      { pattern: /\/wp-json\//i, evidence: 'WP REST API link', confidence: 'medium' },
    ],
    headers: [{ header: 'link', pattern: /<[^>]*\/wp-json\//i, confidence: 'medium' }],
    cookies: [/^wordpress_/i, /^wp-settings/i],
  },
  {
    name: 'Drupal',
    category: 'cms',
    html: [
      {
        pattern: /<meta[^>]+name=["']Generator["'][^>]+content=["']Drupal\s*(\d[\w.+-]*)?/i,
        versionGroup: 1,
        evidence: 'meta[generator]',
      },
      { pattern: /Drupal\.settings|drupal-data-|\/sites\/(default|all)\//i, evidence: 'Drupal markup', confidence: 'medium' },
    ],
    headers: [
      { header: 'x-generator', pattern: /Drupal\s*([\d.]+)?/i, versionGroup: 1 },
      { header: 'x-drupal-cache', pattern: /.+/, confidence: 'medium' },
    ],
  },
  {
    name: 'Joomla',
    category: 'cms',
    html: [
      {
        pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']Joomla!?\s*(\d[\w.+-]*)?/i,
        versionGroup: 1,
        evidence: 'meta[generator]',
      },
      { pattern: /\/media\/system\/js\/|\/templates\/[^"']+\/css\//i, evidence: 'Joomla asset path', confidence: 'low' },
    ],
  },
  {
    name: 'Ghost',
    category: 'cms',
    html: [
      {
        pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']Ghost\s*(\d[\w.+-]*)?/i,
        versionGroup: 1,
        evidence: 'meta[generator]',
      },
    ],
  },
  {
    name: 'Webflow',
    category: 'cms',
    html: [
      { pattern: /<meta[^>]+content=["']Webflow["']/i, evidence: 'meta[generator]' },
      { pattern: /\.webflow\.(io|com)/i, evidence: 'Webflow asset host', confidence: 'medium' },
    ],
  },
  {
    name: 'Squarespace',
    category: 'cms',
    html: [{ pattern: /static1?\.squarespace\.com|Squarespace\.afterBodyLoad/i, evidence: 'Squarespace assets' }],
    headers: [{ header: 'server', pattern: /Squarespace/i }],
  },
  {
    name: 'Wix',
    category: 'cms',
    html: [{ pattern: /static\.parastorage\.com|wix-?(?:code|perf|bi)/i, evidence: 'Wix assets' }],
    headers: [{ header: 'x-wix-request-id', pattern: /.+/ }],
  },

  /* ---------------------------- E-commerce -------------------------------- */
  {
    name: 'Shopify',
    category: 'ecommerce',
    html: [{ pattern: /cdn\.shopify\.com|Shopify\.theme|shopify-section/i, evidence: 'Shopify assets' }],
    headers: [
      { header: 'x-shopid', pattern: /.+/ },
      { header: 'x-shopify-stage', pattern: /.+/ },
    ],
  },
  {
    name: 'Magento',
    category: 'ecommerce',
    html: [{ pattern: /\/static\/version\d+\/|Magento_\w+\/js|mage\/cookies/i, evidence: 'Magento asset path' }],
    cookies: [/^X-Magento-Vary$/i, /^mage-/i],
  },

  /* ---------------------------- Frameworks -------------------------------- */
  {
    name: 'Next.js',
    category: 'framework',
    html: [
      { pattern: /\/_next\/static\//i, evidence: '/_next/static/ bundle path' },
      { pattern: /id=["']__NEXT_DATA__["']/i, evidence: '__NEXT_DATA__ payload' },
    ],
    headers: [{ header: 'x-powered-by', pattern: /Next\.js\s*([\d.]+)?/i, versionGroup: 1 }],
  },
  {
    name: 'Nuxt',
    category: 'framework',
    html: [{ pattern: /window\.__NUXT__|\/_nuxt\//i, evidence: 'Nuxt runtime payload' }],
  },
  {
    name: 'Gatsby',
    category: 'framework',
    html: [{ pattern: /___gatsby|\/page-data\/|gatsby-announcer/i, evidence: 'Gatsby runtime markers' }],
  },
  {
    name: 'SvelteKit',
    category: 'framework',
    html: [{ pattern: /\/_app\/immutable\/|__sveltekit_/i, evidence: 'SvelteKit bundle path' }],
  },
  {
    name: 'Astro',
    category: 'framework',
    html: [
      { pattern: /\/_astro\/|astro-island/i, evidence: 'Astro bundle path' },
      {
        pattern: /<meta[^>]+name=["']generator["'][^>]+content=["']Astro\s*v?(\d[\w.+-]*)?/i,
        versionGroup: 1,
        evidence: 'meta[generator]',
      },
    ],
  },
  {
    name: 'Angular',
    category: 'framework',
    html: [
      { pattern: /ng-version=["']([\d.]+)["']/i, versionGroup: 1, evidence: 'ng-version attribute' },
    ],
  },
  {
    name: 'AngularJS',
    category: 'framework',
    scriptToken: 'angular',
    banner: /AngularJS\s+v([\d.]+)/i,
    html: [{ pattern: /\sng-app[\s=>]|\sng-controller=/i, evidence: 'ng-app directive', confidence: 'medium' }],
  },
  {
    name: 'React',
    category: 'library',
    html: [
      { pattern: /data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react(?:-dom)?\.production\.min\.js/i, evidence: 'React runtime markers', confidence: 'medium' },
    ],
    scriptToken: 'react',
  },
  {
    name: 'Vue',
    category: 'library',
    scriptToken: 'vue',
    banner: /Vue\.js\s+v([\d.]+)/i,
    html: [{ pattern: /data-v-[0-9a-f]{8}|__VUE_/i, evidence: 'Vue scoped-style attributes', confidence: 'medium' }],
  },
  {
    name: 'Laravel',
    category: 'framework',
    cookies: [/^laravel_session$/i, /^XSRF-TOKEN$/i],
  },
  {
    name: 'Django',
    category: 'framework',
    cookies: [/^csrftoken$/i, /^django_language$/i],
  },
  {
    name: 'Ruby on Rails',
    category: 'framework',
    headers: [{ header: 'x-runtime', pattern: /.+/, confidence: 'medium' }],
    html: [{ pattern: /<meta[^>]+name=["']csrf-param["']/i, evidence: 'csrf-param meta tag', confidence: 'medium' }],
  },
  {
    name: 'ASP.NET',
    category: 'framework',
    headers: [
      { header: 'x-aspnet-version', pattern: /([\d.]+)/, versionGroup: 1 },
      { header: 'x-powered-by', pattern: /ASP\.NET/i },
    ],
    html: [{ pattern: /__VIEWSTATE|__EVENTVALIDATION/i, evidence: 'WebForms hidden fields' }],
    cookies: [/^ASP\.NET_SessionId$/i],
  },

  /* ----------------------------- Libraries -------------------------------- */
  {
    name: 'jQuery',
    category: 'library',
    scriptToken: 'jquery',
    banner: /jQuery\s+(?:JavaScript Library\s+)?v?([\d.]+)/i,
  },
  { name: 'jQuery UI', category: 'library', scriptToken: 'jquery-ui', banner: /jQuery UI\s+-?\s*v?([\d.]+)/i },
  { name: 'Bootstrap', category: 'library', scriptToken: 'bootstrap', banner: /Bootstrap\s+v([\d.]+)/i },
  { name: 'Lodash', category: 'library', scriptToken: 'lodash', banner: /lodash\s+(?:<[^>]+>\s+)?v?([\d.]+)/i },
  { name: 'Moment.js', category: 'library', scriptToken: 'moment', banner: /moment(?:\.js)?\s+v?([\d.]+)/i },

  /* ------------------------- Servers & languages --------------------------- */
  {
    name: 'nginx',
    category: 'server',
    headers: [{ header: 'server', pattern: /nginx(?:\/([\d.]+))?/i, versionGroup: 1 }],
  },
  {
    name: 'Apache',
    category: 'server',
    headers: [{ header: 'server', pattern: /Apache(?:\/([\d.]+))?/i, versionGroup: 1 }],
  },
  {
    name: 'Microsoft IIS',
    category: 'server',
    headers: [{ header: 'server', pattern: /Microsoft-IIS(?:\/([\d.]+))?/i, versionGroup: 1 }],
  },
  {
    name: 'LiteSpeed',
    category: 'server',
    headers: [{ header: 'server', pattern: /LiteSpeed(?:\/([\d.]+))?/i, versionGroup: 1 }],
  },
  {
    name: 'PHP',
    category: 'language',
    headers: [{ header: 'x-powered-by', pattern: /PHP\/([\d.]+)/i, versionGroup: 1 }],
    cookies: [/^PHPSESSID$/i],
  },

  /* -------------------------------- CDN ------------------------------------ */
  {
    name: 'Cloudflare',
    category: 'cdn',
    headers: [
      { header: 'server', pattern: /cloudflare/i },
      { header: 'cf-ray', pattern: /.+/ },
    ],
  },
  { name: 'Fastly', category: 'cdn', headers: [{ header: 'x-served-by', pattern: /cache-/i }] },
  { name: 'Vercel', category: 'cdn', headers: [{ header: 'x-vercel-id', pattern: /.+/ }] },
  { name: 'Amazon CloudFront', category: 'cdn', headers: [{ header: 'x-amz-cf-id', pattern: /.+/ }] },

  /* ----------------------------- Analytics --------------------------------- */
  {
    name: 'Google Tag Manager',
    category: 'analytics',
    html: [{ pattern: /googletagmanager\.com\/(?:gtm|gtag)/i, evidence: 'GTM script tag' }],
  },
  {
    name: 'Google Analytics',
    category: 'analytics',
    html: [{ pattern: /google-analytics\.com\/analytics\.js|gtag\('config',\s*'(?:G|UA)-/i, evidence: 'Analytics snippet' }],
  },
];

/**
 * Find "<token>-1.2.3.js", "/<token>/1.2.3/", "<token>.min.js?ver=1.2.3".
 * Returns the first version seen alongside the token, if any.
 */
export function versionFromScriptUrls(html: string, token: string): string | null {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const patterns = [
    new RegExp(`${escaped}[.-](\\d+\\.\\d+(?:\\.\\d+)?)(?:[.-][\\w.]+)?\\.js`, 'i'),
    new RegExp(`[/.]${escaped}[/@](\\d+\\.\\d+(?:\\.\\d+)?)[/"']`, 'i'),
    new RegExp(`${escaped}[^"'<>]*?\\.js\\?[^"'<>]*?ver(?:sion)?=(\\d+\\.\\d+(?:\\.\\d+)?)`, 'i'),
  ];
  for (const pattern of patterns) {
    const match = html.match(pattern);
    if (match?.[1]) return match[1];
  }
  return null;
}

/** Does the page reference this library at all? */
function mentionsToken(html: string, token: string): boolean {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`[/.-]${escaped}[./-]|["'/]${escaped}(?:\\.min)?\\.js`, 'i').test(html);
}

export function detectTechnologies(
  html: string,
  headers: Record<string, string>,
  cookieNames: string[],
): TechnologyMatch[] {
  const found = new Map<string, TechnologyMatch>();

  const record = (match: TechnologyMatch) => {
    const existing = found.get(match.name);
    if (!existing) {
      found.set(match.name, match);
      return;
    }
    // Prefer the sighting that carries a version, then the higher confidence.
    if (!existing.version && match.version) {
      found.set(match.name, match);
    } else if (existing.confidence !== 'high' && match.confidence === 'high') {
      found.set(match.name, { ...match, version: existing.version ?? match.version });
    }
  };

  for (const detector of DETECTORS) {
    for (const rule of detector.headers ?? []) {
      const value = headers[rule.header];
      if (!value) continue;
      const match = value.match(rule.pattern);
      if (!match) continue;
      record({
        name: detector.name,
        category: detector.category,
        version: rule.versionGroup ? (match[rule.versionGroup] ?? null) : null,
        evidence: `header:${rule.header}: ${value.slice(0, 120)}`,
        confidence: rule.confidence ?? 'high',
      });
    }

    for (const rule of detector.html ?? []) {
      const match = html.match(rule.pattern);
      if (!match) continue;
      record({
        name: detector.name,
        category: detector.category,
        version: rule.versionGroup ? (match[rule.versionGroup] ?? null) : null,
        evidence: rule.evidence,
        confidence: rule.confidence ?? 'high',
      });
    }

    for (const pattern of detector.cookies ?? []) {
      const hit = cookieNames.find((name) => pattern.test(name));
      if (!hit) continue;
      record({
        name: detector.name,
        category: detector.category,
        version: null,
        evidence: `cookie:${hit}`,
        confidence: 'medium',
      });
    }

    if (detector.banner) {
      const match = html.match(detector.banner);
      if (match?.[1]) {
        record({
          name: detector.name,
          category: detector.category,
          version: match[1],
          evidence: 'version banner in bundle',
          confidence: 'high',
        });
      }
    }

    if (detector.scriptToken) {
      const version = versionFromScriptUrls(html, detector.scriptToken);
      if (version) {
        record({
          name: detector.name,
          category: detector.category,
          version,
          evidence: `script URL contains ${detector.scriptToken} ${version}`,
          confidence: 'high',
        });
      } else if (mentionsToken(html, detector.scriptToken)) {
        record({
          name: detector.name,
          category: detector.category,
          version: null,
          evidence: `script URL references ${detector.scriptToken}`,
          confidence: 'medium',
        });
      }
    }
  }

  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/** Normalise a display name to the key used in the CVE table. */
function productKey(name: string): string {
  return name.toLowerCase().replace(/\s+/g, '-').replace(/^microsoft-/, '');
}

export function matchVulnerabilities(technologies: TechnologyMatch[]): VulnerabilityMatch[] {
  const matches: VulnerabilityMatch[] = [];

  for (const tech of technologies) {
    if (!tech.version) continue;
    const key = productKey(tech.name);
    for (const entry of CVE_TABLE) {
      if (entry.product !== key) continue;
      if (!inRange(tech.version, entry.introducedIn, entry.fixedIn)) continue;
      matches.push({
        product: tech.name,
        detectedVersion: tech.version,
        fixedIn: entry.fixedIn,
        cves: entry.cves,
        severity: entry.severity,
        cvss: entry.cvss,
        title: entry.title,
        reference: entry.reference,
        endOfLife: entry.endOfLife === true,
      });
    }
  }

  return matches;
}

/**
 * A version-string match is strong evidence but not proof, so we report one
 * step below the published severity for grading purposes. The published
 * severity stays intact in the JSON under vulnerabilities[].severity.
 */
const FINDING_SEVERITY: Record<Severity, Severity> = {
  critical: 'high',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  pass: 'pass',
};

const SEVERITY_PENALTY: Record<Severity, number> = {
  critical: -50,
  high: -30,
  medium: -15,
  low: -5,
  info: 0,
  pass: 0,
};

export function runFingerprintCheck(response: RawResponse): SectionReport<FingerprintData> {
  const startedAt = Date.now();
  const html = response.body;
  const findings: Finding[] = [];

  const cookieNames = (response.rawHeaders['set-cookie'] ?? []).map(
    (raw) => raw.split(';')[0]?.split('=')[0]?.trim() ?? '',
  );

  const technologies = detectTechnologies(html, response.headers, cookieNames);
  const vulnerabilities = matchVulnerabilities(technologies);

  const generatorMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  const generatorMeta = generatorMatch?.[1] ?? null;

  for (const vuln of vulnerabilities) {
    const severity = FINDING_SEVERITY[vuln.severity];
    const cveList = vuln.cves.length > 0 ? vuln.cves.join(', ') : 'no CVE assigned';
    findings.push({
      id: `fingerprint.vuln.${productKey(vuln.product)}.${vuln.cves[0] ?? (vuln.endOfLife ? 'eol' : 'advisory')}`,
      title: `${vuln.product} ${vuln.detectedVersion} — ${vuln.endOfLife ? 'end of life' : 'known vulnerability'}`,
      severity,
      status: 'fail',
      detail:
        `${vuln.title}. Published severity: ${vuln.severity}${vuln.cvss ? ` (CVSS ${vuln.cvss})` : ''}. ` +
        'Matched from the version string in the page, so confirm against your actual deployment before acting.',
      evidence: `${vuln.product} ${vuln.detectedVersion} — ${cveList}`,
      recommendation: vuln.fixedIn
        ? `Upgrade ${vuln.product} to ${vuln.fixedIn} or later.`
        : `Migrate off ${vuln.product} ${vuln.detectedVersion}; this line no longer receives security fixes.`,
      scoreImpact: SEVERITY_PENALTY[severity],
      references: [vuln.reference],
    });
  }

  if (generatorMeta) {
    findings.push({
      id: 'fingerprint.generator-disclosed',
      title: 'Page advertises its CMS and version',
      severity: 'low',
      status: 'warn',
      detail:
        'The generator meta tag tells any visitor exactly what software and version you run, which is the first thing an attacker checks against public advisories.',
      evidence: generatorMeta,
      recommendation: 'Remove the generator meta tag; it has no functional purpose.',
      scoreImpact: -5,
    });
  }

  if (technologies.length === 0) {
    findings.push({
      id: 'fingerprint.none',
      title: 'No recognisable technology signatures',
      severity: 'pass',
      status: 'pass',
      detail: 'Nothing in the headers or HTML identified a specific CMS, framework or library version.',
      scoreImpact: 0,
    });
  } else if (vulnerabilities.length === 0) {
    findings.push({
      id: 'fingerprint.no-known-vulns',
      title: 'No known-vulnerable versions detected',
      severity: 'pass',
      status: 'pass',
      detail: `Identified ${technologies.length} component${technologies.length === 1 ? '' : 's'}; none matched the scanner's advisory table.`,
      evidence: technologies
        .map((tech) => (tech.version ? `${tech.name} ${tech.version}` : tech.name))
        .join(', '),
      scoreImpact: 0,
    });
  }

  const versioned = technologies.filter((tech) => tech.version);
  if (versioned.length > 0) {
    findings.push({
      id: 'fingerprint.components',
      title: `${versioned.length} component version${versioned.length === 1 ? '' : 's'} identified`,
      severity: 'info',
      status: 'info',
      detail: 'Versions readable from the public page let anyone cross-reference your stack against advisory feeds.',
      evidence: versioned.map((tech) => `${tech.name} ${tech.version}`).join(', '),
      scoreImpact: 0,
    });
  }

  const data: FingerprintData = {
    technologies,
    vulnerabilities,
    htmlBytesAnalysed: response.bodyBytes,
    generatorMeta,
  };

  const summary =
    vulnerabilities.length > 0
      ? `${vulnerabilities.length} known issue${vulnerabilities.length === 1 ? '' : 's'} across ${
          new Set(vulnerabilities.map((v) => v.product)).size
        } component${new Set(vulnerabilities.map((v) => v.product)).size === 1 ? '' : 's'}.`
      : `${technologies.length} technolog${technologies.length === 1 ? 'y' : 'ies'} identified, no known-vulnerable versions.`;

  return buildSection('fingerprint', data, sortFindings(findings), summary, Date.now() - startedAt);
}
