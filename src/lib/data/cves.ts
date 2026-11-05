/**
 * Static vulnerability lookup table.
 *
 * This is a deliberately small, hand-curated list of widely-exploited issues in
 * software this scanner can fingerprint passively. It is NOT a vulnerability
 * database and makes no claim to completeness — a match means "this version is
 * published as affected", not "this site is exploitable", and the scanner never
 * attempts to verify a match against the live site.
 *
 * Keep entries conservative: a false "you are vulnerable" costs a client's
 * trust. Last reviewed: 2025-11.
 */

import type { Severity } from '../types';

export interface CveEntry {
  /** Lower-case product key matched against detected technology names. */
  product: string;
  /** Lowest affected version, if the issue was introduced partway through. */
  introducedIn?: string;
  /** First fixed version. null means "no fixed version — the line is dead". */
  fixedIn: string | null;
  cves: string[];
  severity: Severity;
  cvss: number | null;
  title: string;
  reference: string;
  /** The whole version line is unsupported, not just vulnerable to this bug. */
  endOfLife?: boolean;
}

export const CVE_TABLE: CveEntry[] = [
  /* ----------------------------- jQuery ---------------------------------- */
  {
    product: 'jquery',
    introducedIn: '1.0.3',
    fixedIn: '3.5.0',
    cves: ['CVE-2020-11022', 'CVE-2020-11023'],
    severity: 'medium',
    cvss: 6.1,
    title: 'Cross-site scripting when untrusted HTML is passed to jQuery DOM manipulation methods',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2020-11022',
  },
  {
    product: 'jquery',
    fixedIn: '3.4.0',
    cves: ['CVE-2019-11358'],
    severity: 'medium',
    cvss: 6.1,
    title: 'Prototype pollution via jQuery.extend(true, {}, ...)',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2019-11358',
  },
  {
    product: 'jquery',
    fixedIn: '3.0.0',
    cves: ['CVE-2015-9251'],
    severity: 'medium',
    cvss: 6.1,
    title: 'Cross-domain AJAX responses executed as script when no dataType is given',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2015-9251',
  },
  {
    product: 'jquery',
    fixedIn: '3.0.0',
    cves: [],
    severity: 'low',
    cvss: null,
    title: 'jQuery 1.x and 2.x are no longer maintained and receive no security fixes',
    reference: 'https://jquery.com/download/',
    endOfLife: true,
  },
  {
    product: 'jquery-ui',
    fixedIn: '1.13.2',
    cves: ['CVE-2022-31160'],
    severity: 'medium',
    cvss: 6.1,
    title: 'XSS in the checkboxradio widget when a label contains untrusted HTML',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2022-31160',
  },

  /* ---------------------------- Bootstrap -------------------------------- */
  {
    product: 'bootstrap',
    introducedIn: '4.0.0',
    fixedIn: '4.3.1',
    cves: ['CVE-2019-8331'],
    severity: 'medium',
    cvss: 6.1,
    title: 'XSS in tooltip and popover via the data-template attribute',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2019-8331',
  },
  {
    product: 'bootstrap',
    fixedIn: '3.4.1',
    cves: ['CVE-2019-8331', 'CVE-2018-14041', 'CVE-2016-10735'],
    severity: 'medium',
    cvss: 6.1,
    title: 'Multiple XSS issues in tooltip, scrollspy and data-target handling',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2019-8331',
  },
  {
    product: 'bootstrap',
    fixedIn: '4.0.0',
    cves: [],
    severity: 'low',
    cvss: null,
    title: 'Bootstrap 3 reached end of life in 2019 and receives no further fixes',
    reference: 'https://blog.getbootstrap.com/2019/07/24/lts-plan/',
    endOfLife: true,
  },

  /* ---------------------------- AngularJS -------------------------------- */
  {
    product: 'angularjs',
    fixedIn: null,
    cves: ['CVE-2024-21490', 'CVE-2023-26118', 'CVE-2023-26116'],
    severity: 'high',
    cvss: 7.5,
    title:
      'AngularJS 1.x is end-of-life (since January 2022). Known ReDoS issues will never be patched.',
    reference: 'https://docs.angularjs.org/misc/version-support-status',
    endOfLife: true,
  },

  /* ------------------------------ Lodash --------------------------------- */
  {
    product: 'lodash',
    fixedIn: '4.17.21',
    cves: ['CVE-2021-23337'],
    severity: 'high',
    cvss: 7.2,
    title: 'Command injection via lodash.template',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
  },
  {
    product: 'lodash',
    fixedIn: '4.17.19',
    cves: ['CVE-2020-8203'],
    severity: 'high',
    cvss: 7.4,
    title: 'Prototype pollution in zipObjectDeep',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2020-8203',
  },
  {
    product: 'lodash',
    fixedIn: '4.17.12',
    cves: ['CVE-2019-10744'],
    severity: 'critical',
    cvss: 9.1,
    title: 'Prototype pollution in defaultsDeep',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2019-10744',
  },

  /* ------------------------------ Moment --------------------------------- */
  {
    product: 'moment.js',
    fixedIn: '2.29.4',
    cves: ['CVE-2022-31129'],
    severity: 'high',
    cvss: 7.5,
    title: 'Regular expression denial of service when parsing long date strings',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2022-31129',
  },
  {
    product: 'moment.js',
    fixedIn: '2.29.2',
    cves: ['CVE-2022-24785'],
    severity: 'high',
    cvss: 7.5,
    title: 'Path traversal in the locale loader',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2022-24785',
  },

  /* ----------------------------- WordPress ------------------------------- */
  {
    product: 'wordpress',
    fixedIn: '5.8.3',
    cves: ['CVE-2022-21661', 'CVE-2022-21662', 'CVE-2022-21663', 'CVE-2022-21664'],
    severity: 'high',
    cvss: 8.0,
    title: 'SQL injection in WP_Query and WP_Meta_Query, stored XSS and object injection',
    reference: 'https://wordpress.org/news/2022/01/wordpress-5-8-3-security-release/',
  },
  {
    product: 'wordpress',
    fixedIn: '6.4.3',
    cves: ['CVE-2024-31210'],
    severity: 'high',
    cvss: 7.2,
    title: 'PHP file upload bypass allowing remote code execution by an authenticated author',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-31210',
  },
  {
    product: 'wordpress',
    fixedIn: '6.5.5',
    cves: ['CVE-2024-6307'],
    severity: 'medium',
    cvss: 6.4,
    title: 'Stored cross-site scripting in the HTML API',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-6307',
  },

  /* ------------------------------ Drupal --------------------------------- */
  {
    product: 'drupal',
    introducedIn: '7.0',
    fixedIn: '7.58',
    cves: ['CVE-2018-7600'],
    severity: 'critical',
    cvss: 9.8,
    title: 'Drupalgeddon 2 — unauthenticated remote code execution',
    reference: 'https://www.drupal.org/sa-core-2018-002',
  },
  {
    product: 'drupal',
    introducedIn: '8.0',
    fixedIn: '8.5.1',
    cves: ['CVE-2018-7600'],
    severity: 'critical',
    cvss: 9.8,
    title: 'Drupalgeddon 2 — unauthenticated remote code execution',
    reference: 'https://www.drupal.org/sa-core-2018-002',
  },
  {
    product: 'drupal',
    fixedIn: '9.0',
    cves: [],
    severity: 'high',
    cvss: null,
    title: 'Drupal 7 and 8 are end-of-life and no longer receive security coverage',
    reference: 'https://www.drupal.org/psa-2023-06-07',
    endOfLife: true,
  },

  /* ------------------------------ Next.js -------------------------------- */
  {
    product: 'next.js',
    introducedIn: '15.0.0',
    fixedIn: '15.2.3',
    cves: ['CVE-2025-29927'],
    severity: 'critical',
    cvss: 9.1,
    title: 'Middleware authorization bypass via a crafted x-middleware-subrequest header',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-29927',
  },
  {
    product: 'next.js',
    introducedIn: '14.0.0',
    fixedIn: '14.2.25',
    cves: ['CVE-2025-29927'],
    severity: 'critical',
    cvss: 9.1,
    title: 'Middleware authorization bypass via a crafted x-middleware-subrequest header',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-29927',
  },
  {
    product: 'next.js',
    introducedIn: '13.0.0',
    fixedIn: '13.5.9',
    cves: ['CVE-2025-29927', 'CVE-2024-46982'],
    severity: 'critical',
    cvss: 9.1,
    title: 'Middleware authorization bypass and cache poisoning',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2025-29927',
  },

  /* -------------------------------- Vue ---------------------------------- */
  {
    product: 'vue',
    fixedIn: '3.0.0',
    cves: [],
    severity: 'low',
    cvss: null,
    title: 'Vue 2 reached end of life on 31 December 2023',
    reference: 'https://v2.vuejs.org/eol/',
    endOfLife: true,
  },

  /* -------------------------------- PHP ---------------------------------- */
  {
    product: 'php',
    introducedIn: '8.3.0',
    fixedIn: '8.3.8',
    cves: ['CVE-2024-4577'],
    severity: 'critical',
    cvss: 9.8,
    title: 'CGI argument injection leading to remote code execution (Windows installations)',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
  },
  {
    product: 'php',
    introducedIn: '8.2.0',
    fixedIn: '8.2.20',
    cves: ['CVE-2024-4577'],
    severity: 'critical',
    cvss: 9.8,
    title: 'CGI argument injection leading to remote code execution (Windows installations)',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-4577',
  },
  {
    product: 'php',
    fixedIn: '8.1.0',
    cves: [],
    severity: 'high',
    cvss: null,
    title: 'This PHP branch is past end of life and no longer receives security fixes',
    reference: 'https://www.php.net/supported-versions.php',
    endOfLife: true,
  },

  /* ------------------------------ Apache --------------------------------- */
  {
    product: 'apache',
    introducedIn: '2.4.49',
    fixedIn: '2.4.51',
    cves: ['CVE-2021-41773', 'CVE-2021-42013'],
    severity: 'critical',
    cvss: 9.8,
    title: 'Path traversal and remote code execution in mod_cgi (actively exploited)',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013',
  },
  {
    product: 'apache',
    introducedIn: '2.4.0',
    fixedIn: '2.4.59',
    cves: ['CVE-2024-27316', 'CVE-2023-25690'],
    severity: 'high',
    cvss: 7.5,
    title: 'HTTP/2 memory exhaustion and HTTP request smuggling via mod_proxy rewrites',
    reference: 'https://httpd.apache.org/security/vulnerabilities_24.html',
  },

  /* ------------------------------- nginx --------------------------------- */
  {
    product: 'nginx',
    fixedIn: '1.21.0',
    cves: ['CVE-2021-23017'],
    severity: 'critical',
    cvss: 9.4,
    title: 'Off-by-one in the DNS resolver allowing remote code execution',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017',
  },
  {
    product: 'nginx',
    fixedIn: '1.17.7',
    cves: ['CVE-2019-20372'],
    severity: 'medium',
    cvss: 5.3,
    title: 'HTTP request smuggling via error_page handling',
    reference: 'https://nvd.nist.gov/vuln/detail/CVE-2019-20372',
  },
];

/** Index for quick lookup by product key. */
export function entriesFor(product: string): CveEntry[] {
  const key = product.toLowerCase();
  return CVE_TABLE.filter((entry) => entry.product === key);
}
