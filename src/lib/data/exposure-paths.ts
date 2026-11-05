/**
 * Well-known paths the scanner requests.
 *
 * Every entry is a single plain GET of a conventional, documented location —
 * the same request a browser or search engine crawler would make. Nothing here
 * guesses at filenames, walks directories, or does anything with a file that
 * turns out to be readable: the scanner reports the status code and stops.
 */

import type { Severity } from '../types';

export interface ExposurePath {
  path: string;
  /** What the file is, in plain language. */
  description: string;
  /** Severity if the file really is readable. */
  severity: Severity;
  /**
   * Content signatures. A 200 that matches none of these is almost always a
   * catch-all route serving the SPA shell, not the file itself.
   */
  signatures?: RegExp[];
  /** Presence is a good sign rather than a problem. */
  positive?: boolean;
  /** Presence is entirely normal and carries no score. */
  neutral?: boolean;
  recommendation?: string;
}

export const EXPOSURE_PATHS: ExposurePath[] = [
  {
    path: '/robots.txt',
    description: 'Crawler directives',
    severity: 'info',
    neutral: true,
    signatures: [/user-agent\s*:/i, /disallow\s*:/i, /sitemap\s*:/i],
  },
  {
    path: '/.well-known/security.txt',
    description: 'Vulnerability disclosure contact (RFC 9116)',
    severity: 'info',
    positive: true,
    signatures: [/contact\s*:/i],
  },
  {
    path: '/sitemap.xml',
    description: 'XML sitemap',
    severity: 'info',
    neutral: true,
    signatures: [/<urlset|<sitemapindex/i],
  },
  {
    path: '/.env',
    description: 'Environment file — typically holds database credentials and API keys',
    severity: 'critical',
    signatures: [
      /^\s*[A-Z][A-Z0-9_]{2,}\s*=/m,
      /\b(APP_KEY|DB_PASSWORD|DB_USERNAME|SECRET_KEY|AWS_ACCESS_KEY_ID|STRIPE_[A-Z_]*KEY)\b/,
    ],
    recommendation:
      'Move the file outside the web root immediately and rotate every credential it contains — assume it has been read.',
  },
  {
    path: '/.git/config',
    description: 'Git repository config — exposes the remote URL and often the whole source tree',
    severity: 'critical',
    signatures: [/\[core\]/i, /repositoryformatversion/i, /\[remote\s+"/i],
    recommendation:
      'Block access to .git at the web server and stop deploying the repository directory to production.',
  },
  {
    path: '/.git/HEAD',
    description: 'Git HEAD pointer — confirms a downloadable repository',
    severity: 'critical',
    signatures: [/^ref:\s+refs\//m, /^[0-9a-f]{40}\s*$/m],
    recommendation: 'Deny all requests under /.git/ at the web server or CDN.',
  },
  {
    path: '/wp-config.php.bak',
    description: 'WordPress config backup — served as text, so the database password is readable',
    severity: 'critical',
    signatures: [/DB_PASSWORD/i, /define\s*\(/i, /<\?php/i],
    recommendation: 'Delete the backup from the web root and rotate the database credentials.',
  },
  {
    path: '/.htaccess',
    description: 'Apache configuration — reveals rewrite rules and protected paths',
    severity: 'medium',
    signatures: [/RewriteEngine/i, /<Files|<Directory|Order\s+(allow|deny)/i, /AuthUserFile/i],
    recommendation: 'Apache should refuse .ht* by default; restore the default FilesMatch rule.',
  },
  {
    path: '/.svn/entries',
    description: 'Subversion metadata — exposes the source tree',
    severity: 'high',
    signatures: [/^\d+\s*$/m, /svn:/i, /dir\s*$/m],
    recommendation: 'Remove the .svn directory from the deployed site.',
  },
  {
    path: '/.DS_Store',
    description: 'macOS folder index — leaks the names of files in the directory',
    severity: 'low',
    signatures: [/Bud1/],
    recommendation: 'Delete it and add .DS_Store to .gitignore and your deploy ignore list.',
  },
  {
    path: '/phpinfo.php',
    description: 'phpinfo() output — full PHP configuration, paths and loaded modules',
    severity: 'high',
    signatures: [/phpinfo\(\)/i, /PHP Version\s*<?\/?/i, /Loaded Configuration File/i],
    recommendation: 'Delete the file; it is a diagnostic page that should never reach production.',
  },
  {
    path: '/server-status',
    description: 'Apache mod_status — live request log including URLs and client IPs',
    severity: 'medium',
    signatures: [/Apache Server Status/i, /Server uptime/i],
    recommendation: 'Restrict mod_status to localhost, or disable it.',
  },
];

/** Paths in robots.txt that advertise something worth a closer look. */
export const SENSITIVE_ROBOTS_PATTERNS =
  /(admin|backup|\.git|config|private|secret|internal|staging|db|sql|phpmyadmin|wp-admin|\.env|dump|old|test)/i;
