/**
 * The scanner is designed to be embedded in the MEGA Devs website.
 * Set EMBED_ANCESTORS to a space-separated list of origins allowed to iframe it,
 * e.g. "https://megadevs.example https://www.megadevs.example".
 * Leave unset to forbid framing entirely (safest default).
 */
const embedAncestors = process.env.EMBED_ANCESTORS?.trim();
const frameAncestors = embedAncestors ? `'self' ${embedAncestors}` : `'none'`;

/**
 * Next's development server compiles with eval-based source maps and HMR, so
 * it genuinely needs 'unsafe-eval'. Without it the CSP below blocks React from
 * hydrating: the page renders and looks fine, but nothing is interactive —
 * typing in the URL field never reaches React, so the scan button stays
 * disabled as though the field were empty.
 *
 * Production builds do not use eval, so the deployed policy stays strict.
 */
const isDev = process.env.NODE_ENV !== 'production';
const scriptSrc = isDev
  ? `'self' 'unsafe-inline' 'unsafe-eval'`
  : `'self' 'unsafe-inline'`;

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Pin the trace root to this project; a stray lockfile in a parent directory
  // otherwise makes Next guess wrong and bundle the wrong files.
  outputFileTracingRoot: import.meta.dirname,
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()' },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          {
            key: 'Content-Security-Policy',
            value: [
              `default-src 'self'`,
              `script-src ${scriptSrc}`,
              `style-src 'self' 'unsafe-inline'`,
              `img-src 'self' data:`,
              // next/font self-hosts the webfonts under /_next/static.
              `font-src 'self'`,
              `connect-src 'self'`,
              `base-uri 'self'`,
              `form-action 'self'`,
              `object-src 'none'`,
              `frame-ancestors ${frameAncestors}`,
            ].join('; '),
          },
        ],
      },
    ];
  },
};

export default nextConfig;
