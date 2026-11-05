import type { Metadata, Viewport } from 'next';
import { Inter, Manrope } from 'next/font/google';

import './globals.css';

/**
 * next/font downloads and self-hosts these at build time, so they are served
 * from our own origin. A CDN <link> would mean loosening the CSP — not a trade
 * worth making on a tool whose whole job is to tell people their CSP is weak.
 */
const inter = Inter({
  subsets: ['latin'],
  variable: '--font-inter',
  display: 'swap',
});

const manrope = Manrope({
  subsets: ['latin'],
  variable: '--font-manrope',
  display: 'swap',
});

/**
 * Set NEXT_PUBLIC_SITE_URL to the deployed origin. Absolute URLs matter here:
 * Google and every link-preview crawler need them to resolve the icon and the
 * share image.
 */
const siteUrl = process.env.NEXT_PUBLIC_SITE_URL?.trim() || 'https://scanner.megadevs.example';

const title = 'Passive Security Scan — MEGADevs';
const description =
  'Free passive security assessment: HTTP security headers, SSL/TLS, DNS and email authentication, exposed files, leaked credentials and known-vulnerable components. Read-only — nothing is exploited.';

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title,
  description,
  applicationName: 'MEGADevs Passive Scanner',
  robots: { index: true, follow: true },
  // src/app/icon.png and apple-icon.png are picked up by Next's file
  // convention; these entries pin the sizes so crawlers pick the right one.
  icons: {
    icon: [{ url: '/icon.png', sizes: '480x480', type: 'image/png' }],
    apple: [{ url: '/apple-icon.png', sizes: '180x180', type: 'image/png' }],
    shortcut: ['/icon.png'],
  },
  openGraph: {
    type: 'website',
    url: siteUrl,
    siteName: 'MEGADevs',
    title,
    description,
    images: [{ url: '/megadevs-logo.png', width: 1600, height: 605, alt: 'MEGADevs' }],
  },
  twitter: {
    card: 'summary_large_image',
    title,
    description,
    images: ['/megadevs-logo.png'],
  },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#000000',
};

/**
 * Organization structured data. This is what Google reads to associate a logo
 * with the site in search results and the knowledge panel — the favicon alone
 * only covers the small icon next to the result.
 */
const organizationJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'Organization',
  name: 'MEGADevs',
  alternateName: 'MEGADevs Engineering Studio',
  url: siteUrl,
  logo: {
    '@type': 'ImageObject',
    url: `${siteUrl}/megadevs-logo.png`,
    width: 1600,
    height: 605,
  },
};

const webSiteJsonLd = {
  '@context': 'https://schema.org',
  '@type': 'WebSite',
  name: 'MEGADevs Passive Security Scanner',
  url: siteUrl,
  description,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${manrope.variable}`}>
      <body>
        <script
          type="application/ld+json"
          // Static, author-controlled JSON. Nothing user-supplied reaches it.
          dangerouslySetInnerHTML={{
            __html: JSON.stringify([organizationJsonLd, webSiteJsonLd]),
          }}
        />

        {/* Fixed backdrop: red wash, drifting starfield, glow, masked grid. */}
        <div className="backdrop" aria-hidden>
          <div className="backdrop-wash" />
          <div className="stars stars-near" />
          <div className="stars stars-far" />
          <div className="backdrop-glow" />
          <div className="backdrop-grid" />
        </div>
        <div className="top-fade" aria-hidden />
        {children}
      </body>
    </html>
  );
}
