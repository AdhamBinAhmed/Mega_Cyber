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

export const metadata: Metadata = {
  title: 'Passive Security Scan — MEGA Devs Cyber Team',
  description:
    'Free passive security assessment: HTTP security headers, SSL/TLS, DNS and email authentication, exposed files, and known-vulnerable components. Read-only — nothing is exploited.',
  robots: { index: true, follow: true },
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
  themeColor: '#000000',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${inter.variable} ${manrope.variable}`}>
      <body>
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
