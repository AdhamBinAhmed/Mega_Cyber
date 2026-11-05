/**
 * Inline SVG icons (Lucide geometry, hand-inlined).
 *
 * The design reference pulled these from the Iconify CDN. Inlining them keeps
 * the page working under a strict `default-src 'self'` policy and costs one
 * network request less.
 */

type IconProps = { className?: string };

const base = {
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 2,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
};

export function ArrowRight({ className }: IconProps) {
  return (
    <svg {...base} className={className} width="16" height="16">
      <path d="M5 12h14M12 5l7 7-7 7" />
    </svg>
  );
}

export function ShieldCheck({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
      <path d="m9 12 2 2 4-4" />
    </svg>
  );
}

export function Lock({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}

export function FileSearch({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M14 2v4a2 2 0 0 0 2 2h4" />
      <path d="M4.3 21.7A2 2 0 0 0 6 22h12a2 2 0 0 0 2-2V7l-5-5H6a2 2 0 0 0-2 2v3" />
      <circle cx="6" cy="14" r="3" />
      <path d="m9 17 2 2" />
    </svg>
  );
}

export function Globe({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" />
      <path d="M2 12h20" />
    </svg>
  );
}

export function Layers({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="m12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83z" />
      <path d="m6.08 12-3.49 1.59a1 1 0 0 0 0 1.83l8.59 3.9a2 2 0 0 0 1.65 0l8.59-3.9a1 1 0 0 0 0-1.83L17.92 12" />
    </svg>
  );
}

export function Ban({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <circle cx="12" cy="12" r="10" />
      <path d="m4.9 4.9 14.2 14.2" />
    </svg>
  );
}

export function Eye({ className }: IconProps) {
  return (
    <svg {...base} className={className}>
      <path d="M2.06 12.35a1 1 0 0 1 0-.7 10.75 10.75 0 0 1 19.88 0 1 1 0 0 1 0 .7 10.75 10.75 0 0 1-19.88 0" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

export function Caret({ className, open }: IconProps & { open?: boolean }) {
  return (
    <svg
      {...base}
      className={className}
      data-open={open}
      width="14"
      height="14"
      viewBox="0 0 16 16"
      strokeWidth={1.8}
    >
      <path d="M6 3l5 5-5 5" />
    </svg>
  );
}
