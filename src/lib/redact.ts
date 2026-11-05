/**
 * Redaction for anything that reaches a report.
 *
 * Reports get downloaded, emailed and pasted into tickets. If this scanner
 * finds a live AWS secret key and then prints it verbatim into a JSON file
 * that gets shared around, the scanner has made the leak worse, not better.
 *
 * So no credential value ever leaves this module intact. Enough is shown to
 * let the owner find the thing in their source; never enough to use it.
 */

/** How much of a value stays visible at each end. */
const KEEP = 4;

/**
 * Mask the middle of a value. "AKIAIOSFODNN7EXAMPLE" -> "AKIA············MPLE"
 *
 * Short values are masked almost entirely: there is no safe way to show half
 * of an eight-character secret.
 */
export function maskValue(value: string): string {
  const text = String(value);
  if (text.length <= 8) return '•'.repeat(Math.max(text.length, 3));
  if (text.length <= 12) {
    return `${text.slice(0, 2)}${'•'.repeat(text.length - 4)}${text.slice(-2)}`;
  }
  return `${text.slice(0, KEEP)}${'•'.repeat(Math.min(text.length - KEEP * 2, 24))}${text.slice(-KEEP)}`;
}

/**
 * Patterns that must never appear whole in output, applied to free text as a
 * backstop. This runs over *every* finding's evidence, not just the secret
 * check's, so a credential that turns up incidentally — in an error message,
 * a Set-Cookie value, a URL query string — is caught too.
 */
const ALWAYS_MASK: Array<{ pattern: RegExp; group: number }> = [
  // AWS access key ids
  { pattern: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g, group: 1 },
  // Stripe / GitHub / Slack / npm / SendGrid style prefixed tokens
  { pattern: /\b((?:sk|rk)_live_[0-9a-zA-Z]{10,})\b/g, group: 1 },
  { pattern: /\b(gh[pousr]_[A-Za-z0-9]{20,})\b/g, group: 1 },
  { pattern: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g, group: 1 },
  { pattern: /\b(npm_[A-Za-z0-9]{30,})\b/g, group: 1 },
  { pattern: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g, group: 1 },
  { pattern: /\b(key-[0-9a-f]{32})\b/g, group: 1 },
  // Authorization / Cookie header values. The scheme word is skipped, or we
  // mask "Bearer" and publish the token that follows it.
  {
    pattern:
      /\b(?:authorization|cookie|set-cookie)\s*:\s*(?:(?:bearer|basic|token|digest|apikey)\s+)?(\S+)/gi,
    group: 1,
  },
  // JWTs
  { pattern: /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g, group: 1 },
  // PEM private key bodies: collapse the whole block.
  {
    pattern: /(-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----)/g,
    group: 1,
  },
];

/** Hard ceiling on any evidence string, so a report cannot be bloated. */
const MAX_EVIDENCE = 600;

/**
 * Make a string safe to publish in a report: mask known credential shapes,
 * then truncate.
 */
export function redact(text: string | undefined): string | undefined {
  if (text === undefined) return undefined;

  let output = text;
  for (const { pattern, group } of ALWAYS_MASK) {
    output = output.replace(pattern, (match, ...groups) => {
      const captured = groups[group - 1];
      if (typeof captured !== 'string' || captured.length === 0) return match;
      // A PEM block is replaced wholesale rather than masked character-wise.
      if (captured.includes('PRIVATE KEY')) return '[private key redacted]';
      return match.replace(captured, maskValue(captured));
    });
  }

  return output.length > MAX_EVIDENCE ? `${output.slice(0, MAX_EVIDENCE)}…[truncated]` : output;
}

/**
 * Shannon entropy in bits per character. Used to tell a real credential from
 * a word that merely sits next to the word "token".
 */
export function entropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);

  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * Values that look like credentials but are obviously not. Every one of these
 * was a false positive waiting to happen.
 */
const PLACEHOLDER =
  /^(?:your|my|the|a)?[_-]?(?:api|secret|access|auth|private|client)?[_-]?(?:key|token|secret|password|id)?$|^(?:x{3,}|y{3,}|0{3,}|1{3,}|a{3,}|\.{3,}|\*{3,}|-{3,})$|^(?:changeme|change_me|placeholder|example|sample|dummy|test|testing|todo|tbd|none|null|undefined|false|true|insert|replace|redacted|hidden|secret|password|yourkeyhere|yourapikey|apikeyhere)$/i;

/**
 * Strings like "abc123def456" score well on character frequency — every
 * character is distinct — but are obviously not credentials. Entropy alone
 * cannot tell them apart, so look for sequential runs as well.
 */
const SEQUENTIAL = /abc|bcd|cde|def|efg|123|234|345|456|567|678|789|qwer|asdf|zxcv/gi;

function tooPredictable(value: string): boolean {
  const runs = value.match(SEQUENTIAL) ?? [];
  return runs.length >= 2 && value.length <= 24;
}

/** Does this look like a real secret rather than a template value? */
export function looksLikeRealSecret(value: string, minEntropy = 3): boolean {
  const trimmed = value.trim();
  if (trimmed.length < 8) return false;
  if (PLACEHOLDER.test(trimmed)) return false;
  if (tooPredictable(trimmed)) return false;
  // Template interpolation: ${...}, {{...}}, <%= %>, %s, $VAR
  if (/\$\{|\{\{|<%|%s\b|^\$[A-Z_]+$/.test(trimmed)) return false;
  // A single dictionary-ish word is not a key.
  if (/^[a-z]+$/.test(trimmed) && trimmed.length < 20) return false;
  return entropy(trimmed) >= minEntropy;
}
