/**
 * Credential shapes to look for in a public page.
 *
 * The hard part is not finding candidates, it is not crying wolf. Plenty of
 * keys are *supposed* to be in the HTML — a Stripe publishable key, a Firebase
 * apiKey, a reCAPTCHA site key. Reporting those as leaks is the fastest way to
 * lose a client's trust, so they are classified rather than hidden: present,
 * expected, worth confirming the restrictions on.
 *
 * Every pattern captures the credential in group 1.
 */

import type { Severity } from '../types';

export interface SecretPattern {
  id: string;
  /** What the thing is, in the client's language. */
  name: string;
  pattern: RegExp;
  severity: Severity;
  /**
   * The key belongs in a public page by design. Reported as information, with
   * advice to confirm it is restricted — never as a leak.
   */
  publicByDesign?: boolean;
  /** Minimum Shannon entropy for the captured value, when shape is not enough. */
  minEntropy?: number;
  recommendation: string;
}

export const SECRET_PATTERNS: SecretPattern[] = [
  /* ----------------------- unambiguous, rotate now ----------------------- */
  {
    id: 'aws.access-key-id',
    name: 'AWS access key ID',
    pattern: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    severity: 'critical',
    recommendation:
      'Deactivate and rotate this key in IAM now, then audit CloudTrail for use of it. Remove it from the page and serve AWS calls from your backend.',
  },
  {
    id: 'aws.secret-access-key',
    name: 'AWS secret access key',
    pattern:
      /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']/gi,
    severity: 'critical',
    recommendation: 'Rotate immediately in IAM and audit CloudTrail for this key.',
  },
  {
    id: 'stripe.secret',
    name: 'Stripe secret key',
    pattern: /\b((?:sk|rk)_live_[0-9a-zA-Z]{10,})\b/g,
    severity: 'critical',
    recommendation:
      'Roll this key in the Stripe dashboard immediately — it can move money. Only publishable (pk_) keys belong in a browser.',
  },
  {
    id: 'github.token',
    name: 'GitHub token',
    pattern: /\b(gh[pousr]_[A-Za-z0-9]{30,})\b/g,
    severity: 'critical',
    recommendation: 'Revoke the token on GitHub and review the audit log for its use.',
  },
  {
    id: 'slack.token',
    name: 'Slack token',
    pattern: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g,
    severity: 'critical',
    recommendation: 'Revoke in Slack app settings and rotate the app credentials.',
  },
  {
    id: 'private-key',
    name: 'Private key',
    pattern: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)/g,
    severity: 'critical',
    recommendation:
      'Treat the key pair as compromised: generate a new one, reissue anything signed by it, and remove the file from the web root.',
  },
  {
    id: 'sendgrid.key',
    name: 'SendGrid API key',
    pattern: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g,
    severity: 'critical',
    recommendation: 'Delete the key in SendGrid and issue a new one with minimal scope.',
  },
  {
    id: 'mailgun.key',
    name: 'Mailgun API key',
    pattern: /\b(key-[0-9a-f]{32})\b/g,
    severity: 'critical',
    recommendation: 'Rotate the Mailgun key; it allows sending mail as your domain.',
  },
  {
    id: 'npm.token',
    name: 'npm access token',
    pattern: /\b(npm_[A-Za-z0-9]{30,})\b/g,
    severity: 'critical',
    recommendation: 'Revoke on npmjs.com — a publish-scoped token allows supply-chain attacks.',
  },
  {
    id: 'openai.key',
    name: 'OpenAI API key',
    pattern: /\b(sk-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b/g,
    severity: 'critical',
    recommendation: 'Revoke in the OpenAI dashboard; billing is attached to this key.',
  },
  {
    id: 'twilio.api-key',
    name: 'Twilio API key',
    pattern: /\b(SK[0-9a-fA-F]{32})\b/g,
    severity: 'high',
    recommendation: 'Delete the key in the Twilio console.',
  },
  {
    id: 'square.token',
    name: 'Square access token',
    pattern: /\b(sq0atp-[0-9A-Za-z_-]{22,}|EAAA[0-9A-Za-z_-]{60,})\b/g,
    severity: 'critical',
    recommendation: 'Rotate in the Square developer dashboard.',
  },

  /* --------------------------- needs judgement --------------------------- */
  {
    id: 'google.api-key',
    name: 'Google API key',
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    severity: 'low',
    publicByDesign: true,
    recommendation:
      'Browser keys are expected in page source, but must be restricted. In Google Cloud, lock this key to your HTTP referrers and to only the APIs it needs — an unrestricted key can be used from anywhere and billed to you.',
  },
  {
    id: 'stripe.publishable',
    name: 'Stripe publishable key',
    pattern: /\b(pk_live_[0-9a-zA-Z]{10,})\b/g,
    severity: 'info',
    publicByDesign: true,
    recommendation:
      'This is the key that is meant to be public. No action needed — noted only to confirm no secret key sits beside it.',
  },
  /*
   * JWTs are deliberately absent from this list. Shape alone cannot tell a
   * Supabase anon key (published on purpose) from a service_role key (total
   * compromise of the data behind the API), and reporting both as "a JWT,
   * severity medium" is no use to either reader. `checks/api.ts` decodes the
   * claims and grades on what the token says it grants; `redact.ts` keeps its
   * own JWT pattern, so a raw token still never reaches the output.
   */
  {
    id: 'firebase.config',
    name: 'Firebase configuration block',
    pattern: /(["']?(?:authDomain|databaseURL|storageBucket)["']?\s*:\s*["'][^"']+["'])/g,
    severity: 'info',
    publicByDesign: true,
    recommendation:
      'Firebase web config is public by design. What matters is that your Security Rules are not permissive — confirm they are not set to allow all reads and writes.',
  },
  {
    id: 'generic.assignment',
    name: 'Credential-looking assignment',
    pattern:
      /\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd|db[_-]?pass)["']?\s*[:=]\s*["']([^"'\s]{12,120})["']/gi,
    severity: 'high',
    minEntropy: 3.4,
    recommendation:
      'Move the value to a server-side environment variable and rotate it. If it is a placeholder or a public identifier, no action is needed — verify which before acting.',
  },
];

/**
 * Hosts whose appearance in a credential-looking string means it is almost
 * certainly documentation or an example rather than a live value.
 */
export const EXAMPLE_MARKERS =
  /(example\.com|example\.org|localhost|yourdomain|your-domain|mysite|acme\.|foo\.bar|test\.test)/i;
