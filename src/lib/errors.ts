/**
 * Turning a thrown value into something worth showing a user.
 *
 * Node's network errors are not reliably self-describing: a socket timeout
 * arrives as an Error with code "ETIMEDOUT" and an empty message. Reading
 * .message alone yields "", which then reads as a blank reason in the report
 * and — worse — is falsy, so it can silently skip the branches that were
 * supposed to explain the failure.
 */

const CODE_EXPLANATIONS: Record<string, string> = {
  ETIMEDOUT: 'the connection timed out',
  ECONNREFUSED: 'the connection was refused',
  ECONNRESET: 'the connection was reset by the server',
  EHOSTUNREACH: 'the host is unreachable',
  ENETUNREACH: 'the network is unreachable',
  ENOTFOUND: 'the hostname could not be resolved',
  EAI_AGAIN: 'the DNS lookup failed temporarily',
  EPIPE: 'the connection closed while sending',
  EPROTO: 'the TLS handshake failed',
  ERR_SSL_WRONG_VERSION_NUMBER: 'the port answered but is not speaking TLS',
  CERT_HAS_EXPIRED: 'the certificate has expired',
  DEPTH_ZERO_SELF_SIGNED_CERT: 'the certificate is self-signed',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'the certificate chain is incomplete',
};

/** A non-empty, human-readable description of any thrown value. */
export function describeError(err: unknown): string {
  if (typeof err === 'string') {
    return err.trim() || 'unknown error';
  }
  if (!(err instanceof Error)) {
    return 'unknown error';
  }

  const code = (err as NodeJS.ErrnoException).code;
  const message = err.message?.trim() ?? '';

  if (message) {
    // Append the code only when it adds something the message does not say.
    return code && !message.includes(code) ? `${message} (${code})` : message;
  }
  if (code) {
    return CODE_EXPLANATIONS[code] ? `${CODE_EXPLANATIONS[code]} (${code})` : code;
  }
  return err.name || 'unknown error';
}
