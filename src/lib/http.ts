/**
 * The scanner's HTTP client.
 *
 * Built directly on node:http / node:https rather than fetch() because the
 * scanner needs things fetch() does not expose:
 *
 *  - a custom DNS lookup, so the address the socket actually connects to is the
 *    same one the SSRF guard approved (closing the DNS-rebinding window),
 *  - manual redirect handling, so every hop is re-validated,
 *  - a hard cap on bytes read, so a huge or hostile response cannot exhaust the
 *    function's memory,
 *  - the TLS handshake details of the request we were making anyway.
 */

import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import type { TLSSocket } from 'node:tls';
import { Readable } from 'node:stream';

import { config, USER_AGENT } from './config';
import { BlockedTargetError, guardedLookup } from './lookup';
import type { RequestBudget } from './budget';

export { BlockedTargetError };

export interface RawResponse {
  url: string;
  status: number;
  statusText: string;
  /** Lower-cased name -> value; repeated headers are joined with ", ". */
  headers: Record<string, string>;
  /** Lower-cased name -> every value, unjoined (needed for set-cookie). */
  rawHeaders: Record<string, string[]>;
  body: string;
  bodyBytes: number;
  truncated: boolean;
  remoteAddress: string | null;
  tls: {
    authorized: boolean;
    authorizationError: string | null;
    protocol: string | null;
    cipher: string | null;
  } | null;
  durationMs: number;
}

export interface RequestOptions {
  method?: 'GET' | 'HEAD';
  timeoutMs?: number;
  maxBytes?: number;
  extraHeaders?: Record<string, string>;
  /** Collect the body, or just the headers. */
  wantBody?: boolean;
  /**
   * Per-scan request ceiling. Throws BudgetExhaustedError once spent, so a
   * growing catalogue of checks cannot quietly multiply the load we put on
   * someone else's site.
   */
  budget?: RequestBudget;
}

function decompressor(encoding: string | undefined): zlib.Gunzip | zlib.Inflate | zlib.BrotliDecompress | null {
  switch ((encoding ?? '').trim().toLowerCase()) {
    case 'gzip':
    case 'x-gzip':
      return zlib.createGunzip();
    case 'deflate':
      return zlib.createInflate();
    case 'br':
      return zlib.createBrotliDecompress();
    default:
      return null;
  }
}

/**
 * One request, no redirect following. Never throws for an HTTP status — only
 * for transport failures, timeouts and blocked targets.
 */
export function rawRequest(
  target: URL,
  options: RequestOptions = {},
  resolved?: { ips: string[] },
): Promise<RawResponse> {
  const {
    method = 'GET',
    timeoutMs = config.requestTimeoutMs,
    maxBytes = config.maxBodyBytes,
    extraHeaders = {},
    wantBody = true,
    budget,
  } = options;

  // Throws if the scan has used its allowance. Deliberately before any socket
  // work, so an exhausted budget costs the target nothing at all.
  budget?.claim();

  const isHttps = target.protocol === 'https:';
  const transport = isHttps ? https : http;
  const startedAt = Date.now();

  return new Promise<RawResponse>((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      fn();
    };

    const request = transport.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (isHttps ? 443 : 80),
        path: `${target.pathname}${target.search}`,
        method,
        lookup: guardedLookup(resolved),
        headers: {
          host: target.host,
          'user-agent': USER_AGENT,
          accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'accept-language': 'en-US,en;q=0.9',
          'accept-encoding': 'gzip, deflate, br',
          connection: 'close',
          ...extraHeaders,
        },
        // We deliberately do NOT abort on an untrusted certificate: a broken
        // chain is a finding to report, not a reason to stop scanning. The
        // certificate itself is validated separately in the TLS check, and no
        // secrets are ever sent to the target.
        ...(isHttps ? { rejectUnauthorized: false, servername: target.hostname } : {}),
        // Node reuses sockets aggressively; a fresh agent keeps scans isolated.
        agent: false,
      },
      (res) => {
        const rawHeaders: Record<string, string[]> = {};
        for (const [key, value] of Object.entries(res.headers)) {
          if (value === undefined) continue;
          rawHeaders[key.toLowerCase()] = Array.isArray(value) ? value : [String(value)];
        }
        const headers: Record<string, string> = {};
        for (const [key, values] of Object.entries(rawHeaders)) {
          headers[key] = values.join(', ');
        }

        const socket = res.socket as TLSSocket;
        const tls =
          isHttps && typeof socket?.getProtocol === 'function'
            ? {
                authorized: socket.authorized === true,
                authorizationError: socket.authorized
                  ? null
                  : (socket.authorizationError as unknown as string | undefined)?.toString() ??
                    null,
                protocol: socket.getProtocol(),
                cipher: socket.getCipher?.()?.name ?? null,
              }
            : null;
        const remoteAddress = res.socket?.remoteAddress ?? null;

        const done = (body: string, bodyBytes: number, truncated: boolean) =>
          finish(() =>
            resolve({
              url: target.toString(),
              status: res.statusCode ?? 0,
              statusText: res.statusMessage ?? '',
              headers,
              rawHeaders,
              body,
              bodyBytes,
              truncated,
              remoteAddress,
              tls,
              durationMs: Date.now() - startedAt,
            }),
          );

        if (!wantBody || method === 'HEAD') {
          res.resume();
          res.on('end', () => done('', 0, false));
          res.on('error', () => done('', 0, false));
          return;
        }

        const encoding = res.headers['content-encoding'];
        const inflater = decompressor(encoding);
        const source: Readable = inflater ? res.pipe(inflater) : res;

        const chunks: Buffer[] = [];
        let collected = 0;
        let rawSeen = 0;
        let truncated = false;

        // Guard against a decompression bomb: stop reading the wire early too.
        res.on('data', (chunk: Buffer) => {
          rawSeen += chunk.length;
          if (rawSeen > maxBytes * 8) {
            truncated = true;
            res.destroy();
          }
        });

        source.on('data', (chunk: Buffer) => {
          if (collected >= maxBytes) return;
          const remaining = maxBytes - collected;
          const slice = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
          chunks.push(slice);
          collected += slice.length;
          if (collected >= maxBytes) {
            truncated = true;
            res.destroy();
          }
        });

        const flush = () => done(Buffer.concat(chunks).toString('utf8'), collected, truncated);
        source.on('end', flush);
        // A truncated gzip stream errors on close; whatever we already decoded
        // is still perfectly good evidence.
        source.on('error', flush);
        res.on('aborted', flush);
      },
    );

    request.setTimeout(timeoutMs, () => {
      request.destroy(new Error(`timed out after ${timeoutMs}ms`));
    });

    request.on('error', (err) => {
      finish(() => reject(err));
    });

    request.end();
  });
}

export interface FollowResult {
  final: RawResponse;
  chain: Array<{ url: string; status: number; location: string | null }>;
}

/** Follow redirects manually so each hop is re-validated by guardedLookup. */
export async function requestFollowingRedirects(
  target: URL,
  options: RequestOptions = {},
  resolved?: { ips: string[] },
): Promise<FollowResult> {
  const chain: FollowResult['chain'] = [];
  let current = target;

  for (let hop = 0; hop <= config.maxRedirects; hop += 1) {
    const response = await rawRequest(current, options, resolved);
    const location = response.headers['location'] ?? null;
    const isRedirect = response.status >= 300 && response.status < 400 && location;

    if (!isRedirect) {
      return { final: response, chain };
    }

    chain.push({ url: current.toString(), status: response.status, location });

    let next: URL;
    try {
      next = new URL(location, current);
    } catch {
      return { final: response, chain };
    }
    if (next.protocol !== 'http:' && next.protocol !== 'https:') {
      throw new BlockedTargetError(`redirect to unsupported scheme: ${next.protocol}`);
    }
    // Strip any credentials an open redirect might try to smuggle in.
    next.username = '';
    next.password = '';
    current = next;
  }

  throw new Error(`too many redirects (> ${config.maxRedirects})`);
}
