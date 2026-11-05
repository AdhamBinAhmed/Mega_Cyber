/**
 * The DNS lookup every outbound socket in the scanner uses.
 *
 * Because node:net takes the address this function returns instead of
 * resolving the name itself, the address the socket connects to is always one
 * the SSRF guard approved — there is no window in which a name can resolve to
 * a public IP for our check and a private one for the connection.
 */

import dns from 'node:dns';
import type { LookupFunction } from 'node:net';

import { classifyIp } from './ip';
import { allowPrivateTargets } from './config';

export class BlockedTargetError extends Error {
  readonly code = 'blocked_target';
  constructor(message: string) {
    super(message);
    this.name = 'BlockedTargetError';
  }
}

/**
 * @param record optional sink that collects every address we approved, so the
 *   report can show which IPs were actually contacted.
 */
export function guardedLookup(record?: { ips: string[] }): LookupFunction {
  return function lookup(hostname, options, callback): void {
    const opts: dns.LookupOptions =
      typeof options === 'number' ? { family: options } : (options ?? {});

    dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
      if (err) {
        callback(err, '', 0);
        return;
      }

      const wantFamily = typeof opts.family === 'number' && opts.family !== 0 ? opts.family : null;
      const candidates = addresses.filter((entry) => !wantFamily || entry.family === wantFamily);

      const allowed: dns.LookupAddress[] = [];
      const refusals: string[] = [];
      for (const entry of candidates) {
        const verdict = classifyIp(entry.address);
        if (verdict.public || allowPrivateTargets) allowed.push(entry);
        else refusals.push(`${entry.address} (${verdict.reason})`);
      }

      if (allowed.length === 0) {
        const detail = refusals.length
          ? `resolves to a non-public address: ${refusals.join(', ')}`
          : 'no usable address';
        callback(new BlockedTargetError(`${hostname} ${detail}`) as NodeJS.ErrnoException, '', 0);
        return;
      }

      if (record) {
        for (const entry of allowed) {
          if (!record.ips.includes(entry.address)) record.ips.push(entry.address);
        }
      }

      // Node 20+ enables autoSelectFamily, which calls lookup with all:true and
      // expects the whole list back. Returning a bare string there fails deep
      // inside net with "Invalid IP address: undefined".
      if (opts.all === true) {
        callback(null, allowed);
      } else {
        const first = allowed[0]!;
        callback(null, first.address, first.family);
      }
    });
  };
}
