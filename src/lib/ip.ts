/**
 * IP classification used by the SSRF guard.
 *
 * The scanner accepts a URL from an anonymous visitor, so every address we are
 * about to connect to has to be proven publicly routable first. Anything in a
 * private, loopback, link-local or otherwise special-purpose range is refused —
 * most importantly 169.254.169.254, the cloud instance metadata endpoint.
 */

import { isIPv4, isIPv6 } from 'node:net';

export interface IpVerdict {
  public: boolean;
  /** Human readable reason when the address is not public. */
  reason?: string;
}

interface V4Range {
  cidr: string;
  label: string;
}

/** Special-purpose IPv4 blocks (RFC 6890 and friends). */
const BLOCKED_V4: V4Range[] = [
  { cidr: '0.0.0.0/8', label: 'this-network' },
  { cidr: '10.0.0.0/8', label: 'private (RFC 1918)' },
  { cidr: '100.64.0.0/10', label: 'carrier-grade NAT' },
  { cidr: '127.0.0.0/8', label: 'loopback' },
  { cidr: '169.254.0.0/16', label: 'link-local / cloud metadata' },
  { cidr: '172.16.0.0/12', label: 'private (RFC 1918)' },
  { cidr: '192.0.0.0/24', label: 'IETF protocol assignments' },
  { cidr: '192.0.2.0/24', label: 'documentation (TEST-NET-1)' },
  { cidr: '192.88.99.0/24', label: '6to4 relay anycast' },
  { cidr: '192.168.0.0/16', label: 'private (RFC 1918)' },
  { cidr: '198.18.0.0/15', label: 'benchmarking' },
  { cidr: '198.51.100.0/24', label: 'documentation (TEST-NET-2)' },
  { cidr: '203.0.113.0/24', label: 'documentation (TEST-NET-3)' },
  { cidr: '224.0.0.0/4', label: 'multicast' },
  { cidr: '240.0.0.0/4', label: 'reserved' },
];

function v4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    out = (out << 8) | octet;
  }
  // Force unsigned.
  return out >>> 0;
}

function inV4Cidr(ipInt: number, cidr: string): boolean {
  const [base, bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw);
  const baseInt = v4ToInt(base ?? '');
  if (baseInt === null || !Number.isFinite(bits)) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/** Expand any valid IPv6 string to its eight 16-bit groups. */
export function expandIpv6(address: string): number[] | null {
  let addr = address.trim().toLowerCase();
  if (addr.startsWith('[') && addr.endsWith(']')) addr = addr.slice(1, -1);
  // Drop a zone index such as %eth0.
  const zone = addr.indexOf('%');
  if (zone !== -1) addr = addr.slice(0, zone);

  // An embedded IPv4 tail (::ffff:192.0.2.1) becomes two more groups.
  const v4Match = addr.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (v4Match?.[1]) {
    const v4 = v4ToInt(v4Match[1]);
    if (v4 === null) return null;
    const hi = (v4 >>> 16).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    addr = addr.slice(0, v4Match.index) + hi + ':' + lo;
  }

  const doubleColon = addr.indexOf('::');
  let head: string[];
  let tail: string[];
  if (doubleColon === -1) {
    head = addr.split(':');
    tail = [];
  } else {
    const headRaw = addr.slice(0, doubleColon);
    const tailRaw = addr.slice(doubleColon + 2);
    head = headRaw === '' ? [] : headRaw.split(':');
    tail = tailRaw === '' ? [] : tailRaw.split(':');
  }

  const fill = 8 - head.length - tail.length;
  if (fill < 0) return null;
  if (doubleColon === -1 && head.length !== 8) return null;

  const groups = [...head, ...Array<string>(fill).fill('0'), ...tail];
  const out: number[] = [];
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    out.push(parseInt(group, 16));
  }
  return out.length === 8 ? out : null;
}

function classifyIpv4(ip: string): IpVerdict {
  const asInt = v4ToInt(ip);
  if (asInt === null) return { public: false, reason: 'unparseable IPv4 address' };
  if (asInt === 0xffffffff) return { public: false, reason: 'broadcast' };
  for (const range of BLOCKED_V4) {
    if (inV4Cidr(asInt, range.cidr)) {
      return { public: false, reason: `${range.label} (${range.cidr})` };
    }
  }
  return { public: true };
}

function groupsToV4(groups: number[]): string {
  const g6 = groups[6] ?? 0;
  const g7 = groups[7] ?? 0;
  return [g6 >> 8, g6 & 0xff, g7 >> 8, g7 & 0xff].join('.');
}

function classifyIpv6(ip: string): IpVerdict {
  const groups = expandIpv6(ip);
  if (!groups) return { public: false, reason: 'unparseable IPv6 address' };

  const allZero = groups.every((g) => g === 0);
  if (allZero) return { public: false, reason: 'unspecified address (::)' };
  if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) {
    return { public: false, reason: 'loopback (::1)' };
  }

  const first = groups[0] ?? 0;

  // IPv4-mapped (::ffff:0:0/96) and IPv4-translated (::/96) — judge the IPv4.
  const prefixZero = groups.slice(0, 5).every((g) => g === 0);
  if (prefixZero && (groups[5] === 0xffff || groups[5] === 0)) {
    const verdict = classifyIpv4(groupsToV4(groups));
    return verdict.public
      ? { public: true }
      : { public: false, reason: `IPv4-mapped ${verdict.reason}` };
  }

  // NAT64 well-known prefix 64:ff9b::/96 also wraps an IPv4 destination.
  if (first === 0x64 && groups[1] === 0xff9b && groups.slice(2, 6).every((g) => g === 0)) {
    const verdict = classifyIpv4(groupsToV4(groups));
    return verdict.public
      ? { public: true }
      : { public: false, reason: `NAT64-embedded ${verdict.reason}` };
  }

  if ((first & 0xfe00) === 0xfc00) return { public: false, reason: 'unique local (fc00::/7)' };
  if ((first & 0xffc0) === 0xfe80) return { public: false, reason: 'link-local (fe80::/10)' };
  if ((first & 0xff00) === 0xff00) return { public: false, reason: 'multicast (ff00::/8)' };
  if (first === 0x2001 && groups[1] === 0x0db8) {
    return { public: false, reason: 'documentation (2001:db8::/32)' };
  }
  if (first === 0x0100 && groups.slice(1, 4).every((g) => g === 0)) {
    return { public: false, reason: 'discard-only (100::/64)' };
  }

  return { public: true };
}

/** Decide whether an address is safe for the scanner to connect to. */
export function classifyIp(ip: string): IpVerdict {
  if (isIPv4(ip)) return classifyIpv4(ip);
  if (isIPv6(ip)) return classifyIpv6(ip);
  return { public: false, reason: 'not a valid IP address' };
}

export function isPublicIp(ip: string): boolean {
  return classifyIp(ip).public;
}
