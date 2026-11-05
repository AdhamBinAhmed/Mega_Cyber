/**
 * The SSRF guard and target parser. These are the checks that decide whether
 * the scanner will connect to something, so they get the most scrutiny.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import { classifyIp, expandIpv6, isPublicIp } from '../ip';
import { parseTarget, registrableDomain } from '../target';

describe('classifyIp — IPv4', () => {
  it('accepts ordinary public addresses', () => {
    for (const ip of ['1.1.1.1', '8.8.8.8', '140.82.121.4', '93.184.216.34']) {
      expect(isPublicIp(ip), ip).toBe(true);
    }
  });

  it('refuses every private and special-purpose range', () => {
    const blocked = [
      '0.0.0.0',
      '10.0.0.1',
      '100.64.0.1',
      '127.0.0.1',
      '169.254.169.254', // cloud instance metadata
      '172.16.0.1',
      '172.31.255.254',
      '192.0.0.1',
      '192.0.2.1',
      '192.168.1.1',
      '198.18.0.1',
      '198.51.100.1',
      '203.0.113.1',
      '224.0.0.1',
      '240.0.0.1',
      '255.255.255.255',
    ];
    for (const ip of blocked) {
      expect(isPublicIp(ip), ip).toBe(false);
    }
  });

  it('does not over-block addresses adjacent to private ranges', () => {
    expect(isPublicIp('172.15.255.255')).toBe(true);
    expect(isPublicIp('172.32.0.1')).toBe(true);
    expect(isPublicIp('11.0.0.1')).toBe(true);
    expect(isPublicIp('100.63.255.255')).toBe(true);
    expect(isPublicIp('100.128.0.1')).toBe(true);
  });

  it('explains why an address was refused', () => {
    expect(classifyIp('169.254.169.254').reason).toMatch(/link-local|metadata/i);
    expect(classifyIp('10.1.2.3').reason).toMatch(/private/i);
  });
});

describe('expandIpv6', () => {
  it('expands compressed forms', () => {
    expect(expandIpv6('::1')).toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
    expect(expandIpv6('2001:db8::1')).toEqual([0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]);
    expect(expandIpv6('fe80::1%eth0')).toEqual([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
  });

  it('expands embedded IPv4', () => {
    expect(expandIpv6('::ffff:127.0.0.1')).toEqual([0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
  });

  it('rejects malformed input', () => {
    expect(expandIpv6('not-an-address')).toBeNull();
    expect(expandIpv6('1:2:3:4:5:6:7:8:9')).toBeNull();
  });
});

describe('classifyIp — IPv6', () => {
  it('accepts public addresses', () => {
    expect(isPublicIp('2606:4700:4700::1111')).toBe(true);
    expect(isPublicIp('2a00:1450:4001:80e::200e')).toBe(true);
  });

  it('refuses loopback, ULA, link-local and multicast', () => {
    for (const ip of ['::', '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '2001:db8::1']) {
      expect(isPublicIp(ip), ip).toBe(false);
    }
  });

  it('unwraps IPv4-mapped addresses before judging them', () => {
    // The classic bypass: a private IPv4 wearing an IPv6 costume.
    expect(isPublicIp('::ffff:127.0.0.1')).toBe(false);
    expect(isPublicIp('::ffff:169.254.169.254')).toBe(false);
    expect(isPublicIp('::ffff:8.8.8.8')).toBe(true);
    expect(isPublicIp('64:ff9b::10.0.0.1')).toBe(false);
  });
});

describe('parseTarget', () => {
  it('defaults a bare hostname to https', () => {
    const result = parseTarget('example.org');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.url.toString()).toBe('https://example.org/');
  });

  it('keeps an explicit path and query, drops the fragment', () => {
    const result = parseTarget('https://example.org/a/b?c=1#frag');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.url.toString()).toBe('https://example.org/a/b?c=1');
  });

  it('refuses non-http schemes', () => {
    for (const input of ['file:///etc/passwd', 'ftp://example.org', 'gopher://example.org']) {
      const result = parseTarget(input);
      expect(result.ok, input).toBe(false);
    }
  });

  it('refuses credentials embedded in the URL', () => {
    expect(parseTarget('https://user:pass@example.org').ok).toBe(false);
  });

  it('refuses loopback and internal names', () => {
    for (const input of [
      'localhost',
      'http://localhost:8080',
      'foo.localhost',
      'printer.local',
      'db.internal',
      'metadata.google.internal',
      'intranet',
    ]) {
      const result = parseTarget(input);
      expect(result.ok, input).toBe(false);
    }
  });

  it('refuses IP literals in private ranges', () => {
    for (const input of ['127.0.0.1', 'http://169.254.169.254/latest/meta-data/', '10.0.0.5']) {
      const result = parseTarget(input);
      expect(result.ok, input).toBe(false);
      if (!result.ok) expect(result.code).toBe('blocked_target');
    }
  });

  it('allows a public IP literal', () => {
    expect(parseTarget('https://1.1.1.1').ok).toBe(true);
  });

  it('restricts the port to web ports', () => {
    expect(parseTarget('https://example.org:443').ok).toBe(true);
    expect(parseTarget('https://example.org:8443').ok).toBe(true);
    expect(parseTarget('https://example.org:22').ok).toBe(false);
    expect(parseTarget('https://example.org:6379').ok).toBe(false);
  });

  it('rejects empty and oversized input', () => {
    expect(parseTarget('').ok).toBe(false);
    expect(parseTarget(`https://example.org/${'a'.repeat(3000)}`).ok).toBe(false);
  });
});

describe('registrableDomain', () => {
  it('strips subdomains', () => {
    expect(registrableDomain('www.example.com')).toBe('example.com');
    expect(registrableDomain('a.b.c.example.com')).toBe('example.com');
    expect(registrableDomain('example.com')).toBe('example.com');
  });

  it('handles multi-label public suffixes', () => {
    expect(registrableDomain('shop.example.co.uk')).toBe('example.co.uk');
    expect(registrableDomain('example.com.au')).toBe('example.com.au');
    expect(registrableDomain('mail.corp.example.com.br')).toBe('example.com.br');
  });
});

describe('ALLOW_PRIVATE_TARGETS', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it('is off unless explicitly enabled', async () => {
    // The guard must be closed by default. Enabling it is a deliberate,
    // development-only act — see the production test below.
    const { allowPrivateTargets } = await import('../config');
    expect(allowPrivateTargets).toBe(false);
    expect(parseTarget('localhost:3000').ok).toBe(false);
    expect(parseTarget('127.0.0.1').ok).toBe(false);
  });

  it('cannot be switched on in production', async () => {
    vi.resetModules();
    vi.stubEnv('ALLOW_PRIVATE_TARGETS', '1');
    vi.stubEnv('NODE_ENV', 'production');

    const { allowPrivateTargets } = await import('../config');
    expect(allowPrivateTargets).toBe(false);

    const { parseTarget: parseInProd } = await import('../target');
    expect(parseInProd('http://169.254.169.254/latest/meta-data/').ok).toBe(false);
    expect(parseInProd('localhost:3000').ok).toBe(false);
  });

  it('allows a localhost target in development when enabled', async () => {
    vi.resetModules();
    vi.stubEnv('ALLOW_PRIVATE_TARGETS', '1');
    vi.stubEnv('NODE_ENV', 'development');

    const { parseTarget: parseInDev } = await import('../target');
    const result = parseInDev('localhost:3000');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.url.toString()).toBe('https://localhost:3000/');
    expect(parseInDev('http://127.0.0.1:8000/app').ok).toBe(true);

    // Input sanity still applies regardless of the flag.
    expect(parseInDev('http://exa mple.com').ok).toBe(false);
    expect(parseInDev('ftp://localhost').ok).toBe(false);
    expect(parseInDev('https://user:pw@localhost').ok).toBe(false);
  });
});
