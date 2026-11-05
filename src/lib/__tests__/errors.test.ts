import { describe, expect, it } from 'vitest';

import { describeError } from '../errors';

describe('describeError', () => {
  it('never returns an empty string for a code-only error', () => {
    // Node's socket timeout really does arrive like this. Reading .message
    // alone gives "", which rendered as a blank reason in the report and, being
    // falsy, skipped the branches meant to explain the failure.
    const err = Object.assign(new Error(''), { code: 'ETIMEDOUT' });
    const described = describeError(err);
    expect(described).not.toBe('');
    expect(described).toContain('ETIMEDOUT');
    expect(described).toMatch(/timed out/i);
  });

  it('keeps a useful message and appends the code once', () => {
    const err = Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' });
    expect(describeError(err)).toBe('socket hang up (ECONNRESET)');
  });

  it('does not repeat a code already present in the message', () => {
    const err = Object.assign(new Error('getaddrinfo ENOTFOUND nope.invalid'), {
      code: 'ENOTFOUND',
    });
    expect(describeError(err)).toBe('getaddrinfo ENOTFOUND nope.invalid');
  });

  it('falls back to the bare code when it has no explanation', () => {
    const err = Object.assign(new Error(''), { code: 'ESOMETHINGNEW' });
    expect(describeError(err)).toBe('ESOMETHINGNEW');
  });

  it('handles non-Error throws', () => {
    expect(describeError('boom')).toBe('boom');
    expect(describeError('')).toBe('unknown error');
    expect(describeError(undefined)).toBe('unknown error');
    expect(describeError({ nope: true })).toBe('unknown error');
  });

  it('always returns something truthy', () => {
    for (const input of [new Error(''), new Error('  '), null, 0, [], {}]) {
      expect(Boolean(describeError(input)), String(input)).toBe(true);
    }
  });
});
