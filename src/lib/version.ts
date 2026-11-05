/**
 * A small, dependency-free loose-semver comparator.
 *
 * Real-world version strings from HTML and headers are messy ("2.4.49",
 * "5.8", "4.0.0-beta.2", "1.12.4-rc1"), so this is deliberately tolerant:
 * missing components count as 0, and a pre-release sorts before the release
 * it leads up to.
 */

export interface ParsedVersion {
  parts: number[];
  prerelease: string | null;
}

const VERSION_PATTERN = /^v?(\d+(?:\.\d+)*)(?:[-+]([0-9A-Za-z.-]+))?/;

export function parseVersion(raw: string): ParsedVersion | null {
  const match = raw.trim().match(VERSION_PATTERN);
  if (!match?.[1]) return null;
  const parts = match[1].split('.').map((segment) => {
    const value = Number(segment);
    return Number.isFinite(value) ? value : 0;
  });
  return { parts, prerelease: match[2] ?? null };
}

/** -1 if a < b, 0 if equal, 1 if a > b. Returns null when either is unparseable. */
export function compareVersions(a: string, b: string): number | null {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return null;

  const length = Math.max(left.parts.length, right.parts.length);
  for (let i = 0; i < length; i += 1) {
    const l = left.parts[i] ?? 0;
    const r = right.parts[i] ?? 0;
    if (l !== r) return l < r ? -1 : 1;
  }

  // 4.0.0-beta.2 is older than 4.0.0.
  if (left.prerelease && !right.prerelease) return -1;
  if (!left.prerelease && right.prerelease) return 1;
  if (left.prerelease && right.prerelease) {
    if (left.prerelease === right.prerelease) return 0;
    return left.prerelease < right.prerelease ? -1 : 1;
  }
  return 0;
}

export function lessThan(version: string, bound: string): boolean {
  const result = compareVersions(version, bound);
  return result !== null && result < 0;
}

export function atLeast(version: string, bound: string): boolean {
  const result = compareVersions(version, bound);
  return result !== null && result >= 0;
}

/** Inclusive-lower, exclusive-upper range test: introduced <= v < fixed. */
export function inRange(
  version: string,
  introduced: string | undefined,
  fixed: string | null,
): boolean {
  if (!parseVersion(version)) return false;
  if (introduced && !atLeast(version, introduced)) return false;
  if (fixed === null) return true;
  return lessThan(version, fixed);
}
