/**
 * NGINX version parsing and the fixed-build table for the
 * NGINX2Shell release of 18/11/2026.
 *
 * Fixed builds (OSS): 1.30.7 stable, 1.31.9 mainline. A version is
 * fixed iff it is >= 1.31.9, or >= 1.30.7 and < 1.31.0 (the stable
 * line). Every other version inside a CVE range below is affected
 * for that CVE. NGINX Plus builds are NOT mapped from this table:
 * Plus fixed builds differ per CVE (37.0.7.1 / 37.2.0.1 for
 * CVE-2026-123633, 37.0.8.1 / 37.3.0.1 for CVE-2026-123007), and
 * the Plus -V string format was not verified live, so a Plus
 * build is reported as UNKNOWN, never SAFE.
 *
 * Sources (checked 2026-11-19): Wiz, nginx2shell.com; F5 / NGINX
 * security advisories, nginx.org/en/security_advisories.html.
 */
import {
  CVE_HTTP2_FLOW,
  CVE_HTTP2_UAF,
  CVE_HTTP3_UAF,
  CVE_MAIL_UAF,
  CVE_RESOLVER_UAF,
} from "./cli-version.js";

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  /** Full `nginx/X.Y.Z` token as printed, e.g. "1.24.0". */
  raw: string;
  /** "stable" for even minor, "mainline" for odd minor. */
  line: "stable" | "mainline";
  /** Distro suffix from -V, e.g. "(Ubuntu)", or null. */
  distro: string | null;
  /** True when the -V output marks an NGINX Plus build. */
  isPlus: boolean;
}

/** Compare two dotted versions: -1, 0 or 1. */
export function compareVersions(
  a: { major: number; minor: number; patch: number },
  b: { major: number; minor: number; patch: number },
): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return 0;
}

const FIXED_MAINLINE = { major: 1, minor: 31, patch: 9 };
const FIXED_STABLE = { major: 1, minor: 30, patch: 7 };
const STABLE_CUTOFF = { major: 1, minor: 31, patch: 0 };

/** True when the version is at or above a fixed build. */
export function isFixedVersion(v: ParsedVersion): boolean {
  if (compareVersions(v, FIXED_MAINLINE) >= 0) return true;
  return (
    compareVersions(v, FIXED_STABLE) >= 0 &&
    compareVersions(v, STABLE_CUTOFF) < 0
  );
}

/**
 * Parse `nginx -V` output (stderr). The first line looks like
 * `nginx version: nginx/1.24.0 (Ubuntu)`. Returns null when no
 * `nginx/X.Y.Z` token is found.
 */
export function parseNginxVersion(output: string): ParsedVersion | null {
  const m = output.match(/nginx\/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  const patch = Number(m[3]);
  const after = output.slice((m.index ?? 0) + m[0].length);
  const distroMatch = after.match(/^\s*(\([^)]*\))/);
  const lower = output.toLowerCase();
  return {
    major,
    minor,
    patch,
    raw: `${major}.${minor}.${patch}`,
    line: minor % 2 === 0 ? "stable" : "mainline",
    distro: distroMatch ? distroMatch[1] : null,
    isPlus: lower.includes("plus"),
  };
}

export interface CveEntry {
  cve: string;
  title: string;
  /** First affected version (inclusive). */
  from: { major: number; minor: number; patch: number };
  /** What else must be true, besides the version, for exposure. */
  needs: string;
  /** True when this CVE can drive an EXPOSED verdict on its own. */
  verdictDriving: boolean;
}

export const CVE_TABLE: CveEntry[] = [
  {
    cve: CVE_HTTP2_FLOW,
    title: "HTTP/2 send_window integer underflow (RCE)",
    from: { major: 1, minor: 9, patch: 5 },
    needs: "HTTP/2 enabled in at least one server block",
    verdictDriving: true,
  },
  {
    cve: CVE_HTTP2_UAF,
    title: "HTTP/2 use-after-free (RCE)",
    from: { major: 1, minor: 19, patch: 7 },
    needs:
      "HTTP/2 enabled AND proxying to a backend AND low free worker connections (runtime state)",
    verdictDriving: true,
  },
  {
    cve: CVE_HTTP3_UAF,
    title: "HTTP/3 use-after-free (secondary signal)",
    from: { major: 1, minor: 25, patch: 0 },
    needs: "HTTP/3 / QUIC listener enabled",
    verdictDriving: false,
  },
  {
    cve: CVE_RESOLVER_UAF,
    title: "DNS resolver use-after-free (secondary signal)",
    from: { major: 0, minor: 6, patch: 18 },
    needs: "resolver directive in use",
    verdictDriving: false,
  },
  {
    cve: CVE_MAIL_UAF,
    title: "mail proxy use-after-free (secondary signal)",
    from: { major: 0, minor: 5, patch: 33 },
    needs: "mail proxy block in use",
    verdictDriving: false,
  },
];

/** Patch verdict for one CVE range: fixed, affected, or not-affected. */
export type PatchVerdict = "fixed" | "affected" | "not-affected";

export function patchVerdictFor(
  v: ParsedVersion,
  entry: CveEntry,
): PatchVerdict {
  if (isFixedVersion(v)) return "fixed";
  if (compareVersions(v, entry.from) < 0) return "not-affected";
  return "affected";
}

/** Fixed build string for display, per line. */
export function fixedBuildFor(line: "stable" | "mainline"): string {
  return line === "stable" ? "1.30.7" : "1.31.9";
}
