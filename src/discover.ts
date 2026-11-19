/**
 * Discovery: find NGINX installs on the host and probe each one
 * with `nginx -V` (version, stderr) and `nginx -T` (dumped config).
 * Read-only: nothing is started, no port is opened, no config is
 * changed. `nginx -T` only dumps the config; it needs a working
 * config and temp paths, so a failure is reported, never fatal.
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { parseConfigText, type ParsedConfig } from "./config.js";
import { parseNginxVersion, type ParsedVersion } from "./versions.js";

export interface NginxInstall {
  /** Directory holding sbin/nginx, or the binary path itself. */
  home: string;
  /** Full path to the nginx binary. */
  binary: string;
  version: ParsedVersion | null;
  rawVersion: string;
  /** Dumped config from `nginx -T`, or null when it failed. */
  config: ParsedConfig | null;
  /** Why -T failed, when it did. */
  configError: string | null;
  /** Where the config came from ("nginx -T" or a --config path). */
  configSource: string;
}

export function fileExists(path: string): boolean {
  try {
    return existsSync(path);
  } catch {
    return false;
  }
}

/** Candidate binary paths inside one install directory. */
function candidateBinaries(dir: string): string[] {
  return [
    join(dir, "sbin", "nginx"),
    join(dir, "nginx"),
    join(dir, "bin", "nginx"),
  ];
}

/** Resolve a --dirs entry (a dir or a binary path) to a binary path. */
export function resolveBinary(target: string): string | null {
  if (fileExists(target) && target.endsWith("nginx")) return target;
  for (const cand of candidateBinaries(target)) {
    if (fileExists(cand)) return cand;
  }
  return null;
}

/** Well-known NGINX locations per OS, checked after PATH. */
export const WELL_KNOWN_DIRS = [
  "/usr/sbin",
  "/usr/local/nginx",
  "/usr/local/sbin",
  "/etc/nginx",
  "/opt/nginx",
  "/opt/homebrew/sbin",
  "/usr/local/opt/nginx",
];

export function discoverNginx(extraDirs: string[]): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  const add = (binary: string | null): void => {
    if (binary && !seen.has(binary)) {
      seen.add(binary);
      found.push(binary);
    }
  };
  // PATH first: `which nginx` via the shell is avoided on purpose;
  // split PATH and check each entry directly.
  for (const dir of (process.env.PATH ?? "").split(":")) {
    if (dir) add(fileExists(join(dir, "nginx")) ? join(dir, "nginx") : null);
  }
  for (const dir of extraDirs) add(resolveBinary(dir));
  for (const dir of WELL_KNOWN_DIRS) add(resolveBinary(dir));
  return found;
}

/**
 * Probe one binary: `nginx -V` prints the version to stderr, so
 * capture both streams. `nginx -T` dumps the config to stdout.
 */
export function probeNginx(
  binary: string,
  configOverride?: { text: string; source: string },
): NginxInstall {
  // `nginx -V` prints the version to stderr; capture both streams.
  const vRes = spawnSync(binary, ["-V"], {
    encoding: "utf8",
    timeout: 15000,
  });
  const rawVersion = vRes.error
    ? ""
    : `${vRes.stdout ?? ""}${vRes.stderr ?? ""}`;
  const version = parseNginxVersion(rawVersion);
  let config: ParsedConfig | null = null;
  let configError: string | null = null;
  let configSource = "";
  if (configOverride) {
    config = parseConfigText(configOverride.text);
    configSource = configOverride.source;
  } else {
    // `nginx -T` must exit 0: a failing -T prints an error to
    // stderr, and that error text is NOT a config dump. Treat any
    // non-zero exit as "no config", never as an empty config.
    const tRes = spawnSync(binary, ["-T"], {
      encoding: "utf8",
      timeout: 15000,
    });
    if (!tRes.error && tRes.status === 0) {
      config = parseConfigText(`${tRes.stdout ?? ""}`);
      configSource = "nginx -T";
    } else {
      const errText = `${tRes.stderr ?? ""}`.trim().split("\n")[0] ?? "";
      configError = `nginx -T failed${errText ? `: ${errText}` : " (config error, missing temp paths, or no permission)"}`;
    }
  }
  return {
    home: binary.replace(/\/sbin\/nginx$|\/nginx$/, ""),
    binary,
    version,
    rawVersion: rawVersion.trim(),
    config,
    configError,
    configSource,
  };
}
