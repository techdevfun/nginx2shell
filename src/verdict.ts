/**
 * Condition-based verdicts for NGINX2Shell (CVE-2026-123007 and
 * CVE-2026-123633, with three secondary Critical CVEs from the
 * same 18/11/2026 release as signals).
 *
 * Exposure needs the version AND the config condition together:
 * a version in the affected range with HTTP/2 off is not exposed
 * to the two HTTP/2 flaws - but it may still be at risk from the
 * secondary flaws, which HTTP/2-off does not fix.
 *
 * - EXPOSED: affected version + HTTP/2 on in >=1 server block.
 * - SAFE: fixed version, or affected version with HTTP/2 off in
 *   every block and no secondary signal, or below every CVE range.
 * - AT-RISK: affected version but HTTP/2 state unknown, or HTTP/2
 *   off while a secondary signal applies.
 * - UNKNOWN: version unparseable, NGINX Plus build (cannot map
 *   Plus numbers from the OSS table), or the binary could not be
 *   probed at all.
 */
import type { ParsedConfig } from "./config.js";
import {
  CVE_TABLE,
  fixedBuildFor,
  isFixedVersion,
  patchVerdictFor,
  type ParsedVersion,
} from "./versions.js";

export type Verdict = "EXPOSED" | "AT-RISK" | "SAFE" | "UNKNOWN";

export interface CveVerdict {
  cve: string;
  title: string;
  patch: "fixed" | "affected" | "not-affected";
  /** Whether the config condition for this CVE is met. */
  conditionMet: boolean;
  condition: string;
  /** True when this CVE can drive an EXPOSED verdict on its own. */
  verdictDriving: boolean;
}

export interface VerdictInput {
  version: ParsedVersion | null;
  /** Null when no config could be read at all. */
  config: ParsedConfig | null;
  /** Where the config came from, for evidence (or "" when none). */
  configSource: string;
  /** Operator-supplied: this host faces the internet. */
  internetFacing: boolean;
  /** Raw `nginx -V` output, for evidence. */
  rawVersion: string;
}

export interface VerdictResult {
  verdict: Verdict;
  reasons: string[];
  /** The single condition that decides the verdict, for tables. */
  deciding: string;
  /** Per-CVE patch + condition table. */
  cves: CveVerdict[];
}

/** Does the config meet the extra condition for one CVE? */
function conditionMetFor(cve: string, config: ParsedConfig): boolean {
  switch (cve) {
    case "CVE-2026-123007":
      return config.http2State === "on";
    case "CVE-2026-123633":
      return (
        config.http2State === "on" &&
        config.servers.some((s) => s.http2 === "on" && s.hasProxy)
      );
    case "CVE-2026-121810":
      return config.servers.some((s) => s.http3);
    case "CVE-2026-123634":
      return config.hasResolver;
    case "CVE-2026-113425":
      return config.hasMail && config.mailHasProxy;
    default:
      return false;
  }
}

function conditionTextFor(cve: string, config: ParsedConfig): string {
  switch (cve) {
    case "CVE-2026-123007":
      return `HTTP/2 ${config.http2State === "on" ? "on in at least one server block" : config.http2State === "off" ? "off in every server block" : config.http2State === "none" ? "no server blocks found" : "state unknown (no config read)"}`;
    case "CVE-2026-123633":
      return config.servers.some((s) => s.http2 === "on" && s.hasProxy)
        ? "HTTP/2 on and proxy_pass in an HTTP/2 block (low free worker connections is runtime state, not decided here)"
        : "no HTTP/2 block with proxy_pass found";
    case "CVE-2026-121810":
      return config.servers.some((s) => s.http3)
        ? "HTTP/3 / QUIC listener present"
        : "no HTTP/3 / QUIC listener found";
    case "CVE-2026-123634":
      return config.hasResolver
        ? "resolver directive in use"
        : "no resolver directive found";
    case "CVE-2026-113425":
      return config.hasMail && config.mailHasProxy
        ? "mail proxy block in use"
        : "no mail proxy block found";
    default:
      return "unknown condition";
  }
}

export function decideVerdict(input: VerdictInput): VerdictResult {
  const { version, config } = input;
  if (!version) {
    return {
      verdict: "UNKNOWN",
      reasons: ["nginx -V output could not be parsed"],
      deciding: "version unparseable",
      cves: [],
    };
  }
  if (version.isPlus) {
    return {
      verdict: "UNKNOWN",
      reasons: [
        `NGINX Plus build detected (${version.raw}); Plus fixed builds differ per CVE (37.0.7.1 / 37.2.0.1 for CVE-2026-123633, 37.0.8.1 / 37.3.0.1 for CVE-2026-123007) and cannot be mapped from the OSS table`,
        "confirm the Plus build in the F5 advisory before calling this SAFE",
      ],
      deciding: "NGINX Plus build, OSS table does not apply",
      cves: [],
    };
  }
  const cves: CveVerdict[] = CVE_TABLE.map((entry) => ({
    cve: entry.cve,
    title: entry.title,
    patch: patchVerdictFor(version, entry),
    conditionMet: config ? conditionMetFor(entry.cve, config) : false,
    condition: config
      ? conditionTextFor(entry.cve, config)
      : "no config read, condition unknown",
    verdictDriving: entry.verdictDriving,
  }));
  const http2 = cves.find((c) => c.cve === "CVE-2026-123007");
  const http2uaf = cves.find((c) => c.cve === "CVE-2026-123633");
  const secondaryHit = cves.filter(
    (c) => !c.verdictDriving && c.patch === "affected" && c.conditionMet,
  );

  if (isFixedVersion(version)) {
    return {
      verdict: "SAFE",
      reasons: [
        `${version.raw} is at or above the fixed build (${fixedBuildFor(version.line)} ${version.line}) for the 18/11/2026 release`,
      ],
      deciding: "fixed build",
      cves,
    };
  }
  if (!config) {
    if (http2 && http2.patch === "affected") {
      return {
        verdict: "AT-RISK",
        reasons: [
          `${version.raw} is in the affected range for CVE-2026-123007 (fixed build is ${fixedBuildFor(version.line)}) but no config could be read`,
          "run on the host itself, or pass --config with the nginx -T dump, to decide",
        ],
        deciding: "HTTP/2 state unknown",
        cves,
      };
    }
    return {
      verdict: "AT-RISK",
      reasons: [
        `${version.raw} is below the HTTP/2 CVE ranges but no config could be read, so the secondary signals cannot be checked`,
      ],
      deciding: "config unknown",
      cves,
    };
  }
  if (http2 && http2.patch === "affected" && http2.conditionMet) {
    const reasons = [
      `${version.raw} is in the affected range for CVE-2026-123007 (fixed build is ${fixedBuildFor(version.line)})`,
      "HTTP/2 is on in at least one server block",
    ];
    if (http2uaf && http2uaf.patch === "affected" && http2uaf.conditionMet) {
      reasons.push(
        "CVE-2026-123633 also applies: an HTTP/2 block proxies to a backend (low free worker connections is runtime state)",
      );
    }
    if (input.internetFacing) {
      reasons.push("operator states this host faces the internet");
    }
    return {
      verdict: "EXPOSED",
      reasons,
      deciding: "affected version + HTTP/2 on",
      cves,
    };
  }
  // From here the HTTP/2 verdict-driving CVE does not line up.
  // A config was read but it does not settle HTTP/2: "unknown"
  // (blocks exist, no http2 marker) or "none" (no server blocks
  // found) is AT-RISK, never SAFE, when the version is affected.
  if (
    http2 &&
    http2.patch === "affected" &&
    (config.http2State === "unknown" || config.http2State === "none")
  ) {
    return {
      verdict: "AT-RISK",
      reasons: [
        `${version.raw} is in the affected range for CVE-2026-123007 (fixed build is ${fixedBuildFor(version.line)}) but the config read does not settle HTTP/2 (${config.http2State === "none" ? "no server blocks found" : "no http2 directive or listen flag in any server block"})`,
        "pass the full nginx -T dump with --config to decide",
      ],
      deciding: "HTTP/2 state unknown in config",
      cves,
    };
  }
  if (secondaryHit.length > 0) {
    return {
      verdict: "AT-RISK",
      reasons: [
        `HTTP/2 is off, so the two HTTP/2 flaws do not apply, but ${version.raw} is in the affected range for ${secondaryHit.map((c) => c.cve).join(", ")} and the config condition is met (${secondaryHit.map((c) => c.condition).join("; ")})`,
        "turning HTTP/2 off does not fix these three flaws - patch to 1.30.7 / 1.31.9",
      ],
      deciding: `secondary signal: ${secondaryHit.map((c) => c.cve).join(", ")}`,
      cves,
    };
  }
  if (http2 && http2.patch === "affected") {
    return {
      verdict: "SAFE",
      reasons: [
        `${version.raw} is in the affected range, but HTTP/2 is off in every server block (${config.http2State === "none" ? "no server blocks found" : "checked from " + (input.configSource || "config")})`,
        "no secondary signal applies (no HTTP/3 listener, no resolver directive, no mail proxy block)",
      ],
      deciding: "HTTP/2 off, no secondary signal",
      cves,
    };
  }
  return {
    verdict: "SAFE",
    reasons: [
      `${version.raw} is below the affected range for CVE-2026-123007 (from 1.9.5) and CVE-2026-123633 (from 1.19.7)`,
      "no secondary signal applies in the config read",
    ],
    deciding: "version below affected ranges",
    cves,
  };
}
