/**
 * Human tables and JSON output for scan / check / config-scan.
 * Every output carries the scope footer: this tool proves
 * exposure conditions, never exploitability, and never probes.
 */
import { CHECKED_AT, VERSION } from "./cli-version.js";
import type { ParsedConfig } from "./config.js";
import type { NginxInstall } from "./discover.js";
import type { Verdict, VerdictResult } from "./verdict.js";

export const SCOPE_LINE =
  "Exposure conditions only. This tool does not prove exploitability, never probes a port, and never runs exploit input. A SAFE verdict means these conditions do not line up - not that the host is safe from every NGINX flaw.";

export interface InstallReport {
  home: string;
  binary: string;
  version: string | null;
  line: string | null;
  distro: string | null;
  isPlus: boolean;
  verdict: Verdict;
  deciding: string;
  reasons: string[];
  http2State: string;
  http2Blocks: number;
  /** Total server blocks found in the config. */
  serverBlocks: number;
  proxyBlocks: number;
  internetFacing: boolean | null;
  listeningPorts: number[];
  configSource: string;
  configError: string | null;
  rawVersion: string;
  cves: VerdictResult["cves"];
}

export function verdictExitCode(v: Verdict): number {
  if (v === "EXPOSED" || v === "AT-RISK") return 1;
  if (v === "UNKNOWN") return 2;
  return 0;
}

export function renderScanTable(reports: InstallReport[]): string {
  const lines: string[] = [];
  lines.push("install | version | line | http2 | proxy | verdict");
  for (const r of reports) {
    lines.push(
      `${r.home} | ${r.version ?? "?"} | ${r.line ?? "?"} | ${r.http2State} (${r.http2Blocks} block${r.http2Blocks === 1 ? "" : "s"}) | ${r.proxyBlocks} | ${r.verdict}`,
    );
  }
  for (const r of reports) {
    lines.push(`  deciding: ${r.deciding} (${r.home})`);
    for (const reason of r.reasons) lines.push(`  - ${reason}`);
    if (r.configError) lines.push(`  config: ${r.configError}`);
  }
  const counts = countVerdicts(reports.map((r) => r.verdict));
  lines.push(
    `summary: ${reports.length} install${reports.length === 1 ? "" : "s"} scanned - EXPOSED ${counts["EXPOSED"]}, AT-RISK ${counts["AT-RISK"]}, SAFE ${counts["SAFE"]}, UNKNOWN ${counts["UNKNOWN"]}`,
  );
  lines.push(SCOPE_LINE);
  return lines.join("\n");
}

export function renderCheckTable(r: InstallReport): string {
  const lines: string[] = [];
  lines.push(`verdict: ${r.verdict}`);
  lines.push(`install: ${r.home}`);
  lines.push(
    `version: ${r.version ?? "?"} (${r.line ?? "?"})${r.distro ? ` ${r.distro}` : ""}${r.isPlus ? " [NGINX Plus]" : ""}`,
  );
  lines.push(
    `http2: ${r.http2State} (${r.http2Blocks} of ${r.serverBlocks} block${r.serverBlocks === 1 ? "" : "s"} with HTTP/2 on, config: ${r.configSource || "none"})`,
  );
  lines.push(`proxy blocks: ${r.proxyBlocks}`);
  if (r.internetFacing !== null) {
    lines.push(
      `internet-facing: ${r.internetFacing ? "yes (operator states)" : "no (operator states)"}`,
    );
  }
  if (r.listeningPorts.length > 0) {
    lines.push(
      `listening ports (from supplied ss dump): ${r.listeningPorts.join(", ")}`,
    );
  }
  lines.push(`  deciding: ${r.deciding}`);
  for (const reason of r.reasons) lines.push(`  - ${reason}`);
  for (const c of r.cves) {
    lines.push(`  ${c.cve}: ${c.patch} - ${c.condition} (${c.title})`);
  }
  if (r.configError) lines.push(`config: ${r.configError}`);
  lines.push(SCOPE_LINE);
  return lines.join("\n");
}

export function renderConfigTable(
  parsed: ParsedConfig,
  source: string,
): string {
  const lines: string[] = [];
  lines.push(`config: ${source}`);
  lines.push(`server blocks: ${parsed.servers.length}`);
  lines.push(`http2: ${parsed.http2State}`);
  parsed.servers.forEach((s, i) => {
    lines.push(
      `  block ${i + 1}: server_name ${s.serverName ?? "(none)"} | listen ${s.listens.join(", ") || "(none)"} | http2 ${s.http2} (${s.http2Source}) | proxy ${s.hasProxy ? "yes" : "no"} | resolver ${s.hasResolver ? "yes" : "no"} | http3 ${s.http3 ? "yes" : "no"}`,
    );
  });
  lines.push(
    `mail block: ${parsed.hasMail ? "present" : "absent"}${parsed.hasMail ? `, proxy ${parsed.mailHasProxy ? "yes" : "no"}` : ""}`,
  );
  if (parsed.hasInclude) {
    lines.push(
      `warning: unresolved include directives (${parsed.includeLines.length}): ${parsed.includeLines.slice(0, 3).join(" | ")} - parse the nginx -T dump for the full config`,
    );
  }
  lines.push(SCOPE_LINE);
  return lines.join("\n");
}

export function countVerdicts(verdicts: Verdict[]): Record<Verdict, number> {
  const counts: Record<Verdict, number> = {
    EXPOSED: 0,
    "AT-RISK": 0,
    SAFE: 0,
    UNKNOWN: 0,
  };
  for (const v of verdicts) counts[v]++;
  return counts;
}

export function scanJson(
  reports: InstallReport[],
  internetFacing: boolean | null,
): Record<string, unknown> {
  return {
    tool: "nginx2shell",
    version: VERSION,
    checkedAt: CHECKED_AT,
    cves: ["CVE-2026-123007", "CVE-2026-123633"],
    secondaryCves: ["CVE-2026-121810", "CVE-2026-123634", "CVE-2026-113425"],
    fixedBuilds: { stable: "1.30.7", mainline: "1.31.9" },
    internetFacing,
    counts: countVerdicts(reports.map((r) => r.verdict)),
    installs: reports,
    scope: SCOPE_LINE,
  };
}

export function installToReport(
  install: NginxInstall,
  result: VerdictResult,
  internetFacing: boolean | null,
  listeningPorts: number[],
): InstallReport {
  const http2On = install.config
    ? install.config.servers.filter((s) => s.http2 === "on").length
    : 0;
  return {
    home: install.home,
    binary: install.binary,
    version: install.version ? install.version.raw : null,
    line: install.version ? install.version.line : null,
    distro: install.version ? install.version.distro : null,
    isPlus: install.version ? install.version.isPlus : false,
    verdict: result.verdict,
    deciding: result.deciding,
    reasons: result.reasons,
    http2State: install.config ? install.config.http2State : "unknown",
    http2Blocks: http2On,
    serverBlocks: install.config ? install.config.servers.length : 0,
    proxyBlocks: install.config
      ? install.config.servers.filter((s) => s.hasProxy).length
      : 0,
    internetFacing,
    listeningPorts,
    configSource: install.configSource,
    configError: install.configError,
    rawVersion: install.rawVersion,
    cves: result.cves,
  };
}
