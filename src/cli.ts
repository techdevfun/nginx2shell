#!/usr/bin/env node
/**
 * nginx2shell - is this NGINX exposed to NGINX2Shell
 * (CVE-2026-123007, CVE-2026-123633)? Condition-based: NGINX
 * version vs the 18/11/2026 fixed builds + HTTP/2 actually
 * enabled per server block + operator-supplied exposure context,
 * checked together on the live host.
 * Zero runtime dependencies. No network calls in scan/check.
 * Never probes a port, never runs exploit input.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { CHECKED_AT, VERSION } from "./cli-version.js";
import { parseConfigTarget, parseSocketsText } from "./config.js";
import { discoverNginx, probeNginx, resolveBinary } from "./discover.js";
import { EXPLAIN_TOPICS, PLAYBOOK_STEPS } from "./playbook.js";
import {
  SCOPE_LINE,
  installToReport,
  renderCheckTable,
  renderConfigTable,
  renderScanTable,
  scanJson,
  verdictExitCode,
  type InstallReport,
} from "./report.js";
import { decideVerdict } from "./verdict.js";

function printHelp(): void {
  console.log(`nginx2shell ${VERSION} - is this NGINX exposed to NGINX2Shell (CVE-2026-123007, CVE-2026-123633)?
${SCOPE_LINE}

Usage:
  nginx2shell scan [--dirs <dir>...] [--config <file-or-dir>] [--internet-facing] [--sockets <file>] [--json]
  nginx2shell check <nginx-dir-or-binary> [--config <file-or-dir>] [--internet-facing] [--sockets <file>] [--json]
  nginx2shell config-scan <config-file-or-dir> [--json]
  nginx2shell playbook [--json]
  nginx2shell explain <topic>
  nginx2shell init
  nginx2shell --help | --version

Commands:
  scan         Discover NGINX installs (PATH, well-known dirs, --dirs)
               and verdict each one: EXPOSED / AT-RISK / SAFE / UNKNOWN.
  check        Verdict a single NGINX install directory or binary.
  config-scan  Parse a config file, config dir, or nginx -T dump:
               per server block, HTTP/2 on/off, proxy, HTTP/3,
               resolver, mail. No version needed.
  playbook     First-hour stopgap: patch order, http2-off stopgap,
               restart not reload, verification.
  explain      Background on a topic: CVE-2026-123007,
               CVE-2026-123633, secondary, EXPOSED, AT-RISK, SAFE,
               UNKNOWN, http2, versions, plus.
  init         Write nginx2shell.config.json for this directory.

Exit codes (scan/check/config-scan):
  0  no EXPOSED install (scan) / SAFE (check) / no HTTP/2 on (config-scan)
  1  >=1 EXPOSED install (scan) / EXPOSED or AT-RISK (check) /
     HTTP/2 on in >=1 block (config-scan)
  2  usage error, no NGINX found, or UNKNOWN verdict (check)

Flags:
  --config <path>       Config file, config dir, or nginx -T dump to
                        parse instead of running nginx -T per install.
  --internet-facing     Operator states this host faces the internet.
                        Never probed; printed as given.
  --sockets <file>      An ss -tlnp dump file; listening ports are
                        listed as evidence, never probed live.
  --json                Machine-readable output.

Facts checked ${CHECKED_AT}: fixed OSS builds 1.30.7 stable /
1.31.9 mainline. No exploitation in the wild reported as of
${CHECKED_AT}; Rapid7 has published a PoC for CVE-2026-123007,
Wiz has not published its exploit code.`);
}

interface GlobalOpts {
  json: boolean;
  dirs: string[];
  config: string | null;
  internetFacing: boolean;
  sockets: string | null;
}

function parseOpts(args: string[]): { opts: GlobalOpts; rest: string[] } {
  const opts: GlobalOpts = {
    json: false,
    dirs: [],
    config: null,
    internetFacing: false,
    sockets: null,
  };
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === "--json") opts.json = true;
    else if (arg === "--internet-facing") opts.internetFacing = true;
    else if (arg === "--dirs") {
      i++;
      while (i < args.length && !args[i].startsWith("--")) {
        opts.dirs.push(args[i]);
        i++;
      }
      i--;
    } else if (arg === "--config") {
      i++;
      opts.config = args[i] ?? null;
    } else if (arg === "--sockets") {
      i++;
      opts.sockets = args[i] ?? null;
    } else if (arg.startsWith("--")) {
      console.error(`unknown flag: ${arg}`);
      process.exit(2);
    } else {
      rest.push(arg);
    }
  }
  return { opts, rest };
}

function fail(message: string): never {
  console.error(`error: ${message}`);
  process.exit(2);
}

function readSocketsFile(path: string | null): number[] {
  if (!path) return [];
  if (!existsSync(path)) fail(`sockets file not found: ${path}`);
  return parseSocketsText(readFileSync(path, "utf8"));
}

/** Load a --config override once, for scan/check. */
function loadConfigOverride(
  path: string | null,
): { text: string; source: string } | undefined {
  if (!path) return undefined;
  const res = parseConfigTarget(path);
  if ("error" in res) fail(res.error);
  const files = res.source.split(", ");
  const text = files.map((f) => readFileSync(f, "utf8")).join("\n");
  return { text, source: path };
}

function cmdScan(opts: GlobalOpts): number {
  const override = loadConfigOverride(opts.config);
  const binaries = discoverNginx(opts.dirs);
  if (binaries.length === 0) {
    if (opts.json) {
      console.log(JSON.stringify({ error: "no NGINX install found" }, null, 2));
    } else {
      console.error(
        "no NGINX install found (PATH, well-known dirs, --dirs). Pass --dirs <dir> with the install.",
      );
    }
    return 2;
  }
  const ports = readSocketsFile(opts.sockets);
  const reports: InstallReport[] = binaries.map((binary) => {
    const install = probeNginx(binary, override);
    const result = decideVerdict({
      version: install.version,
      config: install.config,
      configSource: install.configSource,
      internetFacing: opts.internetFacing,
      rawVersion: install.rawVersion,
    });
    return installToReport(
      install,
      result,
      opts.internetFacing ? true : null,
      ports,
    );
  });
  if (opts.json) {
    console.log(
      JSON.stringify(
        scanJson(reports, opts.internetFacing ? true : null),
        null,
        2,
      ),
    );
  } else {
    console.log(renderScanTable(reports));
  }
  const worst = reports.some((r) => r.verdict === "EXPOSED")
    ? 1
    : reports.some((r) => r.verdict === "AT-RISK")
      ? 1
      : reports.some((r) => r.verdict === "UNKNOWN")
        ? 2
        : 0;
  return worst;
}

function cmdCheck(target: string, opts: GlobalOpts): number {
  const override = loadConfigOverride(opts.config);
  const binary = resolveBinary(target);
  if (!binary) fail(`no nginx binary found under: ${target}`);
  const ports = readSocketsFile(opts.sockets);
  const install = probeNginx(binary, override);
  const result = decideVerdict({
    version: install.version,
    config: install.config,
    configSource: install.configSource,
    internetFacing: opts.internetFacing,
    rawVersion: install.rawVersion,
  });
  const report = installToReport(
    install,
    result,
    opts.internetFacing ? true : null,
    ports,
  );
  if (opts.json) {
    console.log(
      JSON.stringify(
        scanJson([report], opts.internetFacing ? true : null),
        null,
        2,
      ),
    );
  } else {
    console.log(renderCheckTable(report));
  }
  return verdictExitCode(result.verdict);
}

function cmdConfigScan(target: string, opts: GlobalOpts): number {
  const res = parseConfigTarget(target);
  if ("error" in res) fail(res.error);
  const parsed = res.parsed;
  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          tool: "nginx2shell",
          version: VERSION,
          checkedAt: CHECKED_AT,
          config: target,
          http2State: parsed.http2State,
          servers: parsed.servers,
          hasMail: parsed.hasMail,
          mailHasProxy: parsed.mailHasProxy,
          hasResolver: parsed.hasResolver,
          hasInclude: parsed.hasInclude,
          scope: SCOPE_LINE,
        },
        null,
        2,
      ),
    );
  } else {
    console.log(renderConfigTable(parsed, target));
  }
  if (parsed.servers.length === 0) return 2;
  return parsed.http2State === "on" ? 1 : 0;
}

function cmdPlaybook(opts: GlobalOpts): void {
  if (opts.json) {
    console.log(
      JSON.stringify(
        {
          tool: "nginx2shell",
          version: VERSION,
          checkedAt: CHECKED_AT,
          steps: PLAYBOOK_STEPS,
          scope: SCOPE_LINE,
        },
        null,
        2,
      ),
    );
    return;
  }
  console.log(
    "nginx2shell playbook - first hour after the 18/11/2026 NGINX2Shell disclosure",
  );
  for (const step of PLAYBOOK_STEPS) {
    console.log(`\n${step.title}\n  ${step.detail}`);
  }
  console.log(`\n${SCOPE_LINE}`);
}

function cmdExplain(topic: string): number {
  const text = EXPLAIN_TOPICS[topic];
  if (!text) {
    console.error(
      `unknown topic: ${topic}. Topics: ${Object.keys(EXPLAIN_TOPICS).join(", ")}`,
    );
    return 2;
  }
  console.log(text);
  return 0;
}

function cmdInit(): void {
  const config = {
    scanDirs: [] as string[],
    configPath: "",
    internetFacing: false,
    notes:
      "Run `nginx2shell scan` on each host. Set internetFacing only when an operator confirms the host faces the internet.",
  };
  writeFileSync(
    "nginx2shell.config.json",
    JSON.stringify(config, null, 2) + "\n",
  );
  console.log("wrote nginx2shell.config.json");
  console.log(
    "run on each host: nginx2shell scan --config /etc/nginx/nginx.conf",
  );
}

function main(): void {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    printHelp();
    return;
  }
  if (argv[0] === "--version" || argv[0] === "-V") {
    console.log(`nginx2shell ${VERSION}`);
    return;
  }
  const [command, ...rest] = argv;
  const { opts, rest: positional } = parseOpts(rest);
  let code = 0;
  switch (command) {
    case "scan":
      code = cmdScan(opts);
      break;
    case "check":
      if (positional.length !== 1)
        fail("check needs exactly one <nginx-dir-or-binary>");
      code = cmdCheck(positional[0], opts);
      break;
    case "config-scan":
      if (positional.length !== 1)
        fail("config-scan needs exactly one <config-file-or-dir>");
      code = cmdConfigScan(positional[0], opts);
      break;
    case "playbook":
      cmdPlaybook(opts);
      break;
    case "explain":
      if (positional.length !== 1) fail("explain needs exactly one <topic>");
      code = cmdExplain(positional[0]);
      break;
    case "init":
      cmdInit();
      break;
    default:
      console.error(`unknown command: ${command}`);
      printHelp();
      code = 2;
  }
  process.exit(code);
}

main();
