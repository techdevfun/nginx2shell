/**
 * Unit tests: version parsing, fixed-version compare (stable vs
 * mainline lines), config parsing, verdict matrix, sockets parsing.
 * Fixture -V strings: the Ubuntu 1.24.0 text is RECORDED from the
 * real binary run on this build machine (19/11/2026); the 1.31.8 /
 * 1.30.7 / 1.19.6 / 1.9.4 texts are representative format with
 * version numbers from the F5 / Wiz advisories; the Plus text is
 * SYNTHETIC (format not verified live, see examples/README.md).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { parseConfigText, parseSocketsText } from "../dist/config.js";
import { decideVerdict } from "../dist/verdict.js";
import {
  CVE_TABLE,
  compareVersions,
  isFixedVersion,
  parseNginxVersion,
  patchVerdictFor,
} from "../dist/versions.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ex = (name) => readFileSync(join(ROOT, "examples", name), "utf8");

const V_REAL_1240 = ex("nginx-V-real-1.24.0.txt");
const V_1318 = ex("nginx-V-1.31.8.txt");
const V_1307 = ex("nginx-V-1.30.7.txt");
const V_1196 = ex("nginx-V-1.19.6.txt");
const V_194 = ex("nginx-V-1.9.4.txt");
const V_PLUS = ex("nginx-V-plus-1.31.8.txt");

function ver(text) {
  const v = parseNginxVersion(text);
  assert.ok(v, "version should parse");
  return v;
}

function verdictFor(versionText, configText) {
  const version = parseNginxVersion(versionText);
  const config = configText === null ? null : parseConfigText(configText);
  return decideVerdict({
    version,
    config,
    configSource: configText === null ? "" : "fixture",
    internetFacing: false,
    rawVersion: versionText,
  });
}

const HTTP2_PROXY = ex("nginx-T-http2-proxy.txt");
const HTTP2_OFF = ex("nginx-T-http2-off.txt");
const PLAIN = ex("nginx-T-plain.txt");
const HTTP2_ON_DIR = ex("config-http2-on-directive.conf");
const HTTP3_RES_MAIL = ex("config-http3-resolver-mail.conf");

// --- version parsing ---

test("version: recorded Ubuntu 1.24.0 parses with distro suffix", () => {
  const v = ver(V_REAL_1240);
  assert.equal(v.raw, "1.24.0");
  assert.equal(v.line, "stable");
  assert.equal(v.distro, "(Ubuntu)");
  assert.equal(v.isPlus, false);
});

test("version: 1.31.8 parses as mainline", () => {
  const v = ver(V_1318);
  assert.equal(v.raw, "1.31.8");
  assert.equal(v.line, "mainline");
});

test("version: 1.30.7 parses as stable", () => {
  const v = ver(V_1307);
  assert.equal(v.raw, "1.30.7");
  assert.equal(v.line, "stable");
});

test("version: unparseable output returns null", () => {
  assert.equal(parseNginxVersion("nginx: command not found"), null);
  assert.equal(parseNginxVersion(""), null);
});

test("version: Plus marker is detected (synthetic fixture)", () => {
  const v = ver(V_PLUS);
  assert.equal(v.isPlus, true);
});

// --- fixed-version compare: stable vs mainline lines ---

test("fixed: 1.30.6 affected, 1.30.7 fixed, 1.31.8 affected, 1.31.9 fixed", () => {
  assert.equal(isFixedVersion(ver("nginx version: nginx/1.30.6")), false);
  assert.equal(isFixedVersion(ver("nginx version: nginx/1.30.7")), true);
  assert.equal(isFixedVersion(ver("nginx version: nginx/1.31.8")), false);
  assert.equal(isFixedVersion(ver("nginx version: nginx/1.31.9")), true);
});

test("fixed: old lines are affected (1.24.0, 1.28.0, 1.29.0)", () => {
  assert.equal(isFixedVersion(ver(V_REAL_1240)), false);
  assert.equal(isFixedVersion(ver("nginx version: nginx/1.28.0")), false);
  assert.equal(isFixedVersion(ver("nginx version: nginx/1.29.0")), false);
});

test("fixed: future mainline 1.32.0 counts as fixed", () => {
  assert.equal(isFixedVersion(ver("nginx version: nginx/1.32.0")), true);
});

test("compare: dotted ordering incl. 1.30.7 < 1.31.0", () => {
  assert.equal(
    compareVersions(
      { major: 1, minor: 30, patch: 7 },
      { major: 1, minor: 31, patch: 0 },
    ),
    -1,
  );
  assert.equal(
    compareVersions(
      { major: 1, minor: 31, patch: 9 },
      { major: 1, minor: 31, patch: 9 },
    ),
    0,
  );
});

test("patch verdict: per-CVE lower bounds (1.19.6, 1.9.4)", () => {
  const flow = CVE_TABLE.find((c) => c.cve === "CVE-2026-123007");
  const uaf = CVE_TABLE.find((c) => c.cve === "CVE-2026-123633");
  const v1196 = ver(V_1196);
  assert.equal(patchVerdictFor(v1196, flow), "affected");
  assert.equal(patchVerdictFor(v1196, uaf), "not-affected");
  const v194 = ver(V_194);
  assert.equal(patchVerdictFor(v194, flow), "not-affected");
  assert.equal(patchVerdictFor(v194, uaf), "not-affected");
  const resolver = CVE_TABLE.find((c) => c.cve === "CVE-2026-123634");
  assert.equal(patchVerdictFor(v194, resolver), "affected");
});

// --- config parsing ---

test("config: recorded real -T dump parses (http2 on + proxy)", () => {
  const parsed = parseConfigText(ex("nginx-T-real-1.24.0.txt"));
  assert.equal(parsed.servers.length, 2);
  assert.equal(parsed.http2State, "on");
  assert.equal(parsed.servers[0].http2, "on");
  assert.equal(parsed.servers[0].hasProxy, true);
  assert.equal(parsed.servers[0].serverName, "example.test");
  assert.equal(parsed.servers[1].http2, "unknown");
  assert.equal(parsed.servers[1].hasProxy, false);
});

test("config: listen http2 + proxy_pass detected per block", () => {
  const parsed = parseConfigText(HTTP2_PROXY);
  assert.equal(parsed.servers.length, 2);
  assert.equal(parsed.http2State, "on");
  assert.equal(parsed.servers[0].http2Source, "listen directive carries http2");
  assert.equal(parsed.servers[0].hasProxy, true);
});

test("config: http2 off; directive wins, state off", () => {
  const parsed = parseConfigText(HTTP2_OFF);
  assert.equal(parsed.servers.length, 1);
  assert.equal(parsed.servers[0].http2, "off");
  assert.equal(parsed.http2State, "off");
});

test("config: plain config has no http2 (state unknown)", () => {
  const parsed = parseConfigText(PLAIN);
  assert.equal(parsed.servers.length, 1);
  assert.equal(parsed.servers[0].http2, "unknown");
  assert.equal(parsed.http2State, "unknown");
});

test("config: http2 on; directive form (1.25.1+) is understood", () => {
  const parsed = parseConfigText(HTTP2_ON_DIR);
  assert.equal(parsed.servers.length, 1);
  assert.equal(parsed.servers[0].http2, "on");
  assert.equal(parsed.servers[0].http2Source, "http2 on;");
});

test("config: http3 listener, resolver, mail block detected", () => {
  const parsed = parseConfigText(HTTP3_RES_MAIL);
  assert.equal(
    parsed.servers.some((s) => s.http3),
    true,
  );
  assert.equal(parsed.hasResolver, true);
  assert.equal(parsed.hasMail, true);
  assert.equal(parsed.mailHasProxy, true);
});

test("config: comments are ignored, include is flagged", () => {
  const text =
    "# listen 443 ssl http2;\nhttp {\n  include /etc/nginx/conf.d/*.conf;\n  server {\n    listen 80;\n  }\n}\n";
  const parsed = parseConfigText(text);
  assert.equal(parsed.servers.length, 1);
  assert.equal(parsed.servers[0].http2, "unknown");
  assert.equal(parsed.hasInclude, true);
  assert.equal(parsed.includeLines.length, 1);
});

test("config: empty text has no server blocks", () => {
  const parsed = parseConfigText("");
  assert.equal(parsed.servers.length, 0);
  assert.equal(parsed.http2State, "none");
});

// --- verdict matrix ---

test("verdict: 1.31.8 + http2 + proxy is EXPOSED (both HTTP/2 CVEs named)", () => {
  const r = verdictFor(V_1318, HTTP2_PROXY);
  assert.equal(r.verdict, "EXPOSED");
  assert.match(r.deciding, /affected version \+ HTTP\/2 on/);
  assert.ok(r.reasons.some((x) => x.includes("CVE-2026-123633")));
});

test("verdict: 1.31.8 + http2 without proxy is still EXPOSED (123007 needs no proxy)", () => {
  const r = verdictFor(V_1318, HTTP2_ON_DIR);
  assert.equal(r.verdict, "EXPOSED");
});

test("verdict: 1.30.7 fixed is SAFE even with http2 on", () => {
  const r = verdictFor(V_1307, HTTP2_PROXY);
  assert.equal(r.verdict, "SAFE");
  assert.equal(r.deciding, "fixed build");
});

test("verdict: 1.31.9 fixed is SAFE", () => {
  const r = verdictFor("nginx version: nginx/1.31.9", HTTP2_PROXY);
  assert.equal(r.verdict, "SAFE");
});

test("verdict: 1.24.0 + http2 off is SAFE by config", () => {
  const r = verdictFor(V_REAL_1240, HTTP2_OFF);
  assert.equal(r.verdict, "SAFE");
  assert.equal(r.deciding, "HTTP/2 off, no secondary signal");
});

test("verdict: 1.26.0 + http2 off + http3 on is AT-RISK via CVE-2026-121810", () => {
  const r = verdictFor(
    "nginx version: nginx/1.26.0",
    ex("config-http2-off-http3.conf"),
  );
  assert.equal(r.verdict, "AT-RISK");
  assert.match(r.deciding, /CVE-2026-121810/);
});

test("verdict: 1.24.0 + http2 off + http3 on is AT-RISK (secondary)", () => {
  // 1.24.0 predates the HTTP/3 CVE range (from 1.25.0), so the
  // secondary signal that fires here is the resolver CVE (the
  // fixture has a resolver directive at http level).
  const r = verdictFor(V_REAL_1240, ex("config-http2-off-http3.conf"));
  assert.equal(r.verdict, "AT-RISK");
  assert.match(r.deciding, /CVE-2026-123634/);
});

test("verdict: 1.24.0 + plain config (http2 unknown) is AT-RISK", () => {
  const r = verdictFor(V_REAL_1240, PLAIN);
  assert.equal(r.verdict, "AT-RISK");
  assert.equal(r.deciding, "HTTP/2 state unknown in config");
});

test("verdict: affected version + no config at all is AT-RISK", () => {
  const r = verdictFor(V_REAL_1240, null);
  assert.equal(r.verdict, "AT-RISK");
  assert.equal(r.deciding, "HTTP/2 state unknown");
});

test("verdict: 1.19.6 + http2 on is EXPOSED via 123007 only (below 123633 range)", () => {
  const r = verdictFor(V_1196, HTTP2_PROXY);
  assert.equal(r.verdict, "EXPOSED");
  const uaf = r.cves.find((c) => c.cve === "CVE-2026-123633");
  assert.equal(uaf.patch, "not-affected");
});

test("verdict: 1.9.4 + http2 on is SAFE (below both HTTP/2 ranges, no secondary met)", () => {
  const r = verdictFor(V_194, HTTP2_ON_DIR);
  assert.equal(r.verdict, "SAFE");
});

test("verdict: unparseable version is UNKNOWN", () => {
  const r = decideVerdict({
    version: null,
    config: parseConfigText(HTTP2_PROXY),
    configSource: "fixture",
    internetFacing: false,
    rawVersion: "garbage",
  });
  assert.equal(r.verdict, "UNKNOWN");
});

test("verdict: Plus build is UNKNOWN, never SAFE", () => {
  const r = verdictFor(V_PLUS, HTTP2_OFF);
  assert.equal(r.verdict, "UNKNOWN");
  assert.match(r.reasons.join(" "), /Plus fixed builds differ/);
});

test("verdict: internet-facing flag is recorded in EXPOSED reasons", () => {
  const r = decideVerdict({
    version: parseNginxVersion(V_1318),
    config: parseConfigText(HTTP2_PROXY),
    configSource: "fixture",
    internetFacing: true,
    rawVersion: V_1318,
  });
  assert.equal(r.verdict, "EXPOSED");
  assert.ok(r.reasons.some((x) => x.includes("faces the internet")));
});

// --- sockets parsing ---

test("sockets: ss -tlnp dump yields listening ports", () => {
  const ports = parseSocketsText(ex("sockets.txt"));
  assert.deepEqual(ports, [80, 443, 8080]);
});

test("sockets: empty dump yields no ports", () => {
  assert.deepEqual(parseSocketsText(""), []);
});
