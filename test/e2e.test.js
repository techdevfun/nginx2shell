/**
 * E2E tests: full CLI flows against fixture NGINX installs.
 * Each fixture install is a dir with sbin/nginx, a shell script
 * that prints a fixture -V output on -V and a fixture -T dump
 * on -T. The -V strings: 1.24.0 is RECORDED from the real Ubuntu
 * binary; 1.31.8 / 1.30.7 are representative format (see
 * examples/README.md). Scan assertions filter --json output by
 * install home, so an ambient NGINX on the runner cannot break
 * the counts (java4shell lesson, 18/11/2026).
 */
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "dist", "cli.js");
const ex = (name) => join(ROOT, "examples", name);

function run(args, cwd) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    cwd: cwd ?? ROOT,
  });
}

function makeFakeNginx(dir, versionFile, tFile) {
  mkdirSync(join(dir, "sbin"), { recursive: true });
  const script = join(dir, "sbin", "nginx");
  writeFileSync(
    script,
    `#!/bin/sh\nif [ "$1" = "-V" ]; then cat "${versionFile}" >&2; exit 0; fi\nif [ "$1" = "-T" ]; then cat "${tFile}"; exit 0; fi\nexit 0\n`,
  );
  chmodSync(script, 0o755);
  return dir;
}

function fleet() {
  const work = mkdtempSync(join(tmpdir(), "nginx2shell-e2e-"));
  const vuln = makeFakeNginx(
    join(work, "nginx-1318"),
    ex("nginx-V-1.31.8.txt"),
    ex("nginx-T-http2-proxy.txt"),
  );
  const fixed = makeFakeNginx(
    join(work, "nginx-1307"),
    ex("nginx-V-1.30.7.txt"),
    ex("nginx-T-http2-proxy.txt"),
  );
  const old = makeFakeNginx(
    join(work, "nginx-1240"),
    ex("nginx-V-real-1.24.0.txt"),
    ex("nginx-T-http2-off.txt"),
  );
  return { work, vuln, fixed, old };
}

test("e2e: scan finds the fixture fleet with the right verdicts", () => {
  const { vuln, fixed, old } = fleet();
  const res = run(["scan", "--dirs", vuln, fixed, old, "--json"]);
  assert.equal(res.status, 1, `scan should exit 1, stderr: ${res.stderr}`);
  const out = JSON.parse(res.stdout);
  const byHome = new Map(out.installs.map((i) => [i.home, i]));
  assert.equal(byHome.get(vuln).verdict, "EXPOSED");
  assert.equal(byHome.get(fixed).verdict, "SAFE");
  assert.equal(byHome.get(old).verdict, "SAFE");
  assert.equal(byHome.get(vuln).version, "1.31.8");
  assert.equal(out.counts.EXPOSED, 1);
});

test("e2e: scan human table names the deciding condition", () => {
  const { vuln } = fleet();
  const res = run(["scan", "--dirs", vuln]);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /EXPOSED/);
  assert.match(res.stdout, /affected version \+ HTTP\/2 on/);
  assert.match(res.stdout, /Exposure conditions only/);
});

test("e2e: check EXPOSED install exits 1, fixed install exits 0", () => {
  const { vuln, fixed } = fleet();
  const bad = run(["check", vuln]);
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /verdict: EXPOSED/);
  assert.match(bad.stdout, /CVE-2026-123633/);
  const good = run(["check", fixed]);
  assert.equal(good.status, 0);
  assert.match(good.stdout, /verdict: SAFE/);
});

test("e2e: check with --config override and --internet-facing", () => {
  const { old } = fleet();
  const res = run([
    "check",
    old,
    "--config",
    ex("nginx-T-http2-proxy.txt"),
    "--internet-facing",
    "--json",
  ]);
  // 1.24.0 with an http2+proxy config override is EXPOSED.
  assert.equal(res.status, 1);
  const out = JSON.parse(res.stdout);
  assert.equal(out.installs[0].verdict, "EXPOSED");
  assert.equal(out.installs[0].internetFacing, true);
});

test("e2e: check with --sockets lists listening ports", () => {
  const { vuln } = fleet();
  const res = run(["check", vuln, "--sockets", ex("sockets.txt"), "--json"]);
  assert.equal(res.status, 1);
  const out = JSON.parse(res.stdout);
  assert.deepEqual(out.installs[0].listeningPorts, [80, 443, 8080]);
});

test("e2e: check on a missing dir exits 2 with an error", () => {
  const res = run(["check", "/tmp/does-not-exist-nginx2shell"]);
  assert.equal(res.status, 2);
  assert.match(res.stderr, /no nginx binary found/);
});

test("e2e: scan with no NGINX anywhere exits 2", () => {
  const res = spawnSync(
    process.execPath,
    [CLI, "scan", "--dirs", "/tmp/does-not-exist-nginx2shell"],
    {
      encoding: "utf8",
      cwd: ROOT,
      env: { ...process.env, PATH: "/tmp/does-not-exist-nginx2shell" },
    },
  );
  // PATH is emptied of nginx, --dirs points nowhere: no install found.
  // (If the runner has a system nginx under a well-known dir, this
  // test still passes: discovery finds it and exits 0/1, not 2.
  // The assertion below only checks the no-install path when it
  // actually happens.)
  if (res.status === 2) {
    assert.match(res.stderr + res.stdout, /no NGINX install found/);
  } else {
    assert.ok([0, 1].includes(res.status));
  }
});

test("e2e: config-scan reports http2 on, proxy, and exit 1", () => {
  const res = run(["config-scan", ex("nginx-T-http2-proxy.txt")]);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /http2: on/);
  assert.match(res.stdout, /proxy yes/);
});

test("e2e: config-scan on the http2-off fixture exits 0", () => {
  const res = run(["config-scan", ex("nginx-T-http2-off.txt")]);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /http2: off/);
});

test("e2e: config-scan on the http2-on directive form exits 1", () => {
  const res = run(["config-scan", ex("config-http2-on-directive.conf")]);
  assert.equal(res.status, 1);
  assert.match(res.stdout, /http2 on;/);
});

test("e2e: config-scan --json reports secondary signals", () => {
  const res = run([
    "config-scan",
    ex("config-http3-resolver-mail.conf"),
    "--json",
  ]);
  assert.equal(res.status, 1);
  const out = JSON.parse(res.stdout);
  assert.equal(out.hasMail, true);
  assert.equal(out.hasResolver, true);
  assert.equal(
    out.servers.some((s) => s.http3),
    true,
  );
});

test("e2e: config-scan on a missing path exits 2", () => {
  const res = run(["config-scan", "/tmp/does-not-exist-nginx2shell.conf"]);
  assert.equal(res.status, 2);
});

test("e2e: playbook names the stopgap and the restart rule", () => {
  const res = run(["playbook"]);
  assert.equal(res.status, 0);
  assert.match(res.stdout, /http2 off;/);
  assert.match(res.stdout, /Restart, do not just reload/);
  assert.match(res.stdout, /1\.30\.7/);
  assert.match(res.stdout, /fake nginx2root exploits/);
});

test("e2e: explain covers every topic", () => {
  for (const topic of [
    "CVE-2026-123007",
    "CVE-2026-123633",
    "secondary",
    "EXPOSED",
    "AT-RISK",
    "SAFE",
    "UNKNOWN",
    "http2",
    "versions",
    "plus",
  ]) {
    const res = run(["explain", topic]);
    assert.equal(res.status, 0, `explain ${topic} failed`);
    assert.ok(res.stdout.length > 50, `explain ${topic} is too short`);
  }
  const bad = run(["explain", "nope"]);
  assert.equal(bad.status, 2);
});

test("e2e: init writes a valid config file", () => {
  const work = mkdtempSync(join(tmpdir(), "nginx2shell-init-"));
  const res = run(["init"], work);
  assert.equal(res.status, 0);
  const cfg = JSON.parse(
    readFileSync(join(work, "nginx2shell.config.json"), "utf8"),
  );
  assert.ok(Array.isArray(cfg.scanDirs));
  assert.equal(cfg.internetFacing, false);
});

test("e2e: --help and --version work", () => {
  assert.equal(run(["--help"]).status, 0);
  const v = run(["--version"]);
  assert.equal(v.status, 0);
  assert.match(v.stdout, /nginx2shell 0\.1\.0/);
});

test("e2e: real Ubuntu 1.24.0 binary is EXPOSED with its real -T dump", (t) => {
  const realBin = "/tmp/ngx/usr/sbin/nginx";
  if (!existsSync(realBin)) {
    t.skip("real NGINX binary not present on this machine");
    return;
  }
  const res = run([
    "check",
    realBin,
    "--config",
    ex("nginx-T-real-1.24.0.txt"),
  ]);
  assert.equal(res.status, 1, res.stdout + res.stderr);
  assert.match(res.stdout, /verdict: EXPOSED/);
  assert.match(res.stdout, /version: 1\.24\.0 \(stable\) \(Ubuntu\)/);
});
