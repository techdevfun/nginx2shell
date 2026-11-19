/**
 * Playbook (first-hour stopgap) and explain topics. Every claim
 * cites its source and the check date 2026-11-19: Wiz
 * (nginx2shell.com) and the NGINX security advisories
 * (nginx.org/en/security_advisories.html).
 */
import { CHECKED_AT } from "./cli-version.js";

export const PLAYBOOK_STEPS: { title: string; detail: string }[] = [
  {
    title: "1. Inventory in the hour, not the week",
    detail:
      "Run `nginx2shell scan` on every host that runs NGINX. Patch the EXPOSED ones first: internet-facing servers with HTTP/2 on. A version-only scan over-flags hosts with HTTP/2 off.",
  },
  {
    title: "2. Patch to the fixed build",
    detail:
      "NGINX OSS 1.30.7 (stable) or 1.31.9 (mainline), released 18/11/2026. NGINX Plus: 37.0.7.1 / 37.2.0.1 fix CVE-2026-123633, 37.0.8.1 / 37.3.0.1 fix CVE-2026-123007. Distro packages: confirm the backport in the distro advisory, the version string alone does not prove the fix.",
  },
  {
    title: "3. If you cannot patch today, turn HTTP/2 off",
    detail:
      "On NGINX 1.25.1 or later set `http2 off;` in the affected server blocks. On older versions remove `http2` from the `listen` directive. This is a config change, not a project. It does NOT fix the other three Critical flaws in the same release (HTTP/3, resolver, mail proxy).",
  },
  {
    title: "4. Restart, do not just reload",
    detail:
      "A reload leaves the old master process running, so the binary does not change. Restart NGINX after the upgrade, then re-run `nginx2shell scan` to confirm the fixed build and that no server block still has HTTP/2 on.",
  },
  {
    title: "5. Check the other three Critical flaws too",
    detail:
      "The same release fixes CVE-2026-121810 (HTTP/3), CVE-2026-123634 (DNS resolver) and CVE-2026-113425 (mail proxy), all CVSS 4.0 9.2. `nginx2shell check` reports them as secondary signals when the config condition is met.",
  },
  {
    title: "6. Watch for worker crashes while you patch",
    detail:
      "Wiz suggests investigating unexpected worker crashes (error log lines like `worker process 1234 exited on signal 11`) and commands launched by nginx. No exploitation in the wild has been reported as of 18/11/2026.",
  },
  {
    title: "7. What NOT to do",
    detail:
      "Do not run exploit code from untrusted repositories: fake nginx2root exploits are circulating on GitHub. Do not probe other hosts. This tool never probes a port and never runs exploit input.",
  },
];

export const EXPLAIN_TOPICS: Record<string, string> = {
  "CVE-2026-123007": `CVE-2026-123007 - HTTP/2 send_window integer underflow (RCE).
Affected: NGINX OSS 1.9.5-1.31.8 (in the code since 1.9.5, September 2015).
Fixed: 1.30.7 stable / 1.31.9 mainline (18/11/2026).
Scores: CVSS 4.0 9.2 Critical / CVSS 3.1 8.1 High (F5).
Needs: HTTP/2 enabled. Wiz demonstrated unauthenticated RCE with an
ASLR bypass on official 1.31.7/1.31.8 builds serving ordinary static
files over HTTPS, no backend, no third-party module.
Status as of ${CHECKED_AT}: no exploitation in the wild reported;
Rapid7 has published a PoC for this CVE (about 128 GB of HTTP/2
traffic over one connection, relies on a specific glibc memory-copy
routine chosen on AVX-512 CPUs); Wiz has not published its exploit.
Source: Wiz, nginx2shell.com; NGINX security advisories, nginx.org.`,
  "CVE-2026-123633": `CVE-2026-123633 - HTTP/2 use-after-free (RCE).
Affected: NGINX OSS 1.19.7-1.31.8 (since 1.19.7, February 2021).
Fixed: 1.30.7 stable / 1.31.9 mainline (18/11/2026).
Scores: CVSS 4.0 9.2 Critical / CVSS 3.1 8.1 High (F5).
Needs: HTTP/2 enabled AND proxying to a backend AND free worker
connections running low (runtime state this tool cannot observe;
check the error log for "worker_connections are not enough").
Wiz reported RCE with an ASLR bypass in its lab; F5 says code
execution applies when ASLR is disabled or an attacker can bypass it.
Status as of ${CHECKED_AT}: no exploitation in the wild reported.
Source: Wiz, nginx2shell.com; NGINX security advisories, nginx.org.`,
  secondary: `The other three Critical 9.2 flaws in the 18/11/2026 release.
All three are fixed by the same builds (1.30.7 stable / 1.31.9
mainline). Turning HTTP/2 off does NOT fix them.
- CVE-2026-121810: HTTP/3 use-after-free, 1.25.0-1.31.8, needs an
  HTTP/3 / QUIC listener.
- CVE-2026-123634: DNS resolver use-after-free, 0.6.18-1.31.8, needs
  a resolver directive in use.
- CVE-2026-113425: mail proxy use-after-free, 0.5.33-1.31.8, needs
  a mail proxy block in use.
nginx2shell reports them as secondary signals: version range plus
the config condition, never a full audit of those subsystems.
Source: NGINX security advisories, nginx.org (checked ${CHECKED_AT}).`,
  EXPOSED: `EXPOSED means: the NGINX version is in the affected range for
CVE-2026-123007 AND HTTP/2 is on in at least one server block.
Patch to 1.30.7 / 1.31.9 now, or turn HTTP/2 off as a stopgap
(see: playbook). If an HTTP/2 block also proxies to a backend,
CVE-2026-123633 applies as well.`,
  "AT-RISK": `AT-RISK is the honest middle verdict. It means the version is
in the affected range but the tool could not settle the config:
either no config could be read (run on the host, or pass --config
with the nginx -T dump), or HTTP/2 is off while a secondary signal
applies (HTTP/3 on, resolver in use, or mail proxy in use).
AT-RISK is never silently SAFE: treat it as exposed until proven otherwise.`,
  SAFE: `SAFE means the checked conditions do not line up: a fixed
build (1.30.7 stable / 1.31.9 mainline or later), or an affected
version with HTTP/2 off in every server block and no secondary
signal, or a version below every affected range. SAFE is not a
claim that the host is safe from every NGINX flaw - only the five
NGINX2Shell Critical CVEs are checked.`,
  UNKNOWN: `UNKNOWN means the tool could not decide: the version string
could not be parsed, nginx -V failed, or the build is NGINX Plus
(Plus fixed builds differ per CVE and cannot be mapped from the
OSS table - confirm the Plus build in the F5 advisory). UNKNOWN
is never SAFE.`,
  http2: `HTTP/2 is off by default in NGINX (the http2 directive
defaults to off, and the HTTP/2 module is not built by default).
Two forms enable it: the listen parameter (listen 443 ssl http2;)
and the directive (http2 on; on NGINX 1.25.1 and later). The
stopgap is the reverse: http2 off; on 1.25.1+, or remove http2
from the listen directive on older versions. nginx2shell parses
both forms per server block from nginx -T output or config files.`,
  versions: `Fixed builds as of ${CHECKED_AT}: OSS 1.30.7 (stable line,
even minor) and 1.31.9 (mainline, odd minor). A version is fixed
iff it is >= 1.31.9, or >= 1.30.7 and < 1.31.0. Older stable and
mainline lines below those builds are affected for the CVEs whose
range covers them. Distro builds (nginx/1.24.0 (Ubuntu)) parse from
the nginx/X.Y.Z prefix; confirm distro backports in the vendor
advisory. NGINX Plus: 37.0.7.1 / 37.2.0.1 fix CVE-2026-123633,
37.0.8.1 / 37.3.0.1 fix CVE-2026-123007.`,
  plus: `NGINX Plus fixed builds differ per CVE: 37.0.7.1 and 37.2.0.1
fix CVE-2026-123633, 37.0.8.1 and 37.3.0.1 fix CVE-2026-123007
(Plus from R33 / 37.0.0). The Plus -V string format was not
verified live during this build, so nginx2shell reports any Plus
build as UNKNOWN with the per-CVE fixes named, rather than
guessing from the OSS table. Source: Wiz, nginx2shell.com
(checked ${CHECKED_AT}).`,
};
