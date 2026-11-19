#!/usr/bin/env bash
# Capture the demo transcript from the REAL CLI (no hand-edited output).
# Fixture NGINX installs are dirs with a fake `nginx` shell script
# printing a fixture -V output on -V and a fixture -T dump on -T
# (see examples/ for provenance):
#   - 1.31.8 (representative format, affected mainline) + http2 proxy: EXPOSED
#   - 1.30.7 (representative format, fixed stable): SAFE
#   - 1.24.0 (RECORDED -V from the real Ubuntu binary, 19/11/2026)
#     + http2-off config: SAFE by config
# Part 5 applies the http2-off stopgap to the vulnerable install
# config and shows `check` moving EXPOSED -> SAFE.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH=/tmp/nginx2shell-demo
BIN="$SCRATCH/bin"
rm -rf "$SCRATCH"
mkdir -p "$BIN" "$ROOT/demo"
ln -sf "$ROOT/dist/cli.js" "$BIN/nginx2shell"
chmod +x "$ROOT/dist/cli.js"
export PATH="$BIN:$PATH"

WORK="$SCRATCH/fleet"
mkdir -p "$WORK"
make_fake_nginx() {
  local name="$1" version_file="$2" t_file="$3"
  mkdir -p "$WORK/$name/sbin"
  cat > "$WORK/$name/sbin/nginx" <<EOF
#!/bin/sh
if [ "\$1" = "-V" ]; then cat "$version_file" >&2; exit 0; fi
if [ "\$1" = "-T" ]; then cat "$t_file"; exit 0; fi
exit 0
EOF
  chmod +x "$WORK/$name/sbin/nginx"
}
make_fake_nginx "nginx-1318" "$ROOT/examples/nginx-V-1.31.8.txt" "$ROOT/examples/nginx-T-http2-proxy.txt"
make_fake_nginx "nginx-1307" "$ROOT/examples/nginx-V-1.30.7.txt" "$ROOT/examples/nginx-T-http2-proxy.txt"
make_fake_nginx "nginx-1240" "$ROOT/examples/nginx-V-real-1.24.0.txt" "$ROOT/examples/nginx-T-http2-off.txt"

OUT="$ROOT/demo/transcript.txt"
{
  echo "# nginx2shell demo - real CLI output on fixture NGINX installs"
  echo "# (fake nginx binaries print fixture -V outputs and -T dumps"
  echo "#  from examples/; the 1.24.0 -V text is RECORDED from the"
  echo "#  real Ubuntu binary, the 1.31.8 / 1.30.7 texts are"
  echo "#  representative format; the fleet below is synthetic)"
  echo ""
  echo "\$ nginx2shell scan --dirs nginx-1318 nginx-1307 nginx-1240"
  nginx2shell scan --dirs "$WORK/nginx-1318" "$WORK/nginx-1307" "$WORK/nginx-1240" || echo "exit: $?"
  echo ""
  echo "\$ nginx2shell check nginx-1318"
  nginx2shell check "$WORK/nginx-1318" || echo "exit: $?"
  echo ""
  echo "\$ nginx2shell config-scan nginx-T-http2-proxy.txt"
  nginx2shell config-scan "$ROOT/examples/nginx-T-http2-proxy.txt" || echo "exit: $?"
  echo ""
  echo "\$ nginx2shell playbook"
  nginx2shell playbook
  echo ""
  echo "# Stopgap: turn HTTP/2 off in the vulnerable install config"
  echo "\$ nginx2shell check nginx-1318 --config nginx-T-http2-off.txt"
  nginx2shell check "$WORK/nginx-1318" --config "$ROOT/examples/nginx-T-http2-off.txt" || echo "exit: $?"
} > "$OUT" 2>&1

echo "transcript written: $OUT ($(wc -l < "$OUT") lines)"
