# examples/ - provenance

## Recorded from a real NGINX binary (19/11/2026)

- `nginx-V-real-1.24.0.txt` - `nginx -V` output of the real Ubuntu
  nginx 1.24.0 binary (nginx_1.24.0-2ubuntu7.19_amd64.deb from the
  Ubuntu archive, extracted and run on this build machine).
- `nginx-T-real-1.24.0.txt` - `nginx -T` output of the same binary
  against a real config written for this build (one server block
  with `listen 443 ssl http2;` and a proxy_pass, one plain HTTP
  block). The config used a self-signed certificate generated for
  the test; the dump is the binary's own output, paths included.

## Representative format (version numbers verified, output shape only)

- `nginx-V-1.31.8.txt` - NGINX 1.31.8 (affected, mainline). The
  version number is from the F5 / Wiz advisories (18/11/2026); the
  configure-arguments line is representative, not recorded.
- `nginx-V-1.30.7.txt` - NGINX 1.30.7 (fixed, stable). Same basis.
- `nginx-V-1.19.6.txt` - NGINX 1.19.6 (in the CVE-2026-123007
  range, below the CVE-2026-123633 range). Same basis.
- `nginx-V-1.9.4.txt` - NGINX 1.9.4 (below the CVE-2026-123007
  range, in the resolver / mail secondary ranges). Same basis.

## Synthetic format (labelled, not recorded)

- `nginx-V-plus-1.31.8.txt` - SYNTHETIC: the NGINX Plus `-V`
  string format was not verified live. The file exists only so the
  Plus detection path has a test input; the tool reports any Plus
  build as UNKNOWN and the README says so.

## Config fixtures (hand-written for tests and the demo)

- `nginx-T-http2-proxy.txt` - `nginx -T` dump shape: HTTP/2 on
  with a proxy_pass block, plus a plain HTTP block.
- `nginx-T-http2-off.txt` - same shape with `http2 off;`.
- `nginx-T-plain.txt` - plain HTTP only, no HTTP/2 anywhere.
- `config-http2-on-directive.conf` - the `http2 on;` directive
  form (NGINX 1.25.1 and later).
- `config-http3-resolver-mail.conf` - HTTP/3 listener, a resolver
  directive, and a mail proxy block (secondary signals).
- `sockets.txt` - an `ss -tlnp` dump in the tool's input format.
