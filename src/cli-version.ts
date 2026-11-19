/**
 * Shared constants: tool version and the date the CVE facts below
 * were last verified against Wiz (nginx2shell.com) and the NGINX
 * security advisories (nginx.org). Fix guidance goes stale, so
 * every output that cites a fixed build also cites this date.
 */
export const VERSION = "0.1.0";
export const CHECKED_AT = "2026-11-19";
export const CVE_HTTP2_FLOW = "CVE-2026-123007";
export const CVE_HTTP2_UAF = "CVE-2026-123633";
export const CVE_HTTP3_UAF = "CVE-2026-121810";
export const CVE_RESOLVER_UAF = "CVE-2026-123634";
export const CVE_MAIL_UAF = "CVE-2026-113425";
