/**
 * NGINX config parser: reads server blocks from `nginx -T` dump
 * text or from raw config files and reports, per block, whether
 * HTTP/2 is on, whether the block proxies, and the secondary
 * signals (HTTP/3, resolver, mail proxy).
 *
 * Forms understood:
 *   - `listen 443 ssl http2;` (pre-1.25.1 style, still valid)
 *   - `http2 on;` / `http2 off;` (1.25.1 and later)
 *   - `listen 443 quic;` / `listen 443 http3;` (HTTP/3)
 *   - `proxy_pass http://...;` anywhere inside the server block
 *   - `resolver 8.8.8.8;` anywhere inside the server block
 *   - `mail { ... }` blocks with proxy use
 *
 * Limits, stated honestly: `include` directives are NOT resolved
 * when parsing raw files - parse the `nginx -T` dump instead, which
 * is already include-resolved. A config with unresolved includes
 * is flagged so a reviewer can see the gap.
 */
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

export interface ServerBlock {
  /** Raw `listen` directive arguments, one string per directive. */
  listens: string[];
  /** HTTP/2 state for this block. */
  http2: "on" | "off" | "unknown";
  /** How the state was decided, for evidence. */
  http2Source: string;
  /** A `proxy_pass` directive appears inside this server block. */
  hasProxy: boolean;
  /** A `resolver` directive appears inside this server block. */
  hasResolver: boolean;
  /** A `listen ... quic` or `listen ... http3` line appears. */
  http3: boolean;
  /** First server_name value, or null. */
  serverName: string | null;
}

export interface ParsedConfig {
  servers: ServerBlock[];
  /** A `mail { }` block is present. */
  hasMail: boolean;
  /** The mail block proxies (proxy_pass / auth_http present). */
  mailHasProxy: boolean;
  /** A `resolver` directive appears anywhere in http context. */
  hasResolver: boolean;
  /** An `include` directive was seen (not resolved). */
  hasInclude: boolean;
  includeLines: string[];
  /** Overall HTTP/2 state: on / off / unknown / none (no blocks). */
  http2State: "on" | "off" | "unknown" | "none";
}

/** Strip `#` comments (outside quotes) from config text. */
export function stripComments(text: string): string {
  const out: string[] = [];
  let quote: string | null = null;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      out.push(ch);
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      out.push(ch);
      continue;
    }
    if (ch === "#") {
      while (i < text.length && text[i] !== "\n") i++;
      if (i < text.length) out.push("\n");
      continue;
    }
    out.push(ch);
  }
  return out.join("");
}

type Token =
  | { kind: "word"; value: string }
  | { kind: "open" }
  | { kind: "close" }
  | { kind: "semi" };

/** Split cleaned config text into words, braces and semicolons. */
function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  let current = "";
  let quote: string | null = null;
  const flush = (): void => {
    if (current.length > 0) {
      tokens.push({ kind: "word", value: current });
      current = "";
    }
  };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      current += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }
    if (ch === "{") {
      flush();
      tokens.push({ kind: "open" });
    } else if (ch === "}") {
      flush();
      tokens.push({ kind: "close" });
    } else if (ch === ";") {
      flush();
      tokens.push({ kind: "semi" });
    } else if (/\s/.test(ch)) {
      flush();
    } else {
      current += ch;
    }
  }
  flush();
  return tokens;
}

function newServer(): ServerBlock {
  return {
    listens: [],
    http2: "unknown",
    http2Source: "no http2 directive or listen flag found",
    hasProxy: false,
    hasResolver: false,
    http3: false,
    serverName: null,
  };
}

/**
 * Parse config text (a file, several files joined, or an
 * `nginx -T` dump). The dump header lines start with `#` and are
 * removed by stripComments.
 */
export function parseConfigText(text: string): ParsedConfig {
  const cleaned = stripComments(text);
  const tokens = tokenize(cleaned);
  const servers: ServerBlock[] = [];
  const includeLines: string[] = [];
  let hasMail = false;
  let mailHasProxy = false;
  let hasResolver = false;

  // Block stack: each entry is the block name ("http", "server",
  // "mail", "location", ...). The current server block, when the
  // top of the stack is inside one, is servers[servers.length - 1]
  // while the matching close has not been seen.
  const stack: string[] = [];
  // Pending directive words before a `;` or `{`.
  let pending: string[] = [];
  // Server blocks currently open, keyed by stack depth.
  const openServers = new Map<number, ServerBlock>();

  const inServer = (): ServerBlock | null => {
    for (let d = stack.length - 1; d >= 0; d--) {
      if (stack[d] === "server") return openServers.get(d) ?? null;
    }
    return null;
  };
  const inMail = (): boolean => stack.includes("mail");

  const applyDirective = (words: string[]): void => {
    if (words.length === 0) return;
    const name = words[0];
    const server = inServer();
    if (name === "include") {
      includeLines.push(words.join(" "));
      return;
    }
    // A resolver anywhere in http context counts for the
    // CVE-2026-123634 secondary signal, not only inside a server.
    if (name === "resolver") hasResolver = true;
    if (server) {
      if (name === "listen") {
        const args = words.slice(1).join(" ");
        server.listens.push(args);
        const parts = words.slice(1).map((w) => w.toLowerCase());
        if (parts.includes("http2")) {
          server.http2 = "on";
          server.http2Source = "listen directive carries http2";
        }
        if (parts.includes("http3") || parts.includes("quic")) {
          server.http3 = true;
        }
      } else if (name === "http2") {
        const value = (words[1] ?? "").toLowerCase();
        if (value === "on") {
          server.http2 = "on";
          server.http2Source = "http2 on;";
        } else if (value === "off") {
          server.http2 = "off";
          server.http2Source = "http2 off;";
        }
      } else if (name === "proxy_pass") {
        server.hasProxy = true;
      } else if (name === "resolver") {
        server.hasResolver = true;
      } else if (name === "server_name" && !server.serverName) {
        server.serverName = words[1] ?? null;
      }
    }
    if (inMail() && (name === "proxy_pass" || name === "auth_http")) {
      mailHasProxy = true;
    }
  };

  for (const tok of tokens) {
    if (tok.kind === "word") {
      pending.push(tok.value);
    } else if (tok.kind === "semi") {
      applyDirective(pending);
      pending = [];
    } else if (tok.kind === "open") {
      const blockName = pending.length > 0 ? pending[pending.length - 1] : "";
      if (blockName === "server") {
        const srv = newServer();
        servers.push(srv);
        openServers.set(stack.length, srv);
      }
      if (blockName === "mail") hasMail = true;
      stack.push(blockName);
      pending = [];
    } else if (tok.kind === "close") {
      const popped = stack.pop();
      if (popped === "server") openServers.delete(stack.length);
      pending = [];
    }
  }

  let http2State: ParsedConfig["http2State"] = "none";
  if (servers.length > 0) {
    if (servers.some((s) => s.http2 === "on")) http2State = "on";
    else if (servers.every((s) => s.http2 === "off")) http2State = "off";
    else http2State = "unknown";
  }
  return {
    servers,
    hasMail,
    mailHasProxy,
    hasResolver,
    hasInclude: includeLines.length > 0,
    includeLines,
    http2State,
  };
}

function collectConfigFiles(target: string, out: string[]): void {
  if (!existsSync(target)) return;
  const st = statSync(target);
  if (st.isFile()) {
    out.push(target);
    return;
  }
  if (st.isDirectory()) {
    for (const entry of readdirSync(target)) {
      collectConfigFiles(join(target, entry), out);
    }
  }
}

/**
 * Read a config file, a directory of config files, or an
 * `nginx -T` dump file and parse it. Returns null when the target
 * does not exist; the error text when a file cannot be read.
 */
export function parseConfigTarget(
  target: string,
): { parsed: ParsedConfig; source: string } | { error: string } {
  if (!existsSync(target)) return { error: `config path not found: ${target}` };
  const files: string[] = [];
  collectConfigFiles(target, files);
  const texts: string[] = [];
  for (const file of files) {
    try {
      texts.push(readFileSync(file, "utf8"));
    } catch (err) {
      return { error: `cannot read config file ${file}: ${String(err)}` };
    }
  }
  const parsed = parseConfigText(texts.join("\n"));
  return { parsed, source: files.join(", ") };
}

/** Parse `ss -tlnp` dump text; return the listening TCP ports found. */
export function parseSocketsText(text: string): number[] {
  const ports = new Set<number>();
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("LISTEN")) continue;
    // Columns: State Recv-Q Send-Q Local Address:Port Peer Address:Port
    const fields = trimmed.split(/\s+/);
    const local = fields[3] ?? "";
    const pm = local.match(/:(\d+)$/);
    if (pm) ports.add(Number(pm[1]));
  }
  return [...ports].sort((a, b) => a - b);
}
