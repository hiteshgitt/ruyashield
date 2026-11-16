import { promises as dns } from "node:dns";
import http from "node:http";
import https from "node:https";
import type { LookupFunction } from "node:net";
import { isBlockedIp, isIpLiteral } from "./ip";

export const EGRESS_TIMEOUT_MS = 5000;
export const EGRESS_MAX_BODY = 64 * 1024;
export const EGRESS_MAX_REDIRECTS = 3;
const USER_AGENT = "RuyaShield-Verifier/0.1 (+ownership verification)";

export class EgressError extends Error {
  constructor(public code: "egress_blocked" | "bad_url" | "dns_failed" | "timeout" | "too_large" | "redirect_refused" | "network", message: string) {
    super(message);
  }
}

export interface Resolved { address: string; family: 4 | 6 }

export interface EgressDeps {
  /** Resolves a hostname to every address it maps to. */
  resolve?: (host: string) => Promise<Resolved[]>;
  /** Dev/test only: allow private destinations and non-default ports. Refused in production. */
  allowPrivate?: boolean;
  timeoutMs?: number;
  userAgent?: string;
  accept?: string;
  /** Called before every request, redirect hops included. Throw to block the request. */
  onHop?: (url: URL) => void | Promise<void>;
  /** Read at most this many body bytes, then stop reading and return what arrived (result.truncated = true). */
  truncateAt?: number;
  /** false = return a 3xx as-is instead of following it (default true). */
  followRedirects?: boolean;
  /**
   * Read-only scanner checks only (headers, exposure): connect even when the certificate is untrusted, expired or uses
   * a weak key, so a broken certificate does not hide the site from those checks. TLS problems themselves are
   * reported by tls.cert_expiry / tls.config. Never used for ownership verification or any call that sends data.
   */
  tlsLenient?: boolean;
  /** http.cors only: an Origin request header to send (an ordinary header; no request body is ever sent). */
  origin?: string;
}

const defaultResolve = async (host: string): Promise<Resolved[]> => {
  const all = await dns.lookup(host, { all: true, verbatim: true });
  return all.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }));
};

export function allowPrivateFromEnv(): boolean {
  return process.env.EGRESS_ALLOW_PRIVATE === "true" && process.env.NODE_ENV !== "production";
}

const LOOPBACK = /^(127\.\d+\.\d+\.\d+|::1|::ffff:127\.\d+\.\d+\.\d+)$/;

/**
 * Dev only: EGRESS_DEV_PORT_MAP="443:8443,80:8080" makes a connection to a LOOPBACK address use the mapped port, so a
 * local demo target can stand in for a real site without root. Ignored unless private egress is allowed and never in
 * production; URLs, scope checks and findings keep the real port.
 */
export function devPort(port: number, address: string, allowPrivate: boolean): number {
  if (!allowPrivate || process.env.NODE_ENV === "production" || !LOOPBACK.test(address)) return port;
  for (const pair of (process.env.EGRESS_DEV_PORT_MAP ?? "").split(",")) {
    const [from, to] = pair.split(":").map((x) => Number(x.trim()));
    if (from === port && Number.isInteger(to) && to > 0 && to < 65536) return to;
  }
  return port;
}

/** Resolves host and returns one validated address to pin; throws if any resolved address is not public. */
/** Every address is validated; `family` picks the first validated address of that family (null when there is none). */
export async function resolvePublic(host: string, deps?: EgressDeps): Promise<Resolved>;
export async function resolvePublic(host: string, deps: EgressDeps, family: 4 | 6): Promise<Resolved | null>;
export async function resolvePublic(host: string, deps: EgressDeps = {}, family?: 4 | 6): Promise<Resolved | null> {
  const allowPrivate = !!deps.allowPrivate && process.env.NODE_ENV !== "production";
  let addrs: Resolved[];
  try {
    addrs = await (deps.resolve ?? defaultResolve)(host);
  } catch {
    throw new EgressError("dns_failed", `Could not resolve ${host}`);
  }
  if (!addrs.length) throw new EgressError("dns_failed", `No addresses for ${host}`);
  if (!allowPrivate && addrs.some((a) => isBlockedIp(a.address))) {
    throw new EgressError("egress_blocked", `${host} resolves to a non-public address`);
  }
  return family ? addrs.find((a) => a.family === family) ?? null : addrs[0];
}

export interface FetchResult {
  status: number;
  finalUrl: string;
  contentType: string | null;
  body: string;
  redirects: number;
  pinnedAddress: string;
  headers: http.IncomingHttpHeaders;
  /** True when truncateAt cut the body short. */
  truncated: boolean;
}

/**
 * GET with SSRF protections: http(s) only, default ports, every resolved address validated and the
 * connection pinned to a validated address (no DNS rebinding between check and connect), 5 s timeout,
 * 64 KB body cap, at most 3 redirects and only to the same host.
 */
export async function guardedGet(rawUrl: string, deps: EgressDeps = {}): Promise<FetchResult> {
  const allowPrivate = !!deps.allowPrivate && process.env.NODE_ENV !== "production";
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new EgressError("bad_url", "Invalid URL");
  }
  const originalHost = url.hostname.toLowerCase();
  if (deps.origin !== undefined && !/^(null|https?:\/\/[a-z0-9.-]{1,253})$/i.test(deps.origin)) throw new EgressError("bad_url", "Invalid Origin header");
  const deadline = Date.now() + (deps.timeoutMs ?? EGRESS_TIMEOUT_MS);

  for (let redirects = 0; ; redirects++) {
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new EgressError("bad_url", "Only http and https are allowed");
    if (url.username || url.password) throw new EgressError("bad_url", "Credentials in URL are not allowed");
    if (url.port && !allowPrivate) throw new EgressError("bad_url", "Only default ports are allowed");
    if (isIpLiteral(url.hostname) && !allowPrivate) throw new EgressError("egress_blocked", "IP literal destinations are not allowed");
    if (url.hostname.toLowerCase() !== originalHost) throw new EgressError("redirect_refused", "Redirect to a different host refused");

    await deps.onHop?.(url);
    const pinned = await resolvePublic(url.hostname, deps);
    const res = await requestOnce(url, pinned, deadline, { ...deps, allowPrivate });
    if (res.status >= 300 && res.status < 400 && res.location && deps.followRedirects !== false) {
      if (redirects >= EGRESS_MAX_REDIRECTS) throw new EgressError("redirect_refused", "Too many redirects");
      const next = new URL(res.location, url);
      if (next.hostname.toLowerCase() !== originalHost) throw new EgressError("redirect_refused", "Redirect to a different host refused");
      if (url.protocol === "https:" && next.protocol === "http:") throw new EgressError("redirect_refused", "Downgrade from https refused");
      url = next;
      continue;
    }
    return { status: res.status, finalUrl: url.toString(), contentType: res.contentType, body: res.body, redirects, pinnedAddress: pinned.address, headers: res.headers, truncated: res.truncated };
  }
}

function requestOnce(url: URL, pinned: Resolved, deadline: number, deps: EgressDeps) {
  type Raw = { status: number; location: string | null; contentType: string | null; body: string; headers: http.IncomingHttpHeaders; truncated: boolean };
  return new Promise<Raw>((resolve, reject) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) return reject(new EgressError("timeout", "Request timed out"));
    // Pin: whatever name the socket asks for, it gets only the address validated above.
    const lookup: LookupFunction = (_host, opts, cb) => {
      if (opts && (opts as { all?: boolean }).all) (cb as unknown as (e: null, a: { address: string; family: number }[]) => void)(null, [{ address: pinned.address, family: pinned.family }]);
      else cb(null, pinned.address, pinned.family);
    };
    const cap = deps.truncateAt !== undefined ? Math.max(0, Math.min(deps.truncateAt, EGRESS_MAX_BODY)) : null;
    let settled = false;
    const done = (fn: () => void) => { if (settled) return; settled = true; clearTimeout(timer); fn(); };
    const mod = url.protocol === "https:" ? https : http;
    const port = devPort(Number(url.port) || (url.protocol === "https:" ? 443 : 80), pinned.address, !!deps.allowPrivate);
    const req = mod.request(url, {
      method: "GET", lookup, port, headers: { "user-agent": deps.userAgent ?? USER_AGENT, accept: deps.accept ?? "text/plain, text/html;q=0.9", ...(deps.origin ? { origin: deps.origin } : {}) },
      servername: url.protocol === "https:" ? url.hostname : undefined,
      ...(url.protocol === "https:" && deps.tlsLenient ? { rejectUnauthorized: false, ciphers: "DEFAULT:@SECLEVEL=0", minVersion: "TLSv1" as const } : {}),
    }, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      const finish = (truncated: boolean) => done(() => {
        const loc = res.headers.location;
        resolve({
          status: res.statusCode ?? 0, location: typeof loc === "string" ? loc : null,
          contentType: res.headers["content-type"] ?? null, body: Buffer.concat(chunks).toString("utf8"),
          headers: res.headers, truncated,
        });
      });
      res.on("data", (c: Buffer) => {
        if (settled) return;
        if (cap !== null && size + c.length >= cap) {
          // Keep exactly `cap` bytes and stop downloading: the rest of the file is never read.
          const room = cap - size;
          chunks.push(c.subarray(0, room));
          size = cap;
          finish(c.length > room || !res.complete);
          req.destroy();
          return;
        }
        size += c.length;
        if (size > EGRESS_MAX_BODY) {
          req.destroy(new EgressError("too_large", "Response exceeded 64 KB"));
          return;
        }
        chunks.push(c);
      });
      res.on("end", () => finish(false));
      res.on("error", (e) => done(() => reject(e instanceof EgressError ? e : new EgressError("network", e.message))));
    });
    const timer = setTimeout(() => req.destroy(new EgressError("timeout", "Request timed out")), remaining);
    req.on("error", (e) => done(() => reject(e instanceof EgressError ? e : new EgressError("network", e.message))));
    req.end();
  });
}

export interface TxtDeps { resolvers?: string[][]; resolveTxt?: (name: string, servers: string[]) => Promise<string[][]>; timeoutMs?: number }

export function resolversFromEnv(): string[][] {
  const raw = process.env.DNS_RESOLVERS ?? "1.1.1.1,8.8.8.8";
  return raw.split(",").map((s) => s.trim()).filter(Boolean).map((s) => [s]);
}

const defaultResolveTxt = async (name: string, servers: string[], timeoutMs: number) => {
  const r = new dns.Resolver({ timeout: timeoutMs, tries: 2 });
  r.setServers(servers);
  return r.resolveTxt(name);
};

export type TxtLookup = { resolver: string; records: string[] | null; error: string | null };

/** Queries the TXT name on each independent resolver. Callers decide agreement. */
export async function lookupTxtEverywhere(name: string, deps: TxtDeps = {}): Promise<TxtLookup[]> {
  const resolvers = deps.resolvers ?? resolversFromEnv();
  const timeoutMs = deps.timeoutMs ?? EGRESS_TIMEOUT_MS;
  return Promise.all(resolvers.map(async (servers) => {
    try {
      const recs = deps.resolveTxt ? await deps.resolveTxt(name, servers) : await defaultResolveTxt(name, servers, timeoutMs);
      return { resolver: servers.join(","), records: recs.map((parts) => parts.join("")), error: null };
    } catch (e) {
      const code = (e as { code?: string }).code ?? "error";
      // NXDOMAIN / no data are answers, not failures.
      if (code === "ENOTFOUND" || code === "ENODATA") return { resolver: servers.join(","), records: [], error: null };
      return { resolver: servers.join(","), records: null, error: code };
    }
  }));
}

export interface TlsInfo { validTo: string; validFrom: string; subject: string | null; issuer: string | null; authorized: boolean; authorizationError: string | null; pinnedAddress: string }

/**
 * Opens a TLS handshake to the pinned, validated address of host:443 and reads the peer certificate.
 * No HTTP request is sent. Same address rules as guardedGet.
 */
export async function tlsProbe(host: string, deps: EgressDeps & { port?: number } = {}): Promise<TlsInfo> {
  const allowPrivate = !!deps.allowPrivate && process.env.NODE_ENV !== "production";
  if (isIpLiteral(host) && !allowPrivate) throw new EgressError("egress_blocked", "IP literal destinations are not allowed");
  if (deps.port && deps.port !== 443 && !allowPrivate) throw new EgressError("bad_url", "Only the default port is allowed");
  const url = new URL(`https://${host}${deps.port && deps.port !== 443 ? `:${deps.port}` : ""}/`);
  await deps.onHop?.(url);
  const pinned = await resolvePublic(host, deps);
  const { connect } = await import("node:tls");
  return new Promise<TlsInfo>((resolve, reject) => {
    const sock = connect({ host: pinned.address, port: devPort(deps.port ?? 443, pinned.address, allowPrivate), servername: isIpLiteral(host) ? undefined : host, rejectUnauthorized: false });
    const timer = setTimeout(() => sock.destroy(new EgressError("timeout", "TLS handshake timed out")), deps.timeoutMs ?? EGRESS_TIMEOUT_MS);
    sock.once("secureConnect", () => {
      clearTimeout(timer);
      const c = sock.getPeerCertificate();
      sock.end();
      if (!c || !c.valid_to) return reject(new EgressError("network", "No peer certificate"));
      const name = (x: unknown) => (x && typeof x === "object" && "CN" in x ? String((x as { CN: unknown }).CN) : null);
      resolve({
        validTo: c.valid_to, validFrom: c.valid_from, subject: name(c.subject), issuer: name(c.issuer),
        authorized: sock.authorized, authorizationError: sock.authorizationError ? String(sock.authorizationError) : null, pinnedAddress: pinned.address,
      });
    });
    sock.once("error", (e) => { clearTimeout(timer); reject(e instanceof EgressError ? e : new EgressError("network", e.message)); });
  });
}

export type TlsVersion = "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3";
export interface HandshakeOptions { minVersion?: TlsVersion; maxVersion?: TlsVersion; ciphers?: string }
export type HandshakeResult =
  | { outcome: "accepted"; protocol: string | null; cipher: string; keyBits: number | null; keyType: "RSA" | "EC" | "other"; authorizationError: string | null; pinnedAddress: string }
  /** The server answered but would not complete a handshake with these settings (alert, reset, close). */
  | { outcome: "refused"; code: string; pinnedAddress: string }
  /** This client cannot offer these settings (OpenSSL build lacks the protocol or cipher), so nothing was learned. */
  | { outcome: "untestable"; code: string; pinnedAddress: string };

/** Client-side OpenSSL refusals: the request never reached the server in a meaningful form. */
const CLIENT_CANNOT = /NO_PROTOCOLS_AVAILABLE|no cipher match|NO_CIPHER_MATCH|ERR_TLS_INVALID_PROTOCOL_VERSION|ERR_INVALID_ARG/i;
/** What a server refusing a protocol version or cipher set looks like from the client. */
const SERVER_REFUSED = /alert|WRONG_VERSION_NUMBER|UNSUPPORTED_PROTOCOL|NO_SHARED_CIPHER|ECONNRESET|EPIPE|disconnected before secure TLS|socket hang up|UNEXPECTED_EOF|unexpected eof/i;

/**
 * One TLS handshake pinned to a protocol range and/or cipher list, to the validated address of host:443
 * (scanner M6, tls.config). Like tlsProbe: no HTTP request, same address rules, onHop before connecting.
 *  - The certificate is not validated (we record why it would fail instead).
 *  - A timeout or an unexpected socket error throws, so the caller fails closed.
 *  - Old protocols need OpenSSL security level 0 on the client; if the local build still cannot offer them the
 *    result is "untestable", never "refused".
 */
export async function tlsHandshake(host: string, opts: HandshakeOptions, deps: EgressDeps & { port?: number } = {}): Promise<HandshakeResult> {
  const allowPrivate = !!deps.allowPrivate && process.env.NODE_ENV !== "production";
  if (isIpLiteral(host) && !allowPrivate) throw new EgressError("egress_blocked", "IP literal destinations are not allowed");
  if (deps.port && deps.port !== 443 && !allowPrivate) throw new EgressError("bad_url", "Only the default port is allowed");
  await deps.onHop?.(new URL(`https://${host}${deps.port && deps.port !== 443 ? `:${deps.port}` : ""}/`));
  const pinned = await resolvePublic(host, deps);
  const tls = await import("node:tls");
  const codeOf = (e: unknown) => { const x = e as { code?: string; message?: string }; return `${x.code ?? ""} ${x.message ?? ""}`.trim(); };
  let sock: import("node:tls").TLSSocket;
  try {
    sock = tls.connect({
      host: pinned.address, port: devPort(deps.port ?? 443, pinned.address, allowPrivate), servername: isIpLiteral(host) ? undefined : host, rejectUnauthorized: false,
      minVersion: opts.minVersion, maxVersion: opts.maxVersion, ciphers: opts.ciphers,
    });
  } catch (e) {
    // Thrown synchronously while building the client context: this client cannot offer it.
    return { outcome: "untestable", code: codeOf(e).slice(0, 120), pinnedAddress: pinned.address };
  }
  return new Promise<HandshakeResult>((resolve, reject) => {
    let settled = false;
    const settle = (fn: () => void) => { if (!settled) { settled = true; clearTimeout(timer); fn(); } };
    const timer = setTimeout(() => { settle(() => reject(new EgressError("timeout", "TLS handshake timed out"))); sock.destroy(); }, deps.timeoutMs ?? EGRESS_TIMEOUT_MS);
    sock.once("secureConnect", () => settle(() => {
      const c = sock.getPeerCertificate() as import("node:tls").PeerCertificate & { asn1Curve?: string; modulus?: string };
      const keyType = c && c.modulus ? "RSA" : c && c.asn1Curve ? "EC" : "other";
      resolve({
        outcome: "accepted", protocol: sock.getProtocol(), cipher: sock.getCipher()?.name ?? "unknown",
        keyBits: c && typeof c.bits === "number" ? c.bits : null, keyType,
        authorizationError: sock.authorizationError ? String(sock.authorizationError) : null, pinnedAddress: pinned.address,
      });
      sock.end();
    }));
    sock.once("error", (e) => settle(() => {
      const code = codeOf(e);
      if (CLIENT_CANNOT.test(code)) resolve({ outcome: "untestable", code: code.slice(0, 120), pinnedAddress: pinned.address });
      else if (SERVER_REFUSED.test(code)) resolve({ outcome: "refused", code: code.slice(0, 120), pinnedAddress: pinned.address });
      else reject(new EgressError("network", code.slice(0, 200)));
    }));
    sock.once("close", () => settle(() => resolve({ outcome: "refused", code: "closed", pinnedAddress: pinned.address })));
  });
}

export type PortState = "open" | "closed" | "filtered";
export interface PortResult { port: number; state: PortState; banner?: string }
export interface TcpProbeResult { pinnedAddress: string; results: PortResult[] }
/** Minimum gap between connection attempts: at most 5 connects per second to one host. */
export const TCP_MIN_SPACING_MS = 200;
const BANNER_MAX = 256;
const BANNER_WAIT_MS = 1500;

/** Keeps only printable ASCII so a banner can never carry control sequences into the UI or logs. */
export function cleanBanner(b: Buffer): string {
  return b.subarray(0, BANNER_MAX).toString("latin1").replace(/[^\x20-\x7e]+/g, " ").trim().slice(0, 160);
}

/**
 * TCP connect scan of a fixed port list (scanner M3, class A2).
 *  - Resolves once and only ever connects to that pinned, public address (no DNS rebinding between ports).
 *  - Sends nothing. On an open port it waits briefly for a server-first banner (SSH, SMTP, FTP...) and closes.
 *  - Refused = closed, no answer before the timeout = filtered. Any other socket error (host or network
 *    unreachable) throws, so the caller fails closed instead of reporting everything as "not open".
 *  - Sequential with spacing, so one host never sees a burst. onHop runs before every connect, so the scope guard
 *    can stop the scan between ports (kill switch, budget).
 */
export async function tcpProbe(host: string, ports: readonly number[], deps: EgressDeps & { spacingMs?: number; sleep?: (ms: number) => Promise<void>; bannerWaitMs?: number } = {}): Promise<TcpProbeResult> {
  const allowPrivate = !!deps.allowPrivate && process.env.NODE_ENV !== "production";
  if (isIpLiteral(host) && !allowPrivate) throw new EgressError("egress_blocked", "IP literal destinations are not allowed");
  if (!ports.length || ports.some((p) => !Number.isInteger(p) || p < 1 || p > 65535)) throw new EgressError("bad_url", "Invalid port list");
  // Scope is checked before resolving, and again before every connect (each port is one budgeted hop).
  await deps.onHop?.(new URL(`https://${host}:${ports[0]}/`));
  const pinned = await resolvePublic(host, deps);
  const { connect } = await import("node:net");
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const spacing = Math.max(TCP_MIN_SPACING_MS, deps.spacingMs ?? TCP_MIN_SPACING_MS);
  const timeoutMs = deps.timeoutMs ?? EGRESS_TIMEOUT_MS;
  const bannerWait = Math.min(deps.bannerWaitMs ?? BANNER_WAIT_MS, timeoutMs);

  const one = (port: number) => new Promise<PortResult>((resolve, reject) => {
    const sock = connect({ host: pinned.address, port: devPort(port, pinned.address, allowPrivate), family: pinned.family });
    let settled = false, connected = false;
    const done = (fn: () => void) => { if (settled) return; settled = true; clearTimeout(timer); sock.destroy(); fn(); };
    let timer = setTimeout(() => done(() => resolve({ port, state: "filtered" })), timeoutMs);
    sock.once("connect", () => {
      connected = true;
      const chunks: Buffer[] = [];
      let size = 0;
      clearTimeout(timer);
      const finish = () => done(() => resolve({ port, state: "open", ...(size ? { banner: cleanBanner(Buffer.concat(chunks)) } : {}) }));
      timer = setTimeout(finish, bannerWait);
      sock.on("data", (d: Buffer) => { chunks.push(d); size += d.length; if (size >= BANNER_MAX) finish(); });
      sock.once("end", finish);
    });
    sock.once("error", (e: NodeJS.ErrnoException) => {
      if (e.code === "ECONNREFUSED") return done(() => resolve({ port, state: "closed" }));
      // A reset after the handshake still proves the port is open (some services drop silent clients).
      if (connected) return done(() => resolve({ port, state: "open" }));
      done(() => reject(new EgressError("network", `${e.code ?? "error"} on port ${port}`)));
    });
  });

  const results: PortResult[] = [];
  for (let i = 0; i < ports.length; i++) {
    if (i > 0) { await sleep(spacing); await deps.onHop?.(new URL(`https://${host}:${ports[i]}/`)); }
    results.push(await one(ports[i]));
  }
  return { pinnedAddress: pinned.address, results };
}

export type DnsRecordType = "TXT" | "CAA" | "CNAME" | "A" | "AAAA";
export interface DnsDeps { resolvers?: string[][]; timeoutMs?: number; resolve?: (name: string, type: DnsRecordType) => Promise<string[]> }
/** nxdomain = the name does not exist at all (as opposed to existing with no record of this type). */
export type DnsAnswer = { records: string[]; nxdomain?: boolean } | { error: string };

/** One DNS query on the first configured resolver. NXDOMAIN/NODATA is an empty answer; anything else is an error. */
export async function lookupRecords(name: string, type: DnsRecordType, deps: DnsDeps = {}): Promise<DnsAnswer> {
  try {
    if (deps.resolve) return { records: await deps.resolve(name, type) };
    const r = new dns.Resolver({ timeout: deps.timeoutMs ?? EGRESS_TIMEOUT_MS, tries: 2 });
    r.setServers((deps.resolvers ?? resolversFromEnv())[0] ?? ["1.1.1.1"]);
    if (type === "TXT") return { records: (await r.resolveTxt(name)).map((p) => p.join("")) };
    if (type === "CNAME") return { records: (await r.resolveCname(name)).map((x) => x.toLowerCase().replace(/\.$/, "")) };
    if (type === "A") return { records: await r.resolve4(name) };
    if (type === "AAAA") return { records: await r.resolve6(name) };
    return { records: (await r.resolveCaa(name)).map((c) => `${c.critical} ${Object.keys(c).find((k) => k !== "critical")} ${Object.entries(c).find(([k]) => k !== "critical")?.[1] ?? ""}`) };
  } catch (e) {
    const code = (e as { code?: string }).code ?? "error";
    if (code === "ENOTFOUND") return { records: [], nxdomain: true };
    if (code === "ENODATA") return { records: [] };
    return { error: code };
  }
}
