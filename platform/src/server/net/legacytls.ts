import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { isIpLiteral } from "./ip";
import { devPort, EgressError, resolvePublic, type EgressDeps } from "./egress";

/**
 * Legacy cipher probes (tls.config): Node's OpenSSL 3 cannot offer RC4, 3DES, DES or EXPORT suites, so these probes
 * run an out-of-process legacy OpenSSL client (bin/openssl-legacy, or RUYA_OPENSSL_LEGACY_BIN if absolute).
 *  - Same egress rules as tlsHandshake: onHop (scope guard) first, then a validated, pinned public address.
 *    The client connects to that address, never re-resolving the name.
 *  - One handshake per family, offering only that family; stdin is closed at once, so no application data is sent.
 *  - If the binary is missing, or it cannot offer a family, that family is "untestable", never "refused".
 *  - The 1.0.2 client is IPv4-only, so it connects to a validated IPv4 address; a host with none is "untestable".
 *  - A timeout or a connection error throws, so the check fails closed.
 */

export const LEGACY_FAMILIES = ["RC4", "3DES", "DES", "EXPORT"] as const;
export type LegacyFamily = (typeof LEGACY_FAMILIES)[number];
const FAMILY_CIPHERS: Record<LegacyFamily, string> = { RC4: "RC4", "3DES": "3DES", DES: "DES:!3DES", EXPORT: "EXPORT" };

export type LegacyResult =
  | { outcome: "accepted"; protocol: string | null; cipher: string; pinnedAddress: string }
  | { outcome: "refused"; code: string; pinnedAddress: string }
  | { outcome: "untestable"; code: string };

export interface ExecResult { code: number | null; stdout: string; stderr: string; timedOut: boolean }
export type LegacyExec = (args: string[], timeoutMs: number) => Promise<ExecResult>;

export function legacyOpensslPath(): string {
  const env = process.env.RUYA_OPENSSL_LEGACY_BIN;
  return env && path.isAbsolute(env) ? env : path.join(process.cwd(), "bin", "openssl-legacy");
}

export const defaultLegacyExec: LegacyExec = (args, timeoutMs) => new Promise((resolve) => {
  const bin = legacyOpensslPath();
  if (!existsSync(bin)) return resolve({ code: 127, stdout: "", stderr: "legacy_openssl_unavailable", timedOut: false });
  const child = execFile(bin, args, {
    timeout: timeoutMs, killSignal: "SIGKILL", maxBuffer: 256 * 1024, windowsHide: true,
    env: { PATH: "/usr/bin:/bin", OPENSSL_CONF: "/dev/null", RANDFILE: "/dev/urandom", NODE_ENV: "production" },
  }, (err, stdout, stderr) => {
    const e = err as (NodeJS.ErrnoException & { killed?: boolean; code?: number | string }) | null;
    resolve({ code: e ? (typeof e.code === "number" ? e.code : 1) : 0, stdout: String(stdout), stderr: String(stderr), timedOut: !!e?.killed });
  });
  child.stdin?.end();
});

/** What the local legacy build can offer: its version and the families it has suites for (cached per process). */
let caps: Promise<{ seclevel: boolean; families: Set<LegacyFamily> }> | null = null;
export function resetLegacyCaps() { caps = null; }
async function capabilities(exec: LegacyExec) {
  const v = await exec(["version"], 5000);
  if (v.code !== 0) return { seclevel: false, families: new Set<LegacyFamily>() };
  // OpenSSL 1.1+ needs @SECLEVEL=0 to offer these suites; 1.0.2 does not know the keyword.
  const seclevel = !/^OpenSSL 1\.0\./.test(v.stdout.trim());
  const families = new Set<LegacyFamily>();
  for (const f of LEGACY_FAMILIES) {
    const r = await exec(["ciphers", cipherString(f, seclevel)], 5000);
    if (r.code === 0 && r.stdout.trim()) families.add(f);
  }
  return { seclevel, families };
}
const cipherString = (f: LegacyFamily, seclevel: boolean) => FAMILY_CIPHERS[f] + (seclevel ? ":@SECLEVEL=0" : "");

const CONNECT_FAILED = /connect:errno|Connection refused|No route to host|Network is unreachable|gethostbyname|getaddrinfo/i;
const SERVER_REFUSED = /alert|handshake failure|wrong version number|no ciphers available|unexpected eof|unexpected_eof|errno=104|Connection reset|write:errno|read:errno/i;

/** Parses `openssl s_client` output into a verdict; null when the output fits neither a handshake nor a refusal. */
export function parseSClient(stdout: string, stderr: string): { cipher: string; protocol: string | null } | "refused" | "connect_failed" | null {
  const cipher = /^\s*Cipher\s*:\s*(\S+)/m.exec(stdout)?.[1] ?? /Cipher is (\S+)/.exec(stdout)?.[1];
  if (cipher && cipher !== "(NONE)" && cipher !== "0000") {
    return { cipher, protocol: /^\s*Protocol\s*:\s*(\S+)/m.exec(stdout)?.[1] ?? null };
  }
  if (CONNECT_FAILED.test(stderr)) return "connect_failed";
  if (SERVER_REFUSED.test(stderr) || /CONNECTED\(/.test(stdout)) return "refused";
  return null;
}

export async function legacyCipherProbe(
  host: string, family: LegacyFamily, deps: EgressDeps & { port?: number } = {}, exec: LegacyExec = defaultLegacyExec,
): Promise<LegacyResult> {
  const allowPrivate = !!deps.allowPrivate && process.env.NODE_ENV !== "production";
  if (isIpLiteral(host) && !allowPrivate) throw new EgressError("egress_blocked", "IP literal destinations are not allowed");
  if (deps.port && deps.port !== 443 && !allowPrivate) throw new EgressError("bad_url", "Only the default port is allowed");
  caps ??= capabilities(exec);
  const c = await caps;
  // Only a working build is cached, so installing the binary takes effect without restarting the worker.
  if (!c.families.size) caps = null;
  if (!c.families.has(family)) return { outcome: "untestable", code: c.families.size ? "client_lacks_family" : "legacy_openssl_unavailable" };

  await deps.onHop?.(new URL(`https://${host}${deps.port && deps.port !== 443 ? `:${deps.port}` : ""}/`));
  const pinned = await resolvePublic(host, deps, 4);
  if (!pinned) return { outcome: "untestable", code: "client_ipv4_only" };
  const port = devPort(deps.port ?? 443, pinned.address, allowPrivate);
  const args = ["s_client", "-connect", `${pinned.address}:${port}`, "-cipher", cipherString(family, c.seclevel), ...(isIpLiteral(host) ? [] : ["-servername", host])];
  const r = await exec(args, deps.timeoutMs ?? 8000);
  if (r.timedOut) throw new EgressError("timeout", "legacy TLS handshake timed out");
  const v = parseSClient(r.stdout, r.stderr);
  if (v === "connect_failed" || v === null) throw new EgressError("network", (r.stderr.split("\n").find((l) => l.trim()) ?? "legacy client failed").slice(0, 200));
  if (v === "refused") return { outcome: "refused", code: (r.stderr.match(SERVER_REFUSED)?.[0] ?? "no handshake").slice(0, 120), pinnedAddress: pinned.address };
  return { outcome: "accepted", ...v, pinnedAddress: pinned.address };
}
