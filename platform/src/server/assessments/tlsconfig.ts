import { EgressError, tlsHandshake, type HandshakeOptions, type HandshakeResult } from "../net/egress";
import { LEGACY_FAMILIES, legacyCipherProbe, type LegacyFamily, type LegacyResult } from "../net/legacytls";
import type { CheckAdapter, CheckContext, CheckResult, FindingCandidate } from "./checks";

/**
 * tls.config (scanner M6, class A1): how the server's TLS is configured, from a handful of plain handshakes.
 *  - One default handshake (baseline), then one handshake pinned to each of TLS 1.0, 1.1, 1.2 and 1.3, then one
 *    TLS 1.2 handshake offering only weak cipher suites. No HTTP request is sent and nothing is exploited.
 *  - Fails closed: if the baseline handshake fails, or any probe times out or errors unexpectedly, the check
 *    reports an error instead of "configuration is fine".
 *  - A probe this client cannot offer (the local OpenSSL build lacks it) is recorded as "untestable" in the
 *    evidence and never turned into a "not supported" verdict.
 *  - RC4, 3DES, DES and EXPORT are probed one family at a time by an out-of-process legacy OpenSSL client (net/legacytls),
 *    under the same scope guard and address pinning. Without that binary those families stay "untestable".
 *  - Fingerprint = host:443 + issue key, so fixing the setting and re-testing resolves exactly that finding.
 */

/** Weak suites Node's OpenSSL 3 can ask for. RC4, 3DES, DES and EXPORT are absent from it; the legacy client probes those. */
export const WEAK_CIPHERS = "NULL:aNULL:RC4:3DES:DES:EXPORT:@SECLEVEL=0";
const LEGACY = "DEFAULT:@SECLEVEL=0";
/** Names that are weak whenever a server negotiates them, whatever probe it came from. */
const WEAK_NAME = /(^|[-_])(NULL|RC4|DES|3DES|DES-CBC3|EXP|EXPORT|ADH|AECDH|anon)([-_]|$)/i;
/** Chain errors that mean intermediates are missing (as opposed to an untrusted root or a name mismatch). */
const CHAIN_ERRORS = new Set(["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "UNABLE_TO_GET_ISSUER_CERT", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"]);

export type Handshake = (host: string, opts: HandshakeOptions, ctx: CheckContext) => Promise<HandshakeResult>;
const defaultHandshake: Handshake = (host, opts, ctx) => tlsHandshake(host, opts, { ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 8000) });
export type LegacyProbe = (host: string, family: LegacyFamily, ctx: CheckContext) => Promise<LegacyResult>;
const defaultLegacy: LegacyProbe = (host, family, ctx) => legacyCipherProbe(host, family, { ...ctx.egress, onHop: ctx.onHop, timeoutMs: Math.min(ctx.timeoutMs, 8000) });

type ProbeState = "accepted" | "refused" | "untestable";
const state = (r: HandshakeResult): ProbeState => r.outcome;

export const TLS_REMEDIATION = {
  tls10_enabled: "Disable TLS 1.0 on this server or load balancer and allow only TLS 1.2 and 1.3. For nginx: ssl_protocols TLSv1.2 TLSv1.3; for Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3. Cloud load balancers and CDNs have a minimum-TLS-version or security-policy setting.",
  tls11_enabled: "Disable TLS 1.1 and allow only TLS 1.2 and 1.3 (nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3; or raise the minimum TLS version in your CDN / load balancer policy).",
  weak_cipher: "Remove NULL, anonymous, RC4, 3DES, DES and EXPORT cipher suites. Use a modern cipher list such as Mozilla's \"intermediate\" profile (ECDHE with AES-GCM or ChaCha20-Poly1305) and restart the TLS terminator.",
  weak_rsa_key: "Replace the certificate with one using an RSA key of at least 2048 bits (3072 recommended) or an ECDSA P-256 key. Generate a new private key: do not reuse the weak one.",
  incomplete_chain: "Serve the full certificate chain: your certificate followed by the CA's intermediate certificate(s). Most CAs provide a 'fullchain' file (e.g. Let's Encrypt fullchain.pem); point ssl_certificate / SSLCertificateFile at it.",
  no_tls13: "Enable TLS 1.3 alongside TLS 1.2 (nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache 2.4.37+ with OpenSSL 1.1.1+). It is faster and removes legacy cipher choices.",
} as const;

export function createTlsConfigAdapter(handshake: Handshake = defaultHandshake, legacy: LegacyProbe = defaultLegacy): CheckAdapter {
  return {
    id: "tls.config@1", checkKey: "tls.config", target: "host",
    async run(ctx): Promise<CheckResult> {
      const loc = `${ctx.host}:443`;
      let base: HandshakeResult;
      const probes: Record<string, HandshakeResult> = {};
      const legacyProbes: Partial<Record<LegacyFamily, LegacyResult>> = {};
      try {
        base = await handshake(ctx.host, {}, ctx);
        if (base.outcome !== "accepted") return { status: "error", reason: "baseline_handshake_failed", evidence: { outcome: base.outcome, code: base.code } };
        probes["TLSv1"] = await handshake(ctx.host, { minVersion: "TLSv1", maxVersion: "TLSv1", ciphers: LEGACY }, ctx);
        probes["TLSv1.1"] = await handshake(ctx.host, { minVersion: "TLSv1.1", maxVersion: "TLSv1.1", ciphers: LEGACY }, ctx);
        probes["TLSv1.2"] = await handshake(ctx.host, { minVersion: "TLSv1.2", maxVersion: "TLSv1.2" }, ctx);
        probes["TLSv1.3"] = await handshake(ctx.host, { minVersion: "TLSv1.3", maxVersion: "TLSv1.3" }, ctx);
        probes.weak = await handshake(ctx.host, { minVersion: "TLSv1", maxVersion: "TLSv1.2", ciphers: WEAK_CIPHERS }, ctx);
        for (const f of LEGACY_FAMILIES) legacyProbes[f] = await legacy(ctx.host, f, ctx);
      } catch (e) {
        if (e instanceof EgressError) return { status: "error", reason: e.code === "network" ? "host_unreachable" : e.code, evidence: { error: e.message.slice(0, 200), completed: [...Object.keys(probes), ...Object.keys(legacyProbes).map((f) => `legacy:${f}`)] } };
        throw e;
      }

      const protocols = Object.fromEntries(["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"].map((v) => [v, state(probes[v])]));
      // A pinned handshake that "succeeded" on another protocol means the pin did not hold: treat as untestable.
      for (const v of ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]) {
        const p = probes[v];
        if (p.outcome === "accepted" && p.protocol && p.protocol !== v) protocols[v] = "untestable";
      }
      const negotiated = [...Object.values(probes), ...Object.values(legacyProbes)].flatMap((p) => (p.outcome === "accepted" ? [p.cipher] : []));
      const weakSeen = [...new Set([base.cipher, ...negotiated].filter((c) => WEAK_NAME.test(c)))];
      const evidence = {
        address: base.pinnedAddress, protocol: base.protocol, cipher: base.cipher, keyType: base.keyType, keyBits: base.keyBits,
        chain: base.authorizationError && CHAIN_ERRORS.has(base.authorizationError) ? "incomplete" : base.authorizationError ? "untrusted" : "complete",
        protocols, weakCipherProbe: state(probes.weak),
        legacyProbes: Object.fromEntries(LEGACY_FAMILIES.map((f) => {
          const p = legacyProbes[f]!;
          return [f, p.outcome === "accepted" ? { outcome: p.outcome, cipher: p.cipher, protocol: p.protocol } : { outcome: p.outcome, code: p.code }];
        })),
        // Families the legacy client could not offer stay "untestable": never read as "server refuses them".
        weakCipherCoverage: {
          probed: ["NULL", "anonymous", ...LEGACY_FAMILIES.filter((f) => legacyProbes[f]!.outcome !== "untestable")],
          untestable: LEGACY_FAMILIES.filter((f) => legacyProbes[f]!.outcome === "untestable"),
        },
      };

      const out: FindingCandidate[] = [];
      const add = (issueKey: keyof typeof TLS_REMEDIATION, title: string, severity: FindingCandidate["severity"], ev: Record<string, unknown>) =>
        out.push({ issueKey, title, severity, location: loc, evidence: ev, remediation: TLS_REMEDIATION[issueKey] });
      if (protocols["TLSv1"] === "accepted") add("tls10_enabled", "TLS 1.0 is still accepted", "medium", { protocol: "TLSv1", cipher: (probes["TLSv1"] as { cipher: string }).cipher });
      if (protocols["TLSv1.1"] === "accepted") add("tls11_enabled", "TLS 1.1 is still accepted", "medium", { protocol: "TLSv1.1", cipher: (probes["TLSv1.1"] as { cipher: string }).cipher });
      if (weakSeen.length) add("weak_cipher", "Server negotiates a weak cipher suite", "medium", { ciphers: weakSeen });
      if (base.keyType === "RSA" && base.keyBits !== null && base.keyBits < 2048) add("weak_rsa_key", `Certificate uses a ${base.keyBits}-bit RSA key`, "high", { keyType: "RSA", keyBits: base.keyBits });
      if (evidence.chain === "incomplete") add("incomplete_chain", "Certificate chain is incomplete (intermediate missing)", "low", { error: base.authorizationError });
      if (protocols["TLSv1.3"] === "refused") add("no_tls13", "TLS 1.3 is not supported", "info", { protocols });
      return { status: "ok", findings: out, evidence };
    },
  };
}
