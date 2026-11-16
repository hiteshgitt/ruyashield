import { describe, expect, it } from "vitest";
import { normalizeResult, type CheckContext } from "@/server/assessments/checks";
import { createTlsConfigAdapter, WEAK_CIPHERS, type Handshake, type LegacyProbe } from "@/server/assessments/tlsconfig";
import { EgressError, type HandshakeResult } from "@/server/net/egress";
import type { LegacyFamily, LegacyResult } from "@/server/net/legacytls";

const ctx = { host: "shop.example.com", timeoutMs: 30000, egress: {}, onHop: () => {} } as unknown as CheckContext;
const A = "203.0.113.10";
const ok = (protocol: string, cipher = "ECDHE-RSA-AES128-GCM-SHA256", extra: Partial<HandshakeResult> = {}): HandshakeResult =>
  ({ outcome: "accepted", protocol, cipher, keyBits: 2048, keyType: "RSA", authorizationError: null, pinnedAddress: A, ...extra } as HandshakeResult);
const refused: HandshakeResult = { outcome: "refused", code: "alert 70", pinnedAddress: A };
const untestable: HandshakeResult = { outcome: "untestable", code: "no cipher match", pinnedAddress: A };

/** Recorded server behaviour keyed by probe: base, TLSv1 … TLSv1.3, weak. */
type Server = Partial<Record<"base" | "TLSv1" | "TLSv1.1" | "TLSv1.2" | "TLSv1.3" | "weak", HandshakeResult | Error>>;
const modern: Server = { base: ok("TLSv1.3", "TLS_AES_256_GCM_SHA384"), TLSv1: refused, "TLSv1.1": refused, "TLSv1.2": ok("TLSv1.2"), "TLSv1.3": ok("TLSv1.3", "TLS_AES_256_GCM_SHA384"), weak: refused };
function fake(server: Server, calls: unknown[] = []): Handshake {
  return async (_h, opts) => {
    calls.push(opts);
    const key = opts.ciphers === WEAK_CIPHERS ? "weak" : opts.minVersion ?? "base";
    const r = server[key as keyof Server] ?? refused;
    if (r instanceof Error) throw r;
    return r;
  };
}
/** Legacy client stand-in; by default the binary is absent, so every family is untestable. */
type Legacy = Partial<Record<LegacyFamily, LegacyResult | Error>>;
const noBinary: LegacyResult = { outcome: "untestable", code: "legacy_openssl_unavailable" };
const lRefused: LegacyResult = { outcome: "refused", code: "handshake failure", pinnedAddress: A };
function fakeLegacy(server: Legacy = {}, calls: string[] = []): LegacyProbe {
  return async (_h, family) => {
    calls.push(family);
    const r = server[family] ?? noBinary;
    if (r instanceof Error) throw r;
    return r;
  };
}
const allRefused: Legacy = { RC4: lRefused, "3DES": lRefused, DES: lRefused, EXPORT: lRefused };
const run = async (s: Server, l: Legacy = {}) => normalizeResult(await createTlsConfigAdapter(fake(s), fakeLegacy(l)).run(ctx));
const keys = (r: Awaited<ReturnType<typeof run>>) => (r.status === "ok" ? r.findings.map((f) => [f.issueKey, f.severity]) : r.status);

describe("tls.config adapter", () => {
  it("reports nothing for a modern server and records the probe matrix", async () => {
    const calls: unknown[] = [], lcalls: string[] = [];
    const r = normalizeResult(await createTlsConfigAdapter(fake(modern, calls), fakeLegacy({}, lcalls)).run(ctx));
    expect(r).toMatchObject({ status: "ok", findings: [], evidence: {
      address: A, chain: "complete", keyBits: 2048, weakCipherProbe: "refused",
      protocols: { TLSv1: "refused", "TLSv1.1": "refused", "TLSv1.2": "accepted", "TLSv1.3": "accepted" },
      weakCipherCoverage: { probed: ["NULL", "anonymous"], untestable: ["RC4", "3DES", "DES", "EXPORT"] },
      legacyProbes: { RC4: { outcome: "untestable" } },
    } });
    expect(calls).toHaveLength(6);
    expect(lcalls).toEqual(["RC4", "3DES", "DES", "EXPORT"]);
  });

  it("flags legacy protocols, weak ciphers, a small RSA key, a missing intermediate and no TLS 1.3", async () => {
    const r = await run({
      base: ok("TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", { keyBits: 1024, authorizationError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" }),
      TLSv1: ok("TLSv1", "ECDHE-RSA-AES128-SHA"), "TLSv1.1": ok("TLSv1.1", "ECDHE-RSA-AES128-SHA"), "TLSv1.2": ok("TLSv1.2"),
      "TLSv1.3": refused, weak: ok("TLSv1.2", "AECDH-AES128-SHA"),
    });
    expect(keys(r)).toEqual([
      ["tls10_enabled", "medium"], ["tls11_enabled", "medium"], ["weak_cipher", "medium"],
      ["weak_rsa_key", "high"], ["incomplete_chain", "low"], ["no_tls13", "info"],
    ]);
    if (r.status !== "ok") return;
    expect(r.findings.every((f) => f.location === "shop.example.com:443" && f.remediation.length > 40)).toBe(true);
    expect(r.findings.find((f) => f.issueKey === "weak_cipher")!.evidence).toEqual({ ciphers: ["AECDH-AES128-SHA"] });
  });

  it("probes RC4, 3DES, DES and EXPORT with the legacy client and moves them into coverage", async () => {
    const r = await run(modern, allRefused);
    expect(r).toMatchObject({ status: "ok", findings: [], evidence: {
      weakCipherCoverage: { probed: ["NULL", "anonymous", "RC4", "3DES", "DES", "EXPORT"], untestable: [] },
      legacyProbes: { RC4: { outcome: "refused", code: "handshake failure" } },
    } });
  });

  it("reports weak legacy suites the server accepts, and keeps a family the client lacks untestable", async () => {
    const r = await run(modern, { ...allRefused,
      RC4: { outcome: "accepted", protocol: "TLSv1.2", cipher: "RC4-SHA", pinnedAddress: A },
      "3DES": { outcome: "accepted", protocol: "TLSv1.2", cipher: "DES-CBC3-SHA", pinnedAddress: A },
      EXPORT: { outcome: "untestable", code: "client_lacks_family" } });
    expect(keys(r)).toEqual([["weak_cipher", "medium"]]);
    if (r.status !== "ok") return;
    expect(r.findings[0].evidence).toEqual({ ciphers: ["RC4-SHA", "DES-CBC3-SHA"] });
    expect(r.evidence).toMatchObject({ weakCipherCoverage: { probed: ["NULL", "anonymous", "RC4", "3DES", "DES"], untestable: ["EXPORT"] } });
  });

  it("fails closed when a legacy probe times out or cannot reach the host", async () => {
    expect(await run(modern, { ...allRefused, DES: new EgressError("timeout", "legacy TLS handshake timed out") }))
      .toMatchObject({ status: "error", reason: "timeout", evidence: { completed: expect.arrayContaining(["weak", "legacy:RC4", "legacy:3DES"]) } });
    expect(await run(modern, { RC4: new EgressError("network", "connect:errno=111") })).toMatchObject({ status: "error", reason: "host_unreachable" });
  });

  it("does not turn untestable probes into verdicts", async () => {
    const r = await run({ ...modern, TLSv1: untestable, "TLSv1.1": untestable, "TLSv1.3": untestable, weak: untestable });
    expect(r).toMatchObject({ status: "ok", findings: [], evidence: { weakCipherProbe: "untestable", protocols: { TLSv1: "untestable", "TLSv1.3": "untestable" } } });
  });

  it("treats a pinned probe answered on another protocol as untestable", async () => {
    const r = await run({ ...modern, TLSv1: ok("TLSv1.2") });
    expect(r).toMatchObject({ status: "ok", findings: [], evidence: { protocols: { TLSv1: "untestable" } } });
  });

  it("ignores an untrusted root or name mismatch (that is not a chain gap) and EC keys", async () => {
    const r = await run({ ...modern, base: ok("TLSv1.3", "TLS_AES_256_GCM_SHA384", { keyType: "EC", keyBits: 256, authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT" }) });
    expect(r).toMatchObject({ status: "ok", findings: [], evidence: { chain: "untrusted", keyType: "EC" } });
  });

  it("fails closed when the baseline handshake or any probe fails", async () => {
    expect(await run({ ...modern, base: refused })).toMatchObject({ status: "error", reason: "baseline_handshake_failed" });
    expect(await run({ ...modern, "TLSv1.2": new EgressError("timeout", "Timed out") })).toMatchObject({ status: "error", reason: "timeout", evidence: { completed: ["TLSv1", "TLSv1.1"] } });
    expect(await run({ ...modern, base: new EgressError("network", "ECONNREFUSED") })).toMatchObject({ status: "error", reason: "host_unreachable" });
    expect(await run({ ...modern, base: new EgressError("egress_blocked", "private") })).toMatchObject({ status: "error", reason: "egress_blocked" });
  });
});
