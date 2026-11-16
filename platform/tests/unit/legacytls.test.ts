import { beforeEach, describe, expect, it } from "vitest";
import { legacyCipherProbe, parseSClient, resetLegacyCaps, type ExecResult, type LegacyExec } from "@/server/net/legacytls";

const A = "93.184.215.14";
const deps = (hops: string[] = []) => ({ onHop: (u: URL) => { hops.push(u.href); }, resolve: async () => [{ address: A, family: 4 as const }] });
const res = (stdout = "", stderr = "", code = 0, timedOut = false): ExecResult => ({ code, stdout, stderr, timedOut });

const ACCEPTED = `CONNECTED(00000003)\n---\nNew, TLSv1/SSLv3, Cipher is RC4-SHA\nSSL-Session:\n    Protocol  : TLSv1.2\n    Cipher    : RC4-SHA\n    Session-ID: \n`;
const REFUSED_ERR = "140735:error:14077410:SSL routines:SSL23_GET_SERVER_HELLO:sslv3 alert handshake failure:s23_clnt.c:769:\n";

/** Fake legacy openssl: OpenSSL 1.0.2 with every family, and a scripted s_client answer. */
function fakeExec(sclient: ExecResult, opts: { version?: ExecResult; lacks?: string[] } = {}) {
  const calls: string[][] = [];
  const exec: LegacyExec = async (args) => {
    calls.push(args);
    if (args[0] === "version") return opts.version ?? res("OpenSSL 1.0.2u  20 Dec 2019\n");
    if (args[0] === "ciphers") return opts.lacks?.includes(args[1]) ? res("", "Error in cipher list", 1) : res("RC4-SHA:DES-CBC3-SHA\n");
    return sclient;
  };
  return { exec, calls };
}

describe("parseSClient", () => {
  it("reads an accepted handshake from the SSL-Session block", () => {
    expect(parseSClient(ACCEPTED, "")).toEqual({ cipher: "RC4-SHA", protocol: "TLSv1.2" });
  });
  it("treats an alert, or CONNECTED with no cipher, as refused", () => {
    expect(parseSClient("CONNECTED(00000003)\n", REFUSED_ERR)).toBe("refused");
    expect(parseSClient("CONNECTED(00000003)\n---\nNew, (NONE), Cipher is (NONE)\n    Cipher    : 0000\n", "")).toBe("refused");
  });
  it("separates connection failures from unknown output", () => {
    expect(parseSClient("", "connect: Connection refused\nconnect:errno=111\n")).toBe("connect_failed");
    expect(parseSClient("", "something odd")).toBeNull();
  });
});

describe("legacyCipherProbe", () => {
  beforeEach(() => resetLegacyCaps());

  it("runs the scope guard, connects to the pinned address and offers only the family (no SECLEVEL on 1.0.2)", async () => {
    const hops: string[] = [], f = fakeExec(res(ACCEPTED));
    expect(await legacyCipherProbe("shop.example.com", "RC4", deps(hops), f.exec))
      .toEqual({ outcome: "accepted", cipher: "RC4-SHA", protocol: "TLSv1.2", pinnedAddress: A });
    expect(hops).toEqual(["https://shop.example.com/"]);
    expect(f.calls.at(-1)).toEqual(["s_client", "-connect", `${A}:443`, "-cipher", "RC4", "-servername", "shop.example.com"]);
  });

  it("adds @SECLEVEL=0 on OpenSSL 1.1+ and excludes 3DES from the DES probe", async () => {
    const f = fakeExec(res("CONNECTED(00000003)\n", REFUSED_ERR, 1), { version: res("OpenSSL 1.1.1w  11 Sep 2023\n") });
    expect(await legacyCipherProbe("shop.example.com", "DES", deps(), f.exec)).toMatchObject({ outcome: "refused", code: "alert" });
    expect(f.calls.at(-1)).toContain("DES:!3DES:@SECLEVEL=0");
  });

  it("is untestable, without touching the network, when the binary is missing or lacks the family", async () => {
    const hops: string[] = [];
    const missing = fakeExec(res(ACCEPTED), { version: res("", "legacy_openssl_unavailable", 127) });
    expect(await legacyCipherProbe("shop.example.com", "RC4", deps(hops), missing.exec)).toEqual({ outcome: "untestable", code: "legacy_openssl_unavailable" });
    resetLegacyCaps();
    const lacks = fakeExec(res(ACCEPTED), { lacks: ["EXPORT"] });
    expect(await legacyCipherProbe("shop.example.com", "EXPORT", deps(hops), lacks.exec)).toEqual({ outcome: "untestable", code: "client_lacks_family" });
    expect(hops).toEqual([]);
    expect([...missing.calls, ...lacks.calls].some((c) => c[0] === "s_client")).toBe(false);
  });

  it("fails closed on timeout, connection errors and unrecognised output", async () => {
    await expect(legacyCipherProbe("shop.example.com", "RC4", deps(), fakeExec(res("", "", null as unknown as number, true)).exec)).rejects.toMatchObject({ code: "timeout" });
    await expect(legacyCipherProbe("shop.example.com", "RC4", deps(), fakeExec(res("", "connect:errno=111\n", 1)).exec)).rejects.toMatchObject({ code: "network" });
    await expect(legacyCipherProbe("shop.example.com", "RC4", deps(), fakeExec(res("", "weird", 1)).exec)).rejects.toMatchObject({ code: "network" });
  });

  it("refuses IP literals, other ports and hosts the scope guard rejects", async () => {
    const f = fakeExec(res(ACCEPTED));
    await expect(legacyCipherProbe("203.0.113.10", "RC4", deps(), f.exec)).rejects.toMatchObject({ code: "egress_blocked" });
    await expect(legacyCipherProbe("shop.example.com", "RC4", { ...deps(), port: 8443 }, f.exec)).rejects.toMatchObject({ code: "bad_url" });
    const guard = { ...deps(), onHop: () => { throw new Error("out_of_scope"); } };
    await expect(legacyCipherProbe("shop.example.com", "RC4", guard, f.exec)).rejects.toThrow("out_of_scope");
    expect(f.calls.some((c) => c[0] === "s_client")).toBe(false);
  });

  it("connects to a validated IPv4 address (the 1.0.2 client is IPv4-only); an IPv6-only host is untestable", async () => {
    const V6 = "2606:2800:21f:cb07::1";
    const dual = fakeExec(res(ACCEPTED));
    await legacyCipherProbe("shop.example.com", "RC4", { resolve: async () => [{ address: V6, family: 6 as const }, { address: A, family: 4 as const }] }, dual.exec);
    expect(dual.calls.at(-1)?.[2]).toBe(`${A}:443`);
    const only6 = fakeExec(res(ACCEPTED));
    expect(await legacyCipherProbe("shop.example.com", "RC4", { resolve: async () => [{ address: V6, family: 6 as const }] }, only6.exec))
      .toEqual({ outcome: "untestable", code: "client_ipv4_only" });
    expect(only6.calls.some((c) => c[0] === "s_client")).toBe(false);
    // Every address is still validated, including the IPv6 one that is not used.
    await expect(legacyCipherProbe("shop.example.com", "RC4", { resolve: async () => [{ address: "fd00::1", family: 6 as const }, { address: A, family: 4 as const }] }, dual.exec))
      .rejects.toMatchObject({ code: "egress_blocked" });
  });

  it("refuses a name that resolves to a private address", async () => {
    const f = fakeExec(res(ACCEPTED));
    await expect(legacyCipherProbe("shop.example.com", "RC4", { resolve: async () => [{ address: "10.0.0.5", family: 4 as const }] }, f.exec))
      .rejects.toMatchObject({ code: "egress_blocked" });
  });
});
