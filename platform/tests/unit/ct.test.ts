import { describe, expect, it } from "vitest";
import { normalizeResult, type CheckContext } from "@/server/assessments/checks";
import {
  allowedFor, CACHE_TTL_MS, caOf, createCtAdapter, ctFindings, parseCaa, parseCertSpotter, parseCrtSh, suggestedHosts,
  type CtCache, type CtCacheRow, type CtEntry,
} from "@/server/assessments/ct";
import type { FetchLike } from "@/server/assessments/deps";

// Recorded shape of a crt.sh JSON answer (trimmed). Row 2 and 3 are the precertificate and certificate of one serial.
const CRTSH = [
  { issuer_ca_id: 295815, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: "example.com", name_value: "example.com\nwww.example.com", id: 1001, entry_timestamp: "2026-10-01T10:00:00.123", not_before: "2026-10-01T09:00:00", not_after: "2026-12-30T09:00:00", serial_number: "04aa" },
  { issuer_ca_id: 295815, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: "*.example.com", name_value: "*.example.com\nexample.com", id: 1002, entry_timestamp: "2026-10-02T10:00:00", not_before: "2026-10-02T09:00:00", not_after: "2026-12-31T09:00:00", serial_number: "04bb" },
  { issuer_ca_id: 295815, issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: "*.example.com", name_value: "*.example.com\nexample.com", id: 1003, entry_timestamp: "2026-10-02T10:00:01", not_before: "2026-10-02T09:00:00", not_after: "2026-12-31T09:00:00", serial_number: "04bb" },
  { issuer_ca_id: 1, issuer_name: "C=US, O=DigiCert Inc, CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1", common_name: "shop.example.com", name_value: "shop.example.com\napi.example.com", id: 1004, entry_timestamp: "2026-09-01T00:00:00", not_before: "2026-09-01T00:00:00", not_after: "2027-09-01T00:00:00", serial_number: "0dd1" },
  { issuer_ca_id: 2, issuer_name: "C=XX, O=Tiny Private CA", common_name: "legacy.example.com", name_value: "legacy.example.com", id: 1005, entry_timestamp: "2026-09-01T00:00:00", not_before: "2026-09-01T00:00:00", not_after: "2027-09-01T00:00:00", serial_number: "0ee1" },
  { issuer_ca_id: 3, issuer_name: "C=US, O=DigiCert Inc, CN=Old CA", common_name: "old.example.com", name_value: "old.example.com\nevil.com\nEXAMPLE.COM.attacker.net", id: 1006, entry_timestamp: "2020-01-01T00:00:00", not_before: "2020-01-01T00:00:00", not_after: "2021-01-01T00:00:00", serial_number: "0ff1" },
];
// Recorded shape of a Cert Spotter /v1/issuances answer (expand=dns_names,issuer).
const CERTSPOTTER = [
  { id: "9001", tbs_sha256: "aa", cert_sha256: "bb", dns_names: ["example.com", "mail.example.com"], pubkey_sha256: "cc", issuer: { friendly_name: "Let's Encrypt", caa_domains: ["letsencrypt.org"], name: "C=US, O=Let's Encrypt, CN=R10" }, not_before: "2026-10-05T00:00:00Z", not_after: "2027-01-03T00:00:00Z", revoked: false },
  { id: "9002", dns_names: ["vpn.example.com"], issuer: { friendly_name: "Odd CA", caa_domains: ["odd-ca.example"], name: "CN=Odd" }, not_before: "2026-10-05T00:00:00Z", not_after: "2027-01-03T00:00:00Z" },
];

const NOW = new Date("2026-11-09T12:00:00Z");
const HOST = "example.com";

function ctx(caa: string[] | Error = ["0 issue \"letsencrypt.org\""]): CheckContext {
  const resolve = async (name: string) => {
    if (caa instanceof Error) throw caa;
    return name === HOST ? caa : [];
  };
  return { host: HOST, onHop: () => {}, egress: {}, dns: { resolve }, timeoutMs: 60000, now: () => NOW, sleep: async () => {} } as unknown as CheckContext;
}

type Reply = { status?: number; body?: unknown; raw?: string; throws?: boolean };
function fakeFetch(routes: Record<string, Reply | Reply[]>) {
  const calls: string[] = [];
  const fn: FetchLike = async (url) => {
    calls.push(url);
    const host = new URL(url).host;
    const r = routes[host];
    const reply = Array.isArray(r) ? r.shift() : r;
    if (!reply || reply.throws) throw new Error("ECONNRESET");
    const status = reply.status ?? 200;
    return { ok: status >= 200 && status < 300, status, text: async () => reply.raw ?? JSON.stringify(reply.body) };
  };
  return { fn, calls };
}

function memCache(seed?: [string, CtCacheRow]) {
  const m = new Map<string, CtCacheRow>(seed ? [seed] : []);
  const cache: CtCache = { get: async (d) => m.get(d) ?? null, put: async (d, r) => { m.set(d, r); } };
  return { cache, m };
}

const adapter = (f: FetchLike, cache = memCache().cache) => createCtAdapter({ fetch: f, cache, minSpacingMs: 0 });

describe("CT parsing", () => {
  it("parses crt.sh, merges precertificate and certificate, and normalizes names and dates", () => {
    const e = parseCrtSh(CRTSH);
    expect(e).toHaveLength(5);
    expect(e[0]).toEqual({ id: "1001", issuer: "C=US, O=Let's Encrypt, CN=R11", names: ["example.com", "www.example.com"], notBefore: "2026-10-01T09:00:00.000Z", notAfter: "2026-12-30T09:00:00.000Z" });
    expect(e[1].names).toEqual(["*.example.com", "example.com"]);
  });

  it("parses Cert Spotter including the CA's CAA domains", () => {
    const e = parseCertSpotter(CERTSPOTTER);
    expect(e[1]).toMatchObject({ id: "9002", issuer: "Odd CA", caaDomains: ["odd-ca.example"], names: ["vpn.example.com"] });
  });

  it("rejects malformed answers instead of returning nothing", () => {
    expect(() => parseCrtSh({ error: "x" })).toThrow("crtsh_malformed_response");
    expect(() => parseCrtSh([{ id: 1, issuer_name: "x" }])).toThrow("crtsh_malformed_response");
    expect(() => parseCertSpotter([{ id: "1" }])).toThrow("certspotter_malformed_response");
  });

  it("maps issuers to CAA identifiers", () => {
    expect(caOf({ issuer: "C=US, O=Let's Encrypt, CN=E6" })?.key).toBe("letsencrypt");
    expect(caOf({ issuer: "CN=ZeroSSL RSA Domain Secure Site CA, O=ZeroSSL" })?.key).toBe("zerossl");
    expect(caOf({ issuer: "C=US, O=Google Trust Services, CN=WR1" })?.caa).toContain("pki.goog");
    expect(caOf({ issuer: "Odd CA", caaDomains: ["Odd-CA.example"] })).toMatchObject({ key: "odd-ca.example", caa: ["odd-ca.example"] });
    expect(caOf({ issuer: "C=XX, O=Tiny Private CA" })).toBeNull();
  });

  it("parses CAA: absent tags are unrestricted, issuewild falls back to issue", () => {
    const p = parseCaa(HOST, ["0 issue \"letsencrypt.org\"", "0 issue \"digicert.com; cansignhttpexchanges=yes\"", "0 iodef \"mailto:x@example.com\""]);
    expect(p.issue).toEqual(["letsencrypt.org", "digicert.com"]);
    expect(p.issuewild).toBeNull();
    expect(allowedFor(p, true)).toEqual(["letsencrypt.org", "digicert.com"]);
    expect(allowedFor(parseCaa(HOST, ["0 issue \";\""]), false)).toEqual([]);
    expect(allowedFor(parseCaa(HOST, []), false)).toBeNull();
    expect(allowedFor(parseCaa(HOST, ["0 issue \"digicert.com\"", "0 issuewild \";\""]), true)).toEqual([]);
  });

  it("suggests only well-formed subdomains of the host, wildcards reduced to their base", () => {
    expect(suggestedHosts(HOST, parseCrtSh(CRTSH))).toEqual(["api.example.com", "legacy.example.com", "old.example.com", "shop.example.com", "www.example.com"]);
    const e: CtEntry = { id: "1", issuer: "x", names: ["*.dev.example.com", "bad_name.example.com", "notexample.com"], notBefore: "", notAfter: "" };
    expect(suggestedHosts(HOST, [e])).toEqual(["dev.example.com"]);
  });
});

describe("CT findings", () => {
  const entries = parseCrtSh(CRTSH);

  it("reports wildcard certs and currently valid certs from a CA the CAA records do not allow", () => {
    const f = ctFindings(HOST, entries, parseCaa(HOST, ["0 issue \"letsencrypt.org\""]), NOW);
    expect(f.map((x) => [x.issueKey, x.severity, x.location])).toEqual([["wildcard-cert", "info", HOST], ["unknown-issuer.digicert", "low", HOST]]);
    expect(f[0].evidence).toMatchObject({ names: ["*.example.com"], certificates: 1 });
    expect(f[1]).toMatchObject({ confidence: "likely", evidence: { ca: "DigiCert", caaAllowed: ["letsencrypt.org"], certIds: ["1004"], names: ["shop.example.com", "api.example.com"] } });
    expect(f[1].remediation).toMatch(/0 issue "digicert.com"/);
  });

  it("raises no issuer finding when CAA allows the CA, or when there is no CAA", () => {
    const allowed = ctFindings(HOST, entries, parseCaa(HOST, ["0 issue \"letsencrypt.org\"", "0 issue \"digicert.com\""]), NOW);
    expect(allowed.map((x) => x.issueKey)).toEqual(["wildcard-cert"]);
    expect(ctFindings(HOST, entries, parseCaa(HOST, []), NOW).map((x) => x.issueKey)).toEqual(["wildcard-cert"]);
  });

  it("ignores expired certificates and uses issuewild for wildcards", () => {
    const f = ctFindings(HOST, entries, parseCaa(HOST, ["0 issue \"digicert.com\"", "0 issuewild \"digicert.com\""]), NOW);
    // The Let's Encrypt wildcard is not allowed by issuewild; the expired DigiCert cert is ignored either way.
    expect(f.map((x) => x.issueKey)).toEqual(["wildcard-cert", "unknown-issuer.letsencrypt"]);
    expect(f[1].evidence).toMatchObject({ certIds: ["1001", "1002"] });
  });
});

describe("discovery.ct adapter", () => {
  it("queries crt.sh, caches the answer, and returns findings plus suggested hosts", async () => {
    const { fn, calls } = fakeFetch({ "crt.sh": { body: CRTSH } });
    const { cache, m } = memCache();
    const r = normalizeResult(await adapter(fn, cache).run(ctx()));
    expect(calls).toEqual(["https://crt.sh/?q=%25.example.com&output=json"]);
    expect(r.status).toBe("ok");
    if (r.status !== "ok") return;
    expect(r.findings.map((f) => f.issueKey)).toEqual(["wildcard-cert", "unknown-issuer.digicert"]);
    expect(r.evidence).toMatchObject({
      source: "crt.sh", cached: false, certificates: 5, validCertificates: 4, unmappedIssuers: ["C=XX, O=Tiny Private CA"],
      caa: { name: HOST, records: ["0 issue \"letsencrypt.org\""] }, suggestedHosts: expect.arrayContaining(["api.example.com", "www.example.com"]),
    });
    expect(m.get(HOST)?.source).toBe("crt.sh");
  });

  it("serves a fresh cache entry without any network call, and refreshes a stale one", async () => {
    const row: CtCacheRow = { source: "crt.sh", fetchedAt: new Date(NOW.getTime() - 3600_000), entries: parseCrtSh(CRTSH), truncated: false };
    const fresh = fakeFetch({});
    const r = await adapter(fresh.fn, memCache([HOST, row]).cache).run(ctx());
    expect(fresh.calls).toEqual([]);
    expect(r).toMatchObject({ status: "ok", evidence: { cached: true } });

    const stale = fakeFetch({ "crt.sh": { body: [] } });
    const r2 = await adapter(stale.fn, memCache([HOST, { ...row, fetchedAt: new Date(NOW.getTime() - CACHE_TTL_MS) }]).cache).run(ctx());
    expect(stale.calls).toHaveLength(1);
    expect(r2).toMatchObject({ status: "ok", findings: [], evidence: { cached: false, certificates: 0 } });
  });

  it("treats a broken cache as a miss rather than failing", async () => {
    const { fn } = fakeFetch({ "crt.sh": { body: CRTSH } });
    const broken: CtCache = { get: async () => { throw new Error("db down"); }, put: async () => { throw new Error("db down"); } };
    expect(await adapter(fn, broken).run(ctx())).toMatchObject({ status: "ok" });
  });

  it("falls back to Cert Spotter when crt.sh fails, paging with after", async () => {
    const page1 = Array.from({ length: 100 }, (_, i) => ({ ...CERTSPOTTER[0], id: String(8000 + i), dns_names: [`h${i}.example.com`] }));
    const { fn, calls } = fakeFetch({ "crt.sh": { status: 503 }, "api.certspotter.com": [{ body: page1 }, { body: CERTSPOTTER }] });
    const r = await adapter(fn).run(ctx());
    expect(calls).toHaveLength(3);
    expect(calls[1]).toMatch(/^https:\/\/api\.certspotter\.com\/v1\/issuances\?domain=example\.com&include_subdomains=true&expand=dns_names&expand=issuer$/);
    expect(calls[2]).toMatch(/&after=8099$/);
    expect(r).toMatchObject({ status: "ok", evidence: { source: "certspotter", certificates: 102, failures: { "crt.sh": "crtsh_http_503" } } });
    if (r.status !== "ok") return;
    // Odd CA is mapped through Cert Spotter's caa_domains and is not allowed by CAA.
    expect(r.findings.map((f) => f.issueKey)).toEqual(["unknown-issuer.odd-ca.example"]);
  });

  it("fails closed when neither CT source answers with valid data", async () => {
    const both = await adapter(fakeFetch({ "crt.sh": { throws: true }, "api.certspotter.com": { status: 429 } }).fn).run(ctx());
    expect(both).toEqual({ status: "error", reason: "ct_unavailable", evidence: { failures: { "crt.sh": "crtsh_unreachable", certspotter: "certspotter_http_429" } } });
    const garbage = await adapter(fakeFetch({ "crt.sh": { raw: "<html>busy</html>" }, "api.certspotter.com": { body: { message: "nope" } } }).fn).run(ctx());
    expect(garbage).toMatchObject({ status: "error", reason: "ct_unavailable", evidence: { failures: { "crt.sh": "crtsh_malformed_response", certspotter: "certspotter_malformed_response" } } });
  });

  it("fails closed when CAA cannot be read, before contacting any CT source", async () => {
    const { fn, calls } = fakeFetch({ "crt.sh": { body: CRTSH } });
    const r = await adapter(fn).run(ctx(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })));
    expect(r).toEqual({ status: "error", reason: "dns_ETIMEOUT", evidence: { name: HOST } });
    expect(calls).toEqual([]);
  });

  it("never contacts the target itself", async () => {
    const { fn, calls } = fakeFetch({ "crt.sh": { body: CRTSH } });
    await adapter(fn).run(ctx());
    expect(calls.every((u) => ["crt.sh", "api.certspotter.com"].includes(new URL(u).host))).toBe(true);
  });
});
