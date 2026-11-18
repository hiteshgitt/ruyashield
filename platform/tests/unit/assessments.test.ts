import http from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { inScope, scopeSha, validateScope, type CatalogueEntry } from "@/server/assessments/scope";
import { signJobToken, verifyJobToken } from "@/server/assessments/token";
import { createGuard, ScopeBlocked } from "@/server/assessments/guard";
import { ADAPTERS, cspScriptWeakness, emailFindings, fingerprint, headerFindings, httpRedirectFindings, normalizeResult, tlsFindings } from "@/server/assessments/checks";
import { isCleanResult } from "@/server/assessments/assessments";
import { guardedGet } from "@/server/net/egress";

process.env.JOB_TOKEN_SECRET ??= "unit-test-secret-unit-test-secret-0123";

const catalogue: CatalogueEntry[] = [
  { id: "tls.cert_expiry@1", class: "A1", enabled: true, requestBudget: 1 },
  { id: "http.security_headers@1", class: "A1", enabled: true, requestBudget: 4 },
  { id: "dns.email_posture@1", class: "P", enabled: true, requestBudget: 0 },
  { id: "a2.something@1", class: "A2", enabled: true, requestBudget: 10 },
  { id: "x.exploit_payloads@1", class: "X", enabled: false, requestBudget: 0 },
  { id: "off.check@1", class: "P", enabled: false, requestBudget: 0 },
];
const now = new Date("2026-10-01T00:00:00Z");
const ctx = { assetHost: "acme.example", allowedClasses: ["P", "A1"], catalogue, planMaxRequests: 200, now };

describe("validateScope", () => {
  it("builds a fail-closed scope for the asset's own host only", () => {
    const s = validateScope({ checkIds: ["http.security_headers@1", "dns.email_posture@1", "dns.email_posture@1"] }, ctx);
    expect(s.hosts).toEqual(["acme.example"]);
    expect(s.checkIds).toEqual(["dns.email_posture@1", "http.security_headers@1"]);
    expect(s.classes).toEqual(["A1", "P"]);
    expect(s.basePaths).toEqual(["/"]);
    expect(s.maxRequests).toBe(200);
    expect(s.windowEnd.getTime() - s.windowStart.getTime()).toBe(24 * 3600_000);
  });

  it.each([
    [{ checkIds: ["x.exploit_payloads@1"] }, "check_prohibited"],
    [{ checkIds: ["a2.something@1"] }, "approval_required"],
    [{ checkIds: ["off.check@1"] }, "invalid_scope"],
    [{ checkIds: ["nope@1"] }, "invalid_scope"],
    [{ checkIds: [] }, "invalid_scope"],
    [{ checkIds: ["dns.email_posture@1"], basePaths: ["/a/../admin"] }, "invalid_scope"],
    [{ checkIds: ["dns.email_posture@1"], basePaths: ["relative"] }, "invalid_scope"],
    [{ checkIds: ["dns.email_posture@1"], maxRequests: 201 }, "invalid_scope"],
    [{ checkIds: ["http.security_headers@1"], maxRequests: 3 }, "invalid_scope"],
    [{ checkIds: ["dns.email_posture@1"], maxDurationS: 30 }, "invalid_scope"],
    [{ checkIds: ["dns.email_posture@1"], windowStart: "2026-10-02", windowEnd: "2026-10-01" }, "invalid_scope"],
    [{ checkIds: ["dns.email_posture@1"], windowStart: "2026-09-01", windowEnd: "2026-09-02" }, "invalid_scope"],
    [{ checkIds: ["dns.email_posture@1"], windowEnd: "2026-12-31" }, "invalid_scope"],
  ])("%j -> %s", (raw, code) => {
    expect(() => validateScope(raw, ctx)).toThrow(expect.objectContaining({ code }));
  });

  it("refuses classes the asset's authorization does not cover", () => {
    expect(() => validateScope({ checkIds: ["tls.cert_expiry@1"] }, { ...ctx, allowedClasses: ["P"] }))
      .toThrow(expect.objectContaining({ code: "authorization_required" }));
  });

  it("hashes scopes stably and sensitively", () => {
    const a = validateScope({ checkIds: ["dns.email_posture@1"] }, ctx);
    const b = validateScope({ checkIds: ["dns.email_posture@1"] }, ctx);
    const c = validateScope({ checkIds: ["dns.email_posture@1"], excludedPaths: ["/admin"] }, ctx);
    expect(scopeSha(a)).toBe(scopeSha(b));
    expect(scopeSha(a)).not.toBe(scopeSha(c));
  });
});

describe("inScope", () => {
  const s = { hosts: ["acme.example"], basePaths: ["/app"], excludedPaths: ["/app/admin"] };
  it.each([
    ["https://acme.example/app", true],
    ["https://acme.example/app/x", true],
    ["https://ACME.example./app/x", true],
    ["https://acme.example/application", false],
    ["https://acme.example/app/admin/x", false],
    ["https://acme.example/app/ADMIN", false],
    ["https://acme.example/app/%2e%2e/secret", false],
    ["https://acme.example/app/%61dmin", false],
    ["https://evil.example/app", false],
    ["https://sub.acme.example/app", false],
    ["ftp://acme.example/app", false],
  ])("%s -> %s", (url, want) => expect(inScope(s, new URL(url))).toBe(want));
  it("allows host-only probes regardless of path", () => expect(inScope(s, new URL("https://acme.example/"), { hostOnly: true })).toBe(true));
});

describe("job tokens", () => {
  const claims = { org: "o1", assessment: "a1", sha: "s1" };
  it("accepts a valid token and rejects tampering, mismatch and expiry", () => {
    const t = signJobToken({ ...claims, exp: 2000 });
    expect(verifyJobToken(t, claims, 1000)).toEqual({ ok: true });
    expect(verifyJobToken(t, claims, 3000)).toEqual({ ok: false, reason: "expired" });
    expect(verifyJobToken(t, { ...claims, sha: "other" }, 1000)).toEqual({ ok: false, reason: "mismatch" });
    expect(verifyJobToken(t, { ...claims, org: "o2" }, 1000)).toEqual({ ok: false, reason: "mismatch" });
    expect(verifyJobToken(t.slice(0, -2) + "xx", claims, 1000)).toMatchObject({ ok: false, reason: "bad_signature" });
    expect(verifyJobToken("garbage", claims, 1000)).toEqual({ ok: false, reason: "malformed" });
    expect(verifyJobToken(undefined, claims, 1000)).toEqual({ ok: false, reason: "malformed" });
  });
});

describe("result handling", () => {
  it("treats malformed adapter output as an error, never as clean", () => {
    expect(normalizeResult({ status: "ok" })).toEqual({ status: "error", reason: "malformed_output", evidence: {} });
    expect(normalizeResult(null).status).toBe("error");
    expect(normalizeResult({ status: "ok", findings: [{ issueKey: "BAD KEY", title: "t", severity: "low", location: "x", evidence: {}, remediation: "" }], evidence: {} }).status).toBe("error");
    expect(normalizeResult({ status: "ok", findings: [], evidence: {} }).status).toBe("ok");
  });

  it("only calls a result clean when every planned check completed and nothing was found", () => {
    const cov = (o: Partial<{ planned: number; ok: number; complete: boolean }>) => ({ planned: 3, ok: 3, error: 0, timeout: 0, skipped: 0, requests: 1, complete: true, ...o });
    expect(isCleanResult({ status: "completed", coverage: cov({}) }, 0)).toBe(true);
    expect(isCleanResult({ status: "completed", coverage: cov({}) }, 1)).toBe(false);
    expect(isCleanResult({ status: "completed_with_errors", coverage: cov({ ok: 2, complete: false }) }, 0)).toBe(false);
    expect(isCleanResult({ status: "failed", coverage: cov({ ok: 0, complete: false }) }, 0)).toBe(false);
    expect(isCleanResult({ status: "cancelled", coverage: cov({}) }, 0)).toBe(false);
    expect(isCleanResult({ status: "timed_out", coverage: cov({}) }, 0)).toBe(false);
    expect(isCleanResult({ status: "completed", coverage: cov({ complete: false }) }, 0)).toBe(false);
    expect(isCleanResult({ status: "completed", coverage: null }, 0)).toBe(false);
  });

  it("fingerprints are stable per check, location and issue", () => {
    expect(fingerprint("a", "b", "c")).toBe(fingerprint("a", "b", "c"));
    expect(fingerprint("a", "b", "c")).not.toBe(fingerprint("a", "b", "d"));
  });

  it("has no adapter for prohibited checks", () => {
    expect(ADAPTERS.has("x.exploit_payloads@1")).toBe(false);
    expect([...ADAPTERS.keys()].sort()).toEqual(["code.iac@1", "code.sast@1", "code.secrets@1", "container.image@1", "deps.osv@1", "discovery.ct@1", "dns.caa@1", "dns.email_posture@1", "dns.takeover@1", "http.compromise@1", "http.cors@1", "http.exposure@1", "http.security_headers@1", "net.exposed_services@1", "tls.cert_expiry@1", "tls.config@1", "web.blocklist@1", "web.technology@1"]);
  });
});

describe("finding rules", () => {
  it("TLS: expired, expiring, untrusted", () => {
    const keys = (validTo: string, authorized = true) => tlsFindings("h", { validTo, authorized, authorizationError: authorized ? null : "SELF_SIGNED", issuer: "X" }, now).map((f) => `${f.issueKey}:${f.severity}`);
    expect(keys("2026-09-01")).toEqual(["cert_expired:high"]);
    expect(keys("2026-10-05")).toEqual(["cert_expiring:medium"]);
    expect(keys("2026-10-20")).toEqual(["cert_expiring:low"]);
    expect(keys("2027-06-01")).toEqual([]);
    expect(keys("2027-06-01", false)).toEqual(["cert_untrusted:medium"]);
    expect(keys("not a date")).toEqual(["cert_expiry_unreadable:medium"]);
  });

  it("headers: flags missing protections and weak cookies without storing cookie values", () => {
    const f = headerFindings("https://h/", { "set-cookie": ["sid=SECRET123; Path=/"] });
    expect(f.map((x) => x.issueKey).sort()).toEqual(["cookie_no_httponly.sid", "cookie_no_samesite.sid", "cookie_no_secure.sid", "missing_csp", "missing_frame_protection", "missing_hsts", "missing_nosniff"]);
    expect(JSON.stringify(f)).not.toContain("SECRET123");
    const good = headerFindings("https://h/", {
      "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
      "x-content-type-options": "nosniff", "set-cookie": ["sid=v; Secure; HttpOnly; SameSite=Lax"],
    });
    expect(good).toEqual([]);
  });

  it("headers: weak HSTS, CSP that allows any script, unsafe referrer policy and version banners", () => {
    const base = { "content-security-policy": "default-src 'self'", "x-content-type-options": "nosniff", "x-frame-options": "DENY" };
    const k = (h: Record<string, string>) => headerFindings("https://h/", { ...base, "strict-transport-security": "max-age=31536000", ...h }).map((f) => f.issueKey).sort();
    expect(k({ "strict-transport-security": "max-age=0" })).toEqual(["weak_hsts"]);
    expect(k({ "strict-transport-security": "max-age=86400; includeSubDomains" })).toEqual(["weak_hsts"]);
    expect(k({ "strict-transport-security": "includeSubDomains" })).toEqual(["weak_hsts"]);
    expect(k({ "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'" })).toEqual(["weak_csp"]);
    expect(k({ "content-security-policy": "default-src *" })).toEqual(["weak_csp"]);
    expect(k({ "content-security-policy": "frame-ancestors 'none'" })).toEqual(["weak_csp"]);
    expect(k({ "referrer-policy": "unsafe-url" })).toEqual(["unsafe_referrer_policy"]);
    expect(k({ "referrer-policy": "strict-origin-when-cross-origin" })).toEqual([]);
    expect(k({ server: "nginx" })).toEqual([]);
    const v = headerFindings("https://h/", { ...base, "strict-transport-security": "max-age=31536000", server: "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.2.24" });
    expect(v).toHaveLength(1);
    expect(v[0]).toMatchObject({ issueKey: "version_disclosure", evidence: { headers: { server: "Apache/2.4.29 (Ubuntu)", "x-powered-by": "PHP/7.2.24" } } });
  });

  it("csp: nonces and hashes neutralise 'unsafe-inline'; script-src overrides default-src", () => {
    expect(cspScriptWeakness("script-src 'self' 'unsafe-inline' 'nonce-abc'")).toEqual([]);
    expect(cspScriptWeakness("script-src 'unsafe-inline' 'sha256-xyz'")).toEqual([]);
    expect(cspScriptWeakness("default-src *; script-src 'self'")).toEqual([]);
    expect(cspScriptWeakness("default-src 'self'; script-src https: data:")).toEqual(["wildcard_source"]);
    expect(cspScriptWeakness("img-src *")).toEqual(["no_script_src"]);
  });

  it("http: plain HTTP without a redirect to HTTPS is flagged; redirects, errors and closed ports are not", () => {
    expect(httpRedirectFindings("h", { status: 200, finalUrl: "http://h/" })).toMatchObject([{ issueKey: "http_no_redirect", location: "http://h/" }]);
    expect(httpRedirectFindings("h", { status: 200, finalUrl: "https://h/" })).toEqual([]);
    expect(httpRedirectFindings("h", { status: 404, finalUrl: "http://h/" })).toEqual([]);
    expect(httpRedirectFindings("h", null)).toEqual([]);
  });

  it("email: SPF and DMARC posture", () => {
    const k = (txt: string[], dm: string[]) => emailFindings("h", txt, dm).map((f) => f.issueKey);
    expect(k([], [])).toEqual(["spf_missing", "dmarc_missing"]);
    expect(k(["v=spf1 +all"], ["v=DMARC1; p=reject"])).toEqual(["spf_pass_all"]);
    expect(k(["v=spf1 -all", "v=spf1 ~all"], ["v=DMARC1; p=none"])).toEqual(["spf_multiple", "dmarc_p_none"]);
    expect(k(["v=spf1 include:_spf.example -all"], ["v=DMARC1; p=quarantine"])).toEqual([]);
  });
});

// ---------- Scope guard against a real local server ----------
let server: http.Server;
let port = 0;
const hits: string[] = [];
beforeAll(async () => {
  server = http.createServer((req, res) => {
    hits.push(req.url ?? "");
    switch (req.url) {
      case "/app/ok": res.end("ok"); break;
      case "/app/to-admin": res.writeHead(302, { location: "/app/admin/panel" }).end(); break;
      case "/app/to-offsite": res.writeHead(302, { location: `http://other.test:${port}/app/ok` }).end(); break;
      case "/app/to-meta": res.writeHead(302, { location: "http://169.254.169.254/latest/meta-data/" }).end(); break;
      default: res.writeHead(404).end();
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
afterAll(() => { server.closeAllConnections(); server.close(); });

describe("scope guard (controlled tests: zero out-of-scope requests)", () => {
  const local = { allowPrivate: true, resolve: async () => [{ address: "127.0.0.1", family: 4 as const }], timeoutMs: 1500 };
  const scope = () => ({ hosts: ["site.test"], basePaths: ["/app"], excludedPaths: ["/app/admin"], maxRequests: 3 });
  const noWait = { sleep: async () => {}, minIntervalMs: 0 };
  const u = (p: string) => `http://site.test:${port}${p}`;

  it("allows in-scope requests and counts them", async () => {
    const g = createGuard(scope(), noWait);
    const r = await guardedGet(u("/app/ok"), { ...local, onHop: g.forCheck("c", 5) });
    expect(r.status).toBe(200);
    expect(g.total).toBe(1);
  });

  it("blocks an in-host redirect into an excluded path before it is sent", async () => {
    hits.length = 0;
    const g = createGuard(scope(), noWait);
    await expect(guardedGet(u("/app/to-admin"), { ...local, onHop: g.forCheck("c", 5) })).rejects.toBeInstanceOf(ScopeBlocked);
    expect(g.blocked.map((b) => b.reason)).toEqual(["out_of_scope"]);
    expect(hits).toEqual(["/app/to-admin"]); // the excluded path never received a request
  });

  it.each(["/app/to-offsite", "/app/to-meta"])("refuses the cross-host redirect from %s (egress layer, before the guard)", async (path) => {
    hits.length = 0;
    const g = createGuard(scope(), noWait);
    await expect(guardedGet(u(path), { ...local, onHop: g.forCheck("c", 5) })).rejects.toThrow();
    expect(hits).toEqual([path]);
    expect(g.total).toBe(1);
  });

  it("blocks out-of-scope first requests without sending anything", async () => {
    hits.length = 0;
    const g = createGuard(scope(), noWait);
    for (const p of ["/", "/app/admin/x", "/other"]) {
      await expect(guardedGet(u(p), { ...local, onHop: g.forCheck("c", 5) })).rejects.toBeInstanceOf(ScopeBlocked);
    }
    expect(hits).toEqual([]);
    expect(g.total).toBe(0);
  });

  it("enforces per-check and total budgets, and stops all traffic once closed", async () => {
    const g = createGuard(scope(), noWait);
    const hop = g.forCheck("c", 2);
    await guardedGet(u("/app/ok"), { ...local, onHop: hop });
    await guardedGet(u("/app/ok"), { ...local, onHop: hop });
    await expect(guardedGet(u("/app/ok"), { ...local, onHop: hop })).rejects.toMatchObject({ reason: "check_budget_exhausted" });
    await guardedGet(u("/app/ok"), { ...local, onHop: g.forCheck("d", 5) });
    await expect(guardedGet(u("/app/ok"), { ...local, onHop: g.forCheck("e", 5) })).rejects.toMatchObject({ reason: "budget_exhausted" });
    g.close();
    await expect(guardedGet(u("/app/ok"), { ...local, onHop: g.forCheck("f", 5) })).rejects.toMatchObject({ reason: "closed" });
    expect(g.total).toBe(3);
  });

  it("spaces requests to the same host", async () => {
    const waits: number[] = [];
    let t = 1000;
    const g = createGuard(scope(), { now: () => t, sleep: async (ms) => { waits.push(ms); t += ms; }, minIntervalMs: 500 });
    const hop = g.forCheck("c", 3);
    await hop(new URL("http://site.test/app/a"));
    await hop(new URL("http://site.test/app/b"));
    await hop(new URL("http://site.test/app/c"));
    expect(waits).toEqual([500, 500]);
  });

  it("refuses a scoped host that resolves to cloud metadata even when the guard allows it", async () => {
    const g = createGuard({ hosts: ["acme.example"], basePaths: ["/"], excludedPaths: [], maxRequests: 5 }, noWait);
    await expect(guardedGet("https://acme.example/", { resolve: async () => [{ address: "169.254.169.254", family: 4 }], onHop: g.forCheck("c", 5) }))
      .rejects.toMatchObject({ code: "egress_blocked" });
  });
});
