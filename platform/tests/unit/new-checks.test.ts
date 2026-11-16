import { describe, expect, it } from "vitest";
import { normalizeResult, type CheckContext } from "@/server/assessments/checks";
import { analysePage, createCompromiseAdapter, type Fetch as CFetch } from "@/server/assessments/compromise";
import { createCorsAdapter, type Fetch as OFetch } from "@/server/assessments/cors";
import { createTakeoverAdapter, type Lookup } from "@/server/assessments/takeover";
import { EgressError, type DnsAnswer, type FetchResult } from "@/server/net/egress";

const HOST = "shop.example.com";
const ctx = { host: HOST, timeoutMs: 30000, egress: {}, dns: {}, onHop: () => {} } as unknown as CheckContext;
const res = (status: number, body = "", headers: Record<string, string> = {}, contentType: string | null = "text/html; charset=utf-8"): FetchResult =>
  ({ status, body, contentType, truncated: false, redirects: 0, finalUrl: "", pinnedAddress: "203.0.113.10", headers } as FetchResult);
const keys = (r: { status: string } & Record<string, unknown>) => r.status === "ok" ? (r.findings as { issueKey: string; severity: string }[]).map((f) => `${f.issueKey}:${f.severity}`) : [`error:${r.reason}`];

describe("http.compromise", () => {
  const CLEAN = `<html><head><script src="/app.js"></script><script src="https://cdn.jsdelivr.net/x.js"></script></head><body><h1>Shoes</h1></body></html>`;
  const run = (user: FetchResult | Error, crawler: FetchResult | Error = user) => {
    const f: CFetch = async (_u, _c, { crawler: c }) => { const r = c ? crawler : user; if (r instanceof Error) throw r; return r; };
    return createCompromiseAdapter(f).run(ctx).then(normalizeResult);
  };

  it("clean page: only the external host is listed (info), and evidence holds no page content", async () => {
    const r = await run(res(200, CLEAN));
    expect(keys(r)).toEqual(["script_host.cdn.jsdelivr.net:info"]);
    expect(JSON.stringify(r)).not.toContain("Shoes");
  });

  it("finds hidden iframes, miners, obfuscation, IP and throwaway-TLD scripts", async () => {
    const html = `<iframe src="http://evil.top/x" width="1" height="1"></iframe>
      <script src="http://198.51.100.7/a.js"></script><script src="https://stats.cdn-x.xyz/s.js"></script>
      <script>var m = new CoinHive.Anonymous("k"); eval(atob("YWxlcnQoMSk="));</script>`;
    const k = keys(await run(res(200, html)));
    expect(k).toEqual(expect.arrayContaining(["hidden_iframe:high", "crypto_miner:high", "obfuscated_inline_script:high", "script_from_ip:high", "script_suspicious_tld:medium"]));
  });

  it("detects hidden spam, and spam shown only to crawlers (cloaking)", async () => {
    const hidden = `<p>Hello</p><div style="display:none">best online casino and cheap viagra</div>`;
    expect(keys(await run(res(200, hidden)))).toContain("seo_spam_hidden:high");
    const k = keys(await run(res(200, "<p>Hello</p>"), res(200, "<p>Hello</p><a>slot gacor</a> <a>judi online</a>")));
    expect(k).toContain("seo_spam_cloaked:high");
  });

  it("detects a search-engine referrer redirect", () => {
    expect(analysePage(`<script>if(/google|bing/.test(document.referrer)){window.location.href="https://x.top"}</script>`, HOST).referrerRedirect).toBe(true);
    expect(analysePage(`<script>console.log(document.referrer)</script>`, HOST).referrerRedirect).toBe(false);
  });

  it("does not count the site's own subdomains as external", () => {
    expect(analysePage(`<script src="https://static.example.com/a.js"></script>`, HOST).scriptHosts).toEqual([]);
  });

  it("fails closed on 429, 5xx, 404, non-HTML and network errors", async () => {
    expect(keys(await run(res(429)))).toEqual(["error:http_429"]);
    expect(keys(await run(res(503)))).toEqual(["error:http_503"]);
    expect((await run(res(404))).status).toBe("error");
    expect((await run(res(200, "{}", {}, "application/json"))).status).toBe("error");
    expect(keys(await run(new EgressError("timeout", "t")))).toEqual(["error:egress:timeout"]);
  });
});

describe("http.cors", () => {
  const PROBE = "https://ruya-abc.invalid";
  const run = (byOrigin: (o: string) => FetchResult | Error) => {
    const f: OFetch = async (_u, _c, o) => { const r = byOrigin(o); if (r instanceof Error) throw r; return r; };
    return createCorsAdapter(f, () => PROBE).run(ctx).then(normalizeResult);
  };

  it("no CORS headers: ok, no findings", async () => {
    const r = await run(() => res(200));
    expect(r.status).toBe("ok");
    expect(keys(r)).toEqual([]);
  });

  it("reflected origin with credentials is high; without credentials low", async () => {
    expect(keys(await run((o) => res(200, "", o === PROBE ? { "access-control-allow-origin": o, "access-control-allow-credentials": "true" } : {})))).toEqual(["cors_reflects_origin_credentials:high"]);
    expect(keys(await run((o) => res(200, "", o === PROBE ? { "access-control-allow-origin": o } : {})))).toEqual(["cors_reflects_origin:low"]);
  });

  it("null origin and wildcard+credentials", async () => {
    expect(keys(await run((o) => res(200, "", o === "null" ? { "access-control-allow-origin": "null", "access-control-allow-credentials": "true" } : {})))).toEqual(["cors_null_origin_credentials:high"]);
    expect(keys(await run(() => res(200, "", { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" })))).toEqual(["cors_wildcard_credentials:low"]);
    expect(keys(await run(() => res(200, "", { "access-control-allow-origin": "*" })))).toEqual([]);
  });

  it("fails closed", async () => {
    expect(keys(await run(() => res(502)))).toEqual(["error:http_502"]);
    expect(keys(await run(() => new EgressError("timeout", "t")))).toEqual(["error:egress:timeout"]);
  });
});

describe("dns.takeover", () => {
  type Zone = Record<string, Partial<Record<string, DnsAnswer>>>;
  const lookup = (zone: Zone): Lookup => async (name, type) => zone[name]?.[type] ?? (zone[name] ? { records: [] } : { records: [], nxdomain: true });
  const run = (zone: Zone, page: FetchResult | Error = res(200, "ok"), calls: string[] = []) =>
    createTakeoverAdapter(lookup(zone), async (u) => { calls.push(u); if (page instanceof Error) throw page; return page; }).run(ctx).then(normalizeResult);

  it("no CNAME: ok with no findings and no HTTP request", async () => {
    const calls: string[] = [];
    const r = await run({ [HOST]: { A: { records: ["203.0.113.1"] } } }, res(200), calls);
    expect(keys(r)).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("CNAME to a name that does not exist is dangling", async () => {
    const r = await run({ [HOST]: { CNAME: { records: ["old-app.azurewebsites.net"] } } });
    expect(keys(r)).toEqual(["dangling_cname:high"]);
  });

  it("CNAME to an unclaimed GitHub Pages site", async () => {
    const zone: Zone = { [HOST]: { CNAME: { records: ["acme.github.io"] } }, "acme.github.io": { A: { records: ["185.199.108.153"] } } };
    expect(keys(await run(zone, res(404, "<title>Site not found</title> There isn't a GitHub Pages site here.")))).toEqual(["unclaimed_service:high"]);
    expect(keys(await run(zone, res(200, "<h1>Acme</h1>")))).toEqual([]);
    expect(keys(await run(zone, res(503, "")))).toEqual(["error:http_503"]);
    expect(keys(await run(zone, new EgressError("timeout", "t")))).toEqual(["error:egress:timeout"]);
  });

  it("CNAME to a non-prone service: ok without an HTTP request", async () => {
    const calls: string[] = [];
    const zone: Zone = { [HOST]: { CNAME: { records: ["lb.example.net"] } }, "lb.example.net": { A: { records: ["203.0.113.5"] } } };
    expect(keys(await run(zone, res(200), calls))).toEqual([]);
    expect(calls).toEqual([]);
  });

  it("DNS errors fail closed", async () => {
    expect(keys(await run({ [HOST]: { CNAME: { error: "timeout" } } }))).toEqual(["error:dns_timeout"]);
  });
});
