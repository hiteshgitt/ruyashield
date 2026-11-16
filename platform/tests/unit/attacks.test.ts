import { describe, expect, it } from "vitest";
import { classify, splitPath } from "@/server/attacks/classify";
import { parseBatch, parseClfDate, parseLine } from "@/server/attacks/logparse";
import { SecretKeyMissing, open, seal } from "@/server/attacks/secretbox";
import { CloudflareError, fetchFirewallEvents, parseEvents, typeFor } from "@/server/attacks/cloudflare";
import { UNKNOWN, geoFrom } from "@/server/attacks/geoip";
import { spikeSourceId } from "@/server/attacks/attacks";
import type { FetchLike } from "@/server/assessments/deps";

const NOW = new Date("2026-11-10T14:00:00Z");
const line = (path: string, status = 404, ua = "Mozilla/5.0", ip = "203.0.113.7", when = "10/Nov/2026:13:55:36 +0000", method = "GET") =>
  `${ip} - - [${when}] "${method} ${path} HTTP/1.1" ${status} 512 "-" "${ua}"`;
const KEY = "k".repeat(40);

describe("classify", () => {
  it("returns null for benign requests", () => {
    expect(classify({ method: "GET", target: "/about?ref=home", status: 200, userAgent: "Mozilla/5.0" })).toBeNull();
    expect(classify({ method: "GET", target: "/wp-login.php", status: 200, userAgent: "Mozilla/5.0" })).toBeNull();
    expect(classify({ method: "GET", target: "/", status: 200, userAgent: "curl/8.5.0" })).toBeNull();
  });
  it("detects common attack signatures", () => {
    expect(classify({ method: "GET", target: "/item?id=1%20UNION%20SELECT%20password", status: 500, userAgent: null })).toBe("sqli");
    expect(classify({ method: "GET", target: "/download?f=../../etc/passwd", status: 400, userAgent: null })).toBe("traversal");
    expect(classify({ method: "GET", target: "/.env", status: 404, userAgent: null })).toBe("sensitive_probe");
    expect(classify({ method: "GET", target: "/.git/config", status: 403, userAgent: null })).toBe("sensitive_probe");
    expect(classify({ method: "POST", target: "/wp-login.php", status: 200, userAgent: null })).toBe("admin_bruteforce");
    expect(classify({ method: "GET", target: "/", status: 200, userAgent: "sqlmap/1.8" })).toBe("scanner");
    expect(classify({ method: "GET", target: "/x", status: 404, userAgent: "curl/8.5.0" })).toBe("scanner");
  });
  it("strips the query string and fragment from stored paths", () => {
    expect(splitPath("/login?token=secret#x")).toBe("/login");
    expect(splitPath("?a=b")).toBe("/");
  });
});

describe("logparse", () => {
  it("parses CLF dates with offsets", () => {
    expect(parseClfDate("10/Nov/2026:15:55:36 +0200")?.toISOString()).toBe("2026-11-10T13:55:36.000Z");
    expect(parseClfDate("10/Foo/2026:15:55:36 +0200")).toBeNull();
  });
  it("keeps suspicious lines without the query string and drops benign ones", () => {
    const e = parseLine(line("/search?q=1'%20or%20'1'='1&session=abc", 200), NOW);
    expect(e?.attackType).toBe("sqli");
    expect(e?.path).toBe("/search");
    expect(e?.ip).toBe("203.0.113.7");
    expect(parseLine(line("/index.html?utm=x", 200), NOW)).toBeNull();
  });
  it("rejects bad IPs, future and expired timestamps, and oversized lines", () => {
    expect(parseLine(line("/.env", 404, "x", "not-an-ip"), NOW)).toBeNull();
    expect(parseLine(line("/.env", 404, "x", "203.0.113.7", "10/Nov/2026:16:00:00 +0000"), NOW)).toBeNull();
    expect(parseLine(line("/.env", 404, "x", "203.0.113.7", "01/Jan/2026:00:00:00 +0000"), NOW)).toBeNull();
    expect(parseLine(line(`/.env${"a".repeat(9000)}`), NOW)).toBeNull();
  });
  it("dedupes within a batch and counts unparsed lines", () => {
    const l = line("/.env");
    const r = parseBatch([l, l, line("/ok", 200), "garbage line", ""], NOW);
    expect(r.events).toHaveLength(1);
    expect(r.received).toBe(5);
    expect(r.unparsed).toBe(1);
  });
});

describe("secretbox", () => {
  it("round-trips and binds the AAD", () => {
    const s = seal("cf-token-value", "attack_source:o:s", KEY);
    expect(s.startsWith("v1.")).toBe(true);
    expect(s).not.toContain("cf-token-value");
    expect(open(s, "attack_source:o:s", KEY)).toBe("cf-token-value");
    expect(() => open(s, "attack_source:o:other", KEY)).toThrow();
    expect(() => open(s, "attack_source:o:s", "z".repeat(40))).toThrow();
    expect(() => open("revoked", "attack_source:o:s", KEY)).toThrow("secret_malformed");
  });
  it("refuses a missing or short key", () => {
    expect(() => seal("x", "a", "short")).toThrow(SecretKeyMissing);
  });
});

const cfRow = (over: Record<string, unknown> = {}) => ({
  action: "block", source: "firewallManaged", ruleId: "r1", rayName: "abc", datetime: "2026-11-10T13:00:00Z", clientIP: "198.51.100.4",
  clientCountryName: "DE", clientAsn: "64500", clientASNDescription: "Example AS", clientRequestHTTPHost: "shop.example.com",
  clientRequestHTTPMethodName: "GET", clientRequestPath: "/wp-admin?x=1", userAgent: "ua", ...over,
});
const cfBody = (rows: unknown[]) => ({ data: { viewer: { zones: [{ firewallEventsAdaptive: rows }] } }, errors: null });

describe("cloudflare parseEvents", () => {
  it("maps rows and strips query strings", () => {
    const [e] = parseEvents(cfBody([cfRow()]));
    expect(e).toMatchObject({ ip: "198.51.100.4", country: "DE", asn: 64500, asOrg: "Example AS", attackType: "waf_block", path: "/wp-admin" });
    expect(e.dedupeKey).toMatch(/^[a-f0-9]{40}$/);
  });
  it("nulls unknown/Tor countries and skips invalid IPs", () => {
    const ev = parseEvents(cfBody([cfRow({ clientCountryName: "XX" }), cfRow({ clientCountryName: "T1", rayName: "b" }), cfRow({ clientIP: "nope" })]));
    expect(ev).toHaveLength(2);
    expect(ev.every((e) => e.country === null)).toBe(true);
  });
  it("fails closed on errors and bad shapes", () => {
    const err = (b: unknown) => { try { parseEvents(b); return "none"; } catch (e) { expect(e).toBeInstanceOf(CloudflareError); return (e as Error).message; } };
    expect(err("x")).toBe("cloudflare_malformed_response");
    expect(err({ errors: [{ message: "not authorized for that account" }] })).toBe("cloudflare_not_authorized");
    expect(err({ errors: [{ message: "zone does not exist" }] })).toBe("cloudflare_zone_not_found");
    expect(err({ errors: [{ message: "quota exceeded" }] })).toBe("cloudflare_rate_limited");
    expect(err({ errors: [{ message: "boom" }] })).toBe("cloudflare_graphql_error");
    expect(err({ data: {} })).toBe("cloudflare_malformed_response");
    expect(err({ data: { viewer: { zones: [] } } })).toBe("cloudflare_zone_not_visible");
    expect(err(cfBody([{ action: "block" }]))).toBe("cloudflare_malformed_response");
  });
  it("types events by action and source", () => {
    expect(typeFor("block", "ratelimit")).toBe("rate_limit");
    expect(typeFor("block", "bic")).toBe("bot");
    expect(typeFor("managed_challenge", "firewallManaged")).toBe("challenge");
    expect(typeFor("drop", "firewallCustom")).toBe("waf_block");
    expect(typeFor("log", "firewallCustom")).toBe("other");
  });
});

describe("cloudflare fetchFirewallEvents", () => {
  const ZONE = "a".repeat(32);
  const since = new Date("2026-11-10T12:00:00Z");
  const fake = (status: number, body: unknown, seen: { url?: string; auth?: string } = {}): FetchLike => async (url, init) => {
    seen.url = url; seen.auth = init.headers?.authorization;
    return { ok: status < 400, status, text: async () => JSON.stringify(body) };
  };
  it("only returns events for the verified host and calls the GraphQL endpoint", async () => {
    const seen: { url?: string; auth?: string } = {};
    const ev = await fetchFirewallEvents(fake(200, cfBody([cfRow(), cfRow({ clientRequestHTTPHost: "other.example.com", rayName: "z" })]), seen), "tok", ZONE, since, NOW, "Shop.Example.com");
    expect(ev).toHaveLength(1);
    expect(ev[0].host).toBe("shop.example.com");
    expect(seen.url).toBe("https://api.cloudflare.com/client/v4/graphql");
    expect(seen.auth).toBe("Bearer tok");
  });
  it("maps HTTP failures and refuses bad input", async () => {
    await expect(fetchFirewallEvents(fake(401, {}), "t", ZONE, since, NOW, "a.com")).rejects.toThrow("cloudflare_not_authorized");
    await expect(fetchFirewallEvents(fake(429, {}), "t", ZONE, since, NOW, "a.com")).rejects.toThrow("cloudflare_rate_limited");
    await expect(fetchFirewallEvents(fake(502, {}), "t", ZONE, since, NOW, "a.com")).rejects.toThrow("cloudflare_http_502");
    await expect(fetchFirewallEvents(fake(200, {}), "t", "not-a-zone", since, NOW, "a.com")).rejects.toThrow("cloudflare_zone_id_invalid");
    await expect(fetchFirewallEvents(fake(200, {}), "t", ZONE, since, NOW, "bad host/")).rejects.toThrow("cloudflare_host_invalid");
    const boom: FetchLike = async () => { throw new Error("ECONNRESET"); };
    await expect(fetchFirewallEvents(boom, "t", ZONE, since, NOW, "a.com")).rejects.toThrow("cloudflare_unreachable");
  });
});

describe("geoip and spike ids", () => {
  it("returns unknown without databases or for non-IPs", () => {
    expect(geoFrom(null, null)("203.0.113.7")).toEqual(UNKNOWN);
    expect(geoFrom(null, null)("nope")).toBe(UNKNOWN);
  });
  it("reads country and ASN from readers", () => {
    const c = { get: () => ({ country: { iso_code: "FR" } }) } as never;
    const a = { get: () => ({ autonomous_system_number: 64501, autonomous_system_organization: "Ex" }) } as never;
    expect(geoFrom(c, a)("203.0.113.7")).toEqual({ country: "FR", asn: 64501, asOrg: "Ex" });
  });
  it("spike notification ids are stable per asset and hour", () => {
    const id = spikeSourceId("11111111-1111-4111-8111-111111111111", new Date("2026-11-10T13:00:00Z"));
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(spikeSourceId("11111111-1111-4111-8111-111111111111", new Date("2026-11-10T13:00:00Z"))).toBe(id);
    expect(spikeSourceId("11111111-1111-4111-8111-111111111111", new Date("2026-11-10T14:00:00Z"))).not.toBe(id);
  });
});
