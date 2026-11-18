import { readFileSync } from "node:fs";
import path from "node:path";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { applyHeaderRule, buildRule, inspectZone, removeHeaderRule, ruleRef, setCloudflareFetch } from "@/server/edge/cloudflare";

// A fake Cloudflare that keeps the zone's response-header ruleset, so the tests check what really ends up there.
const ZONE = "a".repeat(32);
const TOKEN = "t".repeat(40);
const ASSET = "0b9d5c1e-2f3a-4b5c-8d7e-9f0a1b2c3d4e";
type Rule = { id: string; ref: string; expression?: string; action_parameters?: { headers: Record<string, { operation: string; value: string }> } };
let ruleset: { id: string; rules: Rule[] } | null = null;
const calls: string[] = [];
let n = 0;

async function fakeCf(url: string, init: RequestInit): Promise<Response> {
  const method = init.method ?? "GET";
  const p = url.replace("https://api.cloudflare.com/client/v4", "");
  calls.push(`${method} ${p}`);
  const ok = (result: unknown, status = 200) => new Response(JSON.stringify({ success: true, errors: [], result }), { status });
  const notFound = () => new Response(JSON.stringify({ success: false, errors: [{ code: 10003, message: "not found" }] }), { status: 404 });
  if ((init.headers as Record<string, string>).authorization !== `Bearer ${TOKEN}`) return new Response("{}", { status: 403 });
  const body = init.body ? JSON.parse(String(init.body)) : null;
  if (method === "GET" && p === `/zones/${ZONE}`) return ok({ name: "example.com" });
  const ep = `/zones/${ZONE}/rulesets/phases/http_response_headers_transform/entrypoint`;
  if (method === "GET" && p === ep) return ruleset ? ok(ruleset) : notFound();
  if (method === "PUT" && p === ep) {
    if (ruleset) throw new Error("PUT would replace the customer's existing rules");
    ruleset = { id: "rs1", rules: body.rules.map((r: Rule) => ({ ...r, id: `r${++n}` })) };
    return ok(ruleset);
  }
  const rules = `/zones/${ZONE}/rulesets/rs1/rules`;
  if (method === "POST" && p === rules) { ruleset!.rules.push({ ...body, id: `r${++n}` }); return ok(ruleset); }
  const m = p.match(/^\/zones\/[a-f0-9]{32}\/rulesets\/rs1\/rules\/(\w+)$/);
  if (m && method === "PATCH") { ruleset!.rules = ruleset!.rules.map((r) => (r.id === m[1] ? { ...body, id: r.id } : r)); return ok(ruleset); }
  if (m && method === "DELETE") { ruleset!.rules = ruleset!.rules.filter((r) => r.id !== m[1]); return ok(ruleset); }
  return notFound();
}

beforeEach(() => { ruleset = null; calls.length = 0; setCloudflareFetch(fakeCf); });
afterAll(() => setCloudflareFetch(null));

describe("Cloudflare header fixes", () => {
  it("only matches the site's own host and only sets the chosen headers", () => {
    const r = buildRule(ASSET, "Shop.Example.com", ["nosniff", "referrer"]);
    expect(r.expression).toBe('(http.host eq "shop.example.com")');
    expect(Object.keys(r.action_parameters.headers)).toEqual(["X-Content-Type-Options", "Referrer-Policy"]);
    expect(() => buildRule(ASSET, 'x.com" or true or "', ["nosniff"])).toThrow();
    expect(() => buildRule(ASSET, "example.com", [])).toThrow(/at least one/);
  });

  it("refuses a zone that does not hold the site", async () => {
    expect(await inspectZone(TOKEN, ZONE, "www.example.com")).toEqual({ zoneName: "example.com" });
    await expect(inspectZone(TOKEN, ZONE, "other.org")).rejects.toMatchObject({ code: "cloudflare_zone_mismatch" });
    await expect(inspectZone(TOKEN, ZONE, "notexample.com")).rejects.toMatchObject({ code: "cloudflare_zone_mismatch" });
    await expect(inspectZone("x".repeat(40), ZONE, "example.com")).rejects.toMatchObject({ code: "cloudflare_forbidden" });
  });

  it("creates the entrypoint only when the zone has no header rules", async () => {
    await applyHeaderRule(TOKEN, ZONE, ASSET, "example.com", ["hsts"]);
    expect(ruleset!.rules).toHaveLength(1);
    expect(ruleset!.rules[0].ref).toBe(ruleRef(ASSET));
    expect(calls).toContain(`PUT /zones/${ZONE}/rulesets/phases/http_response_headers_transform/entrypoint`);
  });

  it("adds, updates and removes only its own rule next to the customer's rules", async () => {
    ruleset = { id: "rs1", rules: [{ id: "theirs", ref: "customer_rule", expression: "true" }] };
    await applyHeaderRule(TOKEN, ZONE, ASSET, "example.com", ["nosniff"]);
    expect(ruleset!.rules.map((r) => r.ref)).toEqual(["customer_rule", ruleRef(ASSET)]);
    await applyHeaderRule(TOKEN, ZONE, ASSET, "example.com", ["nosniff", "frame"]);
    expect(ruleset!.rules).toHaveLength(2);
    expect(Object.keys(ruleset!.rules[1].action_parameters!.headers)).toEqual(["X-Content-Type-Options", "X-Frame-Options"]);
    expect(calls.filter((c) => c.startsWith("PUT"))).toHaveLength(0);
    expect(await removeHeaderRule(TOKEN, ZONE, ASSET)).toBe(true);
    expect(ruleset!.rules.map((r) => r.id)).toEqual(["theirs"]);
    expect(await removeHeaderRule(TOKEN, ZONE, ASSET)).toBe(false);
    expect(calls.some((c) => c.includes("/rules/theirs"))).toBe(false);
  });

  it("never touches a rule by any id but its own (static)", () => {
    const src = readFileSync(path.join(__dirname, "../../src/server/edge/cloudflare.ts"), "utf8");
    // Every rule-level call uses mine.id; PUT only appears in the no-entrypoint branch.
    for (const m of src.matchAll(/\/rules\/\$\{([^}]+)\}/g)) expect(m[1]).toBe("mine.id");
    expect(src.match(/"PUT"/g)).toHaveLength(1);
    expect(src).toMatch(/if \(!ep\) \{[\s\S]{0,200}"PUT"/);
  });
});
