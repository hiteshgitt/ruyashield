import { randomUUID } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, assetSuggestions, ctCache, findings, users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal, type LoadedPrincipal } from "@/server/principal";
import type { SessionInfo } from "@/server/auth/session";
import { launchAssessment, runAssessment } from "@/server/assessments/assessments";
import { createCtAdapter } from "@/server/assessments/ct";
import type { FetchLike } from "@/server/assessments/deps";
import { transition } from "@/server/findings/findings";
import { requestVerification, runVerification } from "@/server/verification/verification";
import { addSuggestion, dismissSuggestion, listSuggestions } from "@/server/assets/suggestions";

// discovery.ct end to end: a certificate from a CA outside CAA becomes a finding, CT subdomains become suggested
// assets, fixing CAA and re-testing resolves the finding as verified, and the CT answer is cached in the database.
// CT APIs and DNS are faked; parsing and fallback are covered by tests/unit/ct.test.ts.
const run = process.env.DATABASE_URL ? describe : describe.skip;
const ID = "discovery.ct@1";

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

async function fixture() {
  const user = await newUser();
  const org = await createOrg(user, { name: `CT ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const host = `ct-${randomUUID().slice(0, 8)}.example.com`;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host, displayName: "site", environment: "production", createdBy: user.userId, status: "verified",
  }).returning());
  return { ctx, asset, host };
}

const crtsh = (host: string) => [
  { issuer_name: "C=US, O=Let's Encrypt, CN=R11", common_name: host, name_value: `${host}\nwww.${host}`, id: 1, not_before: "2026-01-01T00:00:00", not_after: "2099-01-01T00:00:00", serial_number: "01" },
  { issuer_name: "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA", common_name: `shop.${host}`, name_value: `shop.${host}\napi.${host}`, id: 2, not_before: "2026-01-01T00:00:00", not_after: "2099-01-01T00:00:00", serial_number: "02" },
];

function deps(host: string, caa: string[], calls: string[] = []) {
  const fetch: FetchLike = async (url) => { calls.push(url); return { ok: true, status: 200, text: async () => JSON.stringify(crtsh(host)) }; };
  return {
    adapters: new Map([[ID, createCtAdapter({ fetch, minSpacingMs: 0 })]]), minIntervalMs: 0,
    dns: { resolve: async (name: string) => (name === host ? caa : []) },
  };
}

async function scan(ctx: LoadedPrincipal, assetId: string, d: ReturnType<typeof deps>) {
  const { assessment } = await launchAssessment(ctx, { assetId, idempotencyKey: `k-${randomUUID()}`, checkIds: [ID] });
  const job = await withOrg(ctx.org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(
    sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
  await runAssessment(ctx.org.id, job.rows[0].payload, d);
  return assessment.id;
}
const expireCache = (host: string) => db.update(ctCache).set({ fetchedAt: new Date(Date.now() - 2 * 86400_000) }).where(eq(ctCache.domain, host));
const findingsOf = (orgId: string, assetId: string) => withOrg(orgId, (tx) => tx.select().from(findings).where(eq(findings.assetId, assetId)));

run("discovery.ct (database)", () => {
  it("raises an unknown-issuer finding, stores suggestions, and resolves as verified once CAA allows the CA", async () => {
    const { ctx, asset, host } = await fixture();
    const calls: string[] = [];
    await scan(ctx, asset.id, deps(host, ['0 issue "letsencrypt.org"'], calls));
    const [f] = await findingsOf(ctx.org.id, asset.id);
    expect(f).toMatchObject({ checkKey: "discovery.ct", issueKey: "unknown-issuer.digicert", severity: "low", status: "new", location: host });

    // Suggestions are stored for the org and the CT answer is cached globally.
    expect((await listSuggestions(ctx)).map((s) => s.host)).toEqual([`api.${host}`, `shop.${host}`, `www.${host}`]);
    const [c] = await db.select().from(ctCache).where(eq(ctCache.domain, host));
    expect(c).toMatchObject({ source: "crt.sh", truncated: false });
    expect(calls).toHaveLength(1);

    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: r } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    const fixed = deps(host, ['0 issue "letsencrypt.org"', '0 issue "digicert.com"'], calls);
    expect(await runVerification(ctx.org.id, { runId: r.id }, fixed)).toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).toBe("resolved_verified");
    // The re-test was served from the 24-hour cache.
    expect(calls).toHaveLength(1);
  });

  it("does not resolve the finding when CT is unavailable on re-test (fails closed)", async () => {
    const { ctx, asset, host } = await fixture();
    await scan(ctx, asset.id, deps(host, ['0 issue "letsencrypt.org"']));
    const [f] = await findingsOf(ctx.org.id, asset.id);
    await expireCache(host);
    for (const k of ["triage", "confirm", "start_remediation", "mark_fix_applied"]) await transition(ctx, f.id, k);
    const { run: r } = await requestVerification(ctx, f.id, { idempotencyKey: `v-${randomUUID()}` });
    const down: FetchLike = async () => ({ ok: false, status: 503, text: async () => "" });
    const out = await runVerification(ctx.org.id, { runId: r.id }, {
      adapters: new Map([[ID, createCtAdapter({ fetch: down, minSpacingMs: 0 })]]), minIntervalMs: 0,
      dns: { resolve: async (n: string) => (n === host ? ['0 issue "letsencrypt.org"', '0 issue "digicert.com"'] : []) },
    });
    expect(out).not.toBe("completed:verified");
    expect((await findingsOf(ctx.org.id, asset.id))[0].status).not.toBe("resolved_verified");
  });

  it("adds a suggestion as an unverified asset, dismisses another, and keeps decisions on re-scan", async () => {
    const { ctx, asset, host } = await fixture();
    await scan(ctx, asset.id, deps(host, []));
    const list = await listSuggestions(ctx);
    const api = list.find((s) => s.host === `api.${host}`)!;
    const shop = list.find((s) => s.host === `shop.${host}`)!;

    const added = await addSuggestion(ctx, api.id);
    expect(added).toMatchObject({ host: `api.${host}`, status: "unverified" });
    await dismissSuggestion(ctx, shop.id);
    await expect(dismissSuggestion(ctx, shop.id)).rejects.toMatchObject({ status: 409, code: "already_decided" });
    await expect(addSuggestion(ctx, shop.id)).rejects.toMatchObject({ status: 409, code: "already_decided" });

    await expireCache(host);
    await scan(ctx, asset.id, deps(host, []));
    expect((await listSuggestions(ctx)).map((s) => s.host)).toEqual([`www.${host}`]);
    const rows = await withOrg(ctx.org.id, (tx) => tx.select().from(assetSuggestions));
    expect(Object.fromEntries(rows.map((r) => [r.host.split(".")[0], r.status]))).toEqual({ api: "added", shop: "dismissed", www: "suggested" });
  });
});
