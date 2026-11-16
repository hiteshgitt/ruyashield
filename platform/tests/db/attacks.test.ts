import { randomUUID } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, attackEvents, users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal } from "@/server/principal";
import type { SessionInfo } from "@/server/auth/session";
import { createLogAgentSource, disableSource, getStats, ingest, listSources } from "@/server/attacks/attacks";
import { geoFrom } from "@/server/attacks/geoip";

// Needs a migrated database reachable as the runtime role (ruya_app, NOBYPASSRLS). Skipped otherwise.
const run = process.env.DATABASE_URL ? describe : describe.skip;
const noGeo = geoFrom(null, null);
const MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const clf = (d: Date) => {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getUTCDate())}/${MON[d.getUTCMonth()]}/${d.getUTCFullYear()}:${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
};
const line = (path: string, status: number, ip = "203.0.113.9", at = new Date(Date.now() - 60_000)) =>
  `${ip} - - [${clf(at)}] "GET ${path} HTTP/1.1" ${status} 100 "-" "Mozilla/5.0"`;

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

async function orgWithAsset(status: "verified" | "unverified" = "verified") {
  const user = await newUser();
  const org = await createOrg(user, { name: `AT ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  const [asset] = await withOrg(org.id, (tx) => tx.insert(assets).values({
    orgId: org.id, host: `at-${randomUUID().slice(0, 8)}.example.com`, displayName: "site", environment: "production", createdBy: user.userId, status,
  }).returning());
  return { user, org, ctx, asset };
}

run("attack monitoring", () => {
  it("stores only suspicious events, without query strings, idempotently", async () => {
    const { ctx, asset } = await orgWithAsset();
    const before = await getStats(ctx, { assetId: asset.id, days: 1 });
    expect(before.coverage).toBe("none");
    expect(before.total).toBe(0);

    const src = await createLogAgentSource(ctx, { assetId: asset.id, name: "web-1" });
    expect(src.token).toMatch(/^rs_/);
    const lines = [line("/.env?k=secret", 404), line("/item?id=1%20UNION%20SELECT%20pw", 500, "198.51.100.3"), line("/about?utm=x", 200), "not a log line"];
    const r1 = await ingest(src.token, lines, new Date(), noGeo);
    expect(r1).toEqual({ received: 4, stored: 2, suspicious: 2, unparsed: 1 });

    const rows = await withOrg(ctx.org.id, (tx) => tx.select().from(attackEvents).where(eq(attackEvents.assetId, asset.id)));
    expect(rows).toHaveLength(2);
    expect(rows.every((r) => !r.path?.includes("?"))).toBe(true);
    expect(rows.map((r) => r.attackType).sort()).toEqual(["sensitive_probe", "sqli"]);

    const r2 = await ingest(src.token, lines, new Date(), noGeo);
    expect(r2.stored).toBe(0);

    const after = await getStats(ctx, { assetId: asset.id, days: 1 });
    expect(after.coverage).toBe("full");
    expect(after.total).toBe(2);
    expect(after.uniqueIps).toBe(2);
    const [s] = await listSources(ctx);
    expect(s.status).toBe("active");
  });

  it("rejects bad, disabled and lapsed-asset tokens", async () => {
    await expect(ingest("rs_" + "x".repeat(30), [line("/.env", 404)], new Date(), noGeo)).rejects.toMatchObject({ status: 401 });
    await expect(ingest("nope", [], new Date(), noGeo)).rejects.toMatchObject({ status: 401 });

    const { ctx, asset } = await orgWithAsset();
    const src = await createLogAgentSource(ctx, { assetId: asset.id, name: "web-1" });
    await withOrg(ctx.org.id, (tx) => tx.update(assets).set({ status: "lapsed" }).where(eq(assets.id, asset.id)));
    await expect(ingest(src.token, [line("/.env", 404)], new Date(), noGeo)).rejects.toMatchObject({ status: 403 });
    await withOrg(ctx.org.id, (tx) => tx.update(assets).set({ status: "verified" }).where(eq(assets.id, asset.id)));

    await disableSource(ctx, src.id);
    await expect(ingest(src.token, [line("/.env", 404)], new Date(), noGeo)).rejects.toMatchObject({ status: 401 });
  });

  it("refuses sources on unverified assets", async () => {
    const { ctx, asset } = await orgWithAsset("unverified");
    await expect(createLogAgentSource(ctx, { assetId: asset.id, name: "x" })).rejects.toMatchObject({ status: 422 });
  });

  it("keeps each org's events and sources private", async () => {
    const a = await orgWithAsset();
    const b = await orgWithAsset();
    const src = await createLogAgentSource(a.ctx, { assetId: a.asset.id, name: "a" });
    await ingest(src.token, [line("/.git/config", 403)], new Date(), noGeo);
    const sb = await getStats(b.ctx, { days: 1 });
    expect(sb.total).toBe(0);
    expect(sb.coverage).toBe("none");
    expect(await listSources(b.ctx)).toHaveLength(0);
    const leaked = await withOrg(b.ctx.org.id, (tx) => tx.select().from(attackEvents).where(eq(attackEvents.orgId, a.ctx.org.id)));
    expect(leaked).toHaveLength(0);
  });

  it("purges events older than 90 days", async () => {
    const { ctx, asset } = await orgWithAsset();
    const src = await createLogAgentSource(ctx, { assetId: asset.id, name: "a" });
    const base = { orgId: ctx.org.id, assetId: asset.id, sourceId: src.id, ip: "203.0.113.1", action: "logged", attackType: "sqli" };
    await withOrg(ctx.org.id, (tx) => tx.insert(attackEvents).values([
      { ...base, occurredAt: new Date(Date.now() - 91 * 86_400_000), dedupeKey: `old-${randomUUID()}` },
      { ...base, occurredAt: new Date(Date.now() - 86_400_000), dedupeKey: `new-${randomUUID()}` },
    ]));
    await db.execute(sql`SELECT * FROM attack_events_purge()`);
    const left = await withOrg(ctx.org.id, (tx) => tx.select().from(attackEvents).where(eq(attackEvents.assetId, asset.id)));
    expect(left).toHaveLength(1);
    expect(left[0].dedupeKey.startsWith("new-")).toBe(true);
  });
});
