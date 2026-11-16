import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, users, webmonitorWatchedHosts } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal } from "@/server/principal";
import type { SessionInfo } from "@/server/auth/session";
import { resolveApiToken, revokeApiToken } from "@/server/tokens/tokens";
import { hostPosture } from "@/server/webmonitor/posture";
import { createWebMonitorToken, webmonitorConnections, webmonitorCoverage, WATCH_KEEP_DAYS } from "@/server/webmonitor/watch";

// Needs a migrated database reachable as the runtime role (ruya_app, NOBYPASSRLS). Skipped otherwise.
const run = process.env.DATABASE_URL ? describe : describe.skip;

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

async function orgWith(hosts: string[]) {
  const user = await newUser();
  const org = await createOrg(user, { name: `WMW ${randomUUID().slice(0, 8)}` });
  const ctx = (await loadPrincipal(user, org.id))!;
  if (hosts.length) await withOrg(org.id, (tx) => tx.insert(assets).values(hosts.map((host) => ({
    orgId: org.id, host, displayName: host, environment: "production" as const, createdBy: user.userId, status: "verified" as const,
  }))));
  return { ctx, org };
}

run("WebMonitor uptime coverage (database)", () => {
  it("records the hosts a WebMonitor token asks about and reports coverage", async () => {
    const id = randomUUID().slice(0, 8);
    const watched = `wmw-${id}.example.com`, unwatched = `wmw2-${id}.example.com`, extra = `wmw3-${id}.example.com`;
    const { ctx } = await orgWith([watched, unwatched]);
    const before = await webmonitorCoverage(ctx);
    expect(before.lastSeenAt).toBeNull();
    expect(before.assets.every((a) => !a.watched)).toBe(true);

    const t = await createWebMonitorToken(ctx);
    const tokenCtx = (await resolveApiToken(t.token))!;
    expect(tokenCtx.principal.tokenScopes).toEqual(["assets:read", "findings:read"]);
    // WebMonitor sends both forms of each site it monitors.
    await hostPosture(tokenCtx, [watched, `www.${watched}`, extra, `www.${extra}`]);

    const after = await webmonitorCoverage(ctx);
    expect(after.lastSeenAt).not.toBeNull();
    expect(after.assets.find((a) => a.host === watched)?.watched).toBe(true);
    expect(after.assets.find((a) => a.host === unwatched)?.watched).toBe(false);
    expect(after.notInRuyaShield).toEqual([extra]);

    const conns = await webmonitorConnections(ctx);
    expect(conns).toHaveLength(1);
    expect(conns[0]).toMatchObject({ id: t.id, name: "WebMonitor", sites: 2 });

    await revokeApiToken(ctx, t.id);
    expect(await webmonitorConnections(ctx)).toHaveLength(0);
  });

  it("does not record anything for a signed-in person, and keeps orgs apart", async () => {
    const id = randomUUID().slice(0, 8);
    const a = await orgWith([`wma-${id}.example.com`]);
    const b = await orgWith([`wmb-${id}.example.com`]);
    await hostPosture(a.ctx, [`wma-${id}.example.com`]);
    expect((await webmonitorCoverage(a.ctx)).lastSeenAt).toBeNull();

    const tb = await createWebMonitorToken(b.ctx);
    await hostPosture((await resolveApiToken(tb.token))!, [`wma-${id}.example.com`]);
    expect((await webmonitorCoverage(a.ctx)).lastSeenAt).toBeNull();
    expect((await webmonitorCoverage(b.ctx)).notInRuyaShield).toEqual([`wma-${id}.example.com`]);
  });

  it("deletes sightings older than the keep window on the next call", async () => {
    const id = randomUUID().slice(0, 8);
    const { ctx, org } = await orgWith([]);
    const t = await createWebMonitorToken(ctx);
    const old = new Date(Date.now() - (WATCH_KEEP_DAYS + 1) * 86_400_000);
    await withOrg(org.id, (tx) => tx.insert(webmonitorWatchedHosts).values({ orgId: org.id, host: `old-${id}.example.com`, tokenId: t.id, firstSeenAt: old, lastSeenAt: old }));
    await hostPosture((await resolveApiToken(t.token))!, [`new-${id}.example.com`]);
    const rows = await withOrg(org.id, (tx) => tx.select().from(webmonitorWatchedHosts));
    expect(rows.map((r) => r.host)).toEqual([`new-${id}.example.com`]);
  });
});
