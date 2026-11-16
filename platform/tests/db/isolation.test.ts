import { randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { assets, users } from "@/server/db/schema";
import { verifyChain } from "@/server/audit/audit";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal } from "@/server/principal";
import { checkVerification } from "@/server/assets/assets";
import type { SessionInfo } from "@/server/auth/session";

// Needs a migrated database reachable as the runtime role (ruya_app, NOBYPASSRLS). Skipped otherwise.
const run = process.env.DATABASE_URL ? describe : describe.skip;

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

run("tenant isolation and audit (database)", () => {
  it("runs as a role that cannot bypass row-level security", async () => {
    const r = await db.execute<{ bypass: boolean; superuser: boolean }>(
      sql`SELECT rolbypassrls AS bypass, rolsuper AS superuser FROM pg_roles WHERE rolname = current_user`);
    expect(r.rows[0]).toEqual({ bypass: false, superuser: false });
  });

  it("never shows one organization's assets to another", async () => {
    const alice = await newUser(), bob = await newUser();
    const orgA = await createOrg(alice, { name: `A ${randomUUID().slice(0, 8)}` });
    const orgB = await createOrg(bob, { name: `B ${randomUUID().slice(0, 8)}` });
    const [a] = await withOrg(orgA.id, (tx) => tx.insert(assets).values({
      orgId: orgA.id, host: `rls-${randomUUID().slice(0, 8)}.example.com`, displayName: "a", environment: "production", createdBy: alice.userId,
    }).returning());

    const seenByA = await withOrg(orgA.id, (tx) => tx.select({ id: assets.id }).from(assets));
    const seenByB = await withOrg(orgB.id, (tx) => tx.select({ id: assets.id }).from(assets));
    const seenByNone = await withOrg(null, (tx) => tx.select({ id: assets.id }).from(assets));
    expect(seenByA.map((r) => r.id)).toContain(a.id);
    expect(seenByB.map((r) => r.id)).not.toContain(a.id);
    expect(seenByNone).toEqual([]);

    // Writing a row tagged with another org is refused by the policy's WITH CHECK.
    await expect(withOrg(orgB.id, (tx) => tx.insert(assets).values({
      orgId: orgA.id, host: `x-${randomUUID().slice(0, 8)}.example.com`, displayName: "x", environment: "production", createdBy: bob.userId,
    }))).rejects.toThrow();

    expect(await loadPrincipal(bob, orgA.id)).toBeNull();
  });

  it("keeps the audit log append-only with an intact hash chain", async () => {
    const alice = await newUser();
    const org = await createOrg(alice, { name: `Audit ${randomUUID().slice(0, 8)}` });
    const chain = await withOrg(org.id, (tx) => verifyChain(tx));
    expect(chain.firstBrokenSeq).toBeNull();
    expect(chain.checked).toBeGreaterThan(0);
    await expect(withOrg(org.id, (tx) => tx.execute(sql`UPDATE audit_events SET action = 'tampered'`))).rejects.toThrow();
    await expect(withOrg(org.id, (tx) => tx.execute(sql`DELETE FROM audit_events`))).rejects.toThrow();
  });

  it("refuses and audits ownership checks while the scanning kill switch is engaged", async () => {
    const alice = await newUser();
    const org = await createOrg(alice, { name: `Kill ${randomUUID().slice(0, 8)}` });
    const ctx = (await loadPrincipal(alice, org.id))!;
    const vid = randomUUID();
    await expect(checkVerification({ ...ctx, org: { ...ctx.org, killScanning: true } }, vid))
      .rejects.toMatchObject({ code: "kill_switch_engaged" });
    const ev = await withOrg(org.id, (tx) => tx.execute<{ outcome: string; reason: string }>(
      sql`SELECT outcome, reason FROM audit_events WHERE action = 'authz.denied' AND target_id = ${vid}`));
    expect(ev.rows).toEqual([{ outcome: "denied", reason: "kill_switch_engaged" }]);
  });
});
