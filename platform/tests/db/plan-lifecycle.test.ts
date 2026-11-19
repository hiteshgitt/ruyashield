import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { db, withOrg } from "@/server/db/client";
import { orgs, users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal } from "@/server/principal";
import { startTrial, sweepOrgPlans } from "@/server/plans/lifecycle";
import { listOrgPlans, setOrgPlan } from "@/server/operator/plans";
import type { SessionInfo } from "@/server/auth/session";

const run = process.env.DATABASE_URL ? describe : describe.skip;

async function newUser(): Promise<SessionInfo> {
  const email = `t-${randomUUID()}@ruya-tests.invalid`;
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

async function withTrialsOn<T>(f: () => Promise<T>): Promise<T> {
  const prev = { plan: process.env.RUYA_DEFAULT_ORG_PLAN, trial: process.env.RUYA_ORG_TRIAL };
  delete process.env.RUYA_DEFAULT_ORG_PLAN;
  delete process.env.RUYA_ORG_TRIAL;
  try { return await f(); } finally { process.env.RUYA_DEFAULT_ORG_PLAN = prev.plan; process.env.RUYA_ORG_TRIAL = prev.trial; }
}

const orgRow = (id: string) => withOrg(id, (tx) => tx.select().from(orgs).where(eq(orgs.id, id))).then((r) => r[0]);

run("Pro trial (database)", () => {
  it("the first organization a person creates gets 14 days of Pro; the second starts on Free", async () => {
    const user = await newUser();
    const first = await withTrialsOn(() => createOrg(user, { name: `Trial ${randomUUID().slice(0, 8)}` }));
    const second = await withTrialsOn(() => createOrg(user, { name: `Trial ${randomUUID().slice(0, 8)}` }));
    const a = await orgRow(first.id);
    expect(a).toMatchObject({ plan: "pro", planSource: "trial" });
    expect(Math.round((a.trialEndsAt!.getTime() - Date.now()) / 86_400_000)).toBe(14);
    expect(await orgRow(second.id)).toMatchObject({ plan: "free", planSource: null, trialEndsAt: null });
    // The trial was this person's one trial, so the Free organization cannot start another.
    await expect(startTrial((await loadPrincipal(user, second.id))!)).rejects.toMatchObject({ code: "trial_used" });
  });

  it("a finished trial goes back to Free on the next sweep; a reminder is recorded before that", async () => {
    const user = await newUser();
    const o = await withTrialsOn(() => createOrg(user, { name: `Trial ${randomUUID().slice(0, 8)}` }));
    await withOrg(o.id, (tx) => tx.update(orgs).set({ trialEndsAt: new Date(Date.now() + 2 * 86_400_000) }).where(eq(orgs.id, o.id)));
    await sweepOrgPlans();
    expect(await orgRow(o.id)).toMatchObject({ plan: "pro", trialReminded: 3 });
    await withOrg(o.id, (tx) => tx.update(orgs).set({ trialEndsAt: new Date(Date.now() - 60_000) }).where(eq(orgs.id, o.id)));
    await sweepOrgPlans();
    expect(await orgRow(o.id)).toMatchObject({ plan: "free", planSource: null });
  });

  it("an existing Free organization can start the trial once, from an admin who never had one", async () => {
    const user = await newUser();
    const o = await createOrg(user, { name: `Free ${randomUUID().slice(0, 8)}` }); // trials off in tests by default
    const prev = process.env.RUYA_DEFAULT_ORG_PLAN;
    delete process.env.RUYA_DEFAULT_ORG_PLAN;
    try {
      await withOrg(o.id, (tx) => tx.update(orgs).set({ plan: "free", planSource: null }).where(eq(orgs.id, o.id)));
      const ctx = (await loadPrincipal(user, o.id))!;
      const r = await startTrial(ctx);
      expect(r.endsAt.getTime()).toBeGreaterThan(Date.now());
      expect(await orgRow(o.id)).toMatchObject({ plan: "pro", planSource: "trial" });
    } finally {
      process.env.RUYA_DEFAULT_ORG_PLAN = prev;
    }
  });

  it("the operator console shows a trial, and keeping Pro makes it manual so the sweep never ends it", async () => {
    const user = await newUser();
    const o = await withTrialsOn(() => createOrg(user, { name: `Keep ${randomUUID().slice(0, 8)}` }));
    const opEmail = `op-${randomUUID()}@ruya-tests.invalid`;
    const operator = { ...(await newUser()), email: opEmail };
    const prev = process.env.RUYA_OPERATOR_EMAILS;
    process.env.RUYA_OPERATOR_EMAILS = opEmail;
    try {
      expect((await listOrgPlans(operator)).find((x) => x.id === o.id)).toMatchObject({ plan: "pro", planSource: "trial" });
      await setOrgPlan(operator, { orgSlug: o.slug, plan: "pro" });
      expect(await orgRow(o.id)).toMatchObject({ plan: "pro", planSource: "manual" });
      await withOrg(o.id, (tx) => tx.update(orgs).set({ trialEndsAt: new Date(Date.now() - 60_000) }).where(eq(orgs.id, o.id)));
      await sweepOrgPlans();
      expect(await orgRow(o.id)).toMatchObject({ plan: "pro", planSource: "manual" });
    } finally {
      process.env.RUYA_OPERATOR_EMAILS = prev;
    }
  });
});
