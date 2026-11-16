import { randomUUID } from "node:crypto";
import { describe, expect, it } from "vitest";
import { db } from "@/server/db/client";
import { users } from "@/server/db/schema";
import { createOrg } from "@/server/orgs/orgs";
import { loadPrincipal } from "@/server/principal";
import type { SessionInfo } from "@/server/auth/session";
import { generateReport } from "@/server/reports/reports";
import { listOrgPlans, setOrgPlan } from "@/server/operator/plans";

// Needs a migrated database reachable as the runtime role (ruya_app, NOBYPASSRLS). Skipped otherwise.
const run = process.env.DATABASE_URL ? describe : describe.skip;

async function newUser(email = `t-${randomUUID()}@ruya-tests.invalid`): Promise<SessionInfo> {
  const [u] = await db.insert(users).values({ email, displayName: "Test", idpIssuer: "test", idpSubject: email }).returning();
  return { idHash: "x", userId: u.id, email, displayName: "Test", activeOrgId: null, mfa: true, amr: ["mfa"], authTime: new Date() };
}

run("organization plans (database)", () => {
  it("new organizations start on Free, and Free cannot generate reports", async () => {
    const user = await newUser();
    const prev = process.env.RUYA_DEFAULT_ORG_PLAN;
    delete process.env.RUYA_DEFAULT_ORG_PLAN;
    const org = await createOrg(user, { name: `Plan ${randomUUID().slice(0, 8)}` }).finally(() => { process.env.RUYA_DEFAULT_ORG_PLAN = prev; });
    const ctx = (await loadPrincipal(user, org.id))!;
    expect(ctx.org.plan).toBe("free");
    await expect(generateReport(ctx, { format: "csv" })).rejects.toMatchObject({ status: 402, code: "pro_required" });
  });

  it("an operator switches a plan; others cannot", async () => {
    const owner = await newUser();
    const prevPlan = process.env.RUYA_DEFAULT_ORG_PLAN;
    delete process.env.RUYA_DEFAULT_ORG_PLAN;
    const org = await createOrg(owner, { name: `Plan ${randomUUID().slice(0, 8)}` }).finally(() => { process.env.RUYA_DEFAULT_ORG_PLAN = prevPlan; });
    await expect(setOrgPlan(owner, { orgSlug: org.slug, plan: "pro" })).rejects.toMatchObject({ status: 403 });

    const opEmail = `op-${randomUUID()}@ruya-tests.invalid`;
    const operator = await newUser(opEmail);
    const prev = process.env.RUYA_OPERATOR_EMAILS;
    process.env.RUYA_OPERATOR_EMAILS = opEmail;
    try {
      const listed = await listOrgPlans(operator);
      expect(listed.find((o) => o.id === org.id)).toMatchObject({ plan: "free", members: 1 });
      await setOrgPlan(operator, { orgSlug: org.slug, plan: "pro" });
      const ctx = (await loadPrincipal(owner, org.id))!;
      expect(ctx.org.plan).toBe("pro");
      await expect(generateReport(ctx, { format: "csv" })).resolves.toBeTruthy();
      await expect(setOrgPlan(operator, { orgSlug: org.slug, plan: "gold" })).rejects.toMatchObject({ status: 422 });
    } finally {
      process.env.RUYA_OPERATOR_EMAILS = prev;
    }
  });
});
