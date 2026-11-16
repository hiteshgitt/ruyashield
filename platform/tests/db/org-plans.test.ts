import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
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

run("Free plan limits (database)", () => {
  it("lists only the top findings, refuses the rest, evidence and attacks on Free", async () => {
    const { assets: assetsT, findings: findingsT } = await import("@/server/db/schema");
    const { withOrg } = await import("@/server/db/client");
    const { listFindings, getFinding, getEvidence, FREE_FINDING_LIMIT } = await import("@/server/findings/findings");
    const { getStats } = await import("@/server/attacks/attacks");
    const user = await newUser();
    const prev = process.env.RUYA_DEFAULT_ORG_PLAN;
    delete process.env.RUYA_DEFAULT_ORG_PLAN;
    const org = await createOrg(user, { name: `Free ${randomUUID().slice(0, 8)}` }).finally(() => { process.env.RUYA_DEFAULT_ORG_PLAN = prev; });
    const ctx = (await loadPrincipal(user, org.id))!;
    const [a] = await withOrg(org.id, (tx) => tx.insert(assetsT).values({ orgId: org.id, host: `free-${randomUUID().slice(0, 8)}.example.com`, displayName: "x", environment: "production", createdBy: user.userId, status: "verified" }).returning());
    const { launchAssessment, runAssessment } = await import("@/server/assessments/assessments");
    const { sql } = await import("drizzle-orm");
    const { assessment } = await launchAssessment(ctx, { assetId: a.id, idempotencyKey: `k-${randomUUID()}`, checkIds: ["http.security_headers@1"] });
    const job = await withOrg(org.id, (tx) => tx.execute<{ payload: { assessmentId: string; token: string } }>(sql`SELECT payload FROM outbox WHERE business_key = ${`assessment:${assessment.id}:1`}`));
    const many = Array.from({ length: FREE_FINDING_LIMIT + 3 }, (_, i) => ({
      issueKey: `k${i}`, title: `Finding ${i}`, severity: i === 0 ? "high" as const : "low" as const, location: `https://${a.host}/`, evidence: {}, remediation: "Fix it.",
    }));
    await runAssessment(org.id, job.rows[0].payload, { adapters: new Map([["http.security_headers@1", { id: "http.security_headers@1", checkKey: "http.security_headers", run: async () => ({ status: "ok" as const, findings: many, evidence: {} }) }]]), minIntervalMs: 0 });
    const list = await listFindings(ctx, {});
    expect(list.items).toHaveLength(FREE_FINDING_LIMIT);
    expect(list.lockedCount).toBe(3);
    expect(Object.values(list.bySeverity).reduce((x, y) => x + y, 0)).toBe(FREE_FINDING_LIMIT + 3);
    const shown = new Set(list.items.map((f) => f.id));
    const all = await withOrg(org.id, (tx) => tx.select({ id: findingsT.id }).from(findingsT).where(eq(findingsT.orgId, org.id)));
    const hidden = all.find((r) => !shown.has(r.id))!;
    await expect(getFinding(ctx, hidden.id)).rejects.toMatchObject({ status: 402, code: "pro_required" });
    await expect(getFinding(ctx, list.items[0].id)).resolves.toBeTruthy();
    await expect(getEvidence(ctx, randomUUID())).rejects.toMatchObject({ status: 402 });
    await expect(getStats(ctx)).rejects.toMatchObject({ status: 402 });
  });
});
