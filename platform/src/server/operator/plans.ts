import { eq, sql } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg } from "../db/client";
import { orgs } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError } from "../errors";
import type { SessionInfo } from "../auth/session";
import { notifyAdmins } from "../notifications/notifications";
import { isOperator, requireOperator } from "./breakglass";

// Organization plans, switched by an operator until online payment exists. Every change is written to the
// organization's own audit chain and announced to its admins.

export const ORG_PLANS = ["free", "pro"] as const;
export type OrgPlan = (typeof ORG_PLANS)[number];

export async function listOrgPlans(s: SessionInfo) {
  if (!isOperator(s.email)) throw new AppError(403, "forbidden");
  const r = await db.execute<{ id: string; name: string; slug: string; plan: string; created_at: Date; members: string }>(
    sql`SELECT id, name, slug, plan, created_at, members FROM operator_org_list()`);
  return r.rows.map((o) => ({ id: o.id, name: o.name, slug: o.slug, plan: o.plan, createdAt: new Date(o.created_at), members: Number(o.members) }));
}

const setInput = z.object({ orgSlug: z.string().trim().min(1).max(80), plan: z.enum(ORG_PLANS) });

export async function setOrgPlan(s: SessionInfo, input: unknown, meta: { ip?: string | null; requestId?: string | null } = {}, now = new Date()) {
  requireOperator(s, now);
  const v = setInput.safeParse(input);
  if (!v.success) throw new AppError(422, "validation_failed", "Choose an organization and a plan.");
  const o = (await db.execute<{ id: string; name: string }>(sql`SELECT id, name FROM operator_org_lookup(${v.data.orgSlug})`)).rows[0];
  if (!o) throw new AppError(404, "not_found", "No organization with that slug.");
  await withOrg(o.id, async (tx) => {
    const before = (await tx.select({ plan: orgs.plan }).from(orgs).where(eq(orgs.id, o.id)))[0]?.plan;
    if (before === v.data.plan) return;
    await tx.update(orgs).set({ plan: v.data.plan }).where(eq(orgs.id, o.id));
    await audit(tx, {
      actor: { type: "user", id: s.userId, ip: meta.ip }, action: "org.plan_changed", target: { type: "org", id: o.id },
      requestId: meta.requestId, details: { from: before, to: v.data.plan },
    });
    await notifyAdmins(tx, o.id, {
      kind: "plan_changed",
      title: v.data.plan === "pro"
        ? "Your organization is now on RuyaShield Pro: reports, evidence downloads, FixProof and audit exports are unlocked."
        : "Your organization is now on RuyaShield Free: reports and downloads are off; findings and assessments are unchanged.",
      link: "/dashboard", sourceId: o.id,
    });
  });
  return { name: o.name, plan: v.data.plan };
}
