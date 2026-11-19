import { eq, sql } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg } from "../db/client";
import { orgs, users } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError } from "../errors";
import type { SessionInfo } from "../auth/session";
import { notifyAdmins } from "../notifications/notifications";
import { isOperator, requireOperator } from "./breakglass";
import type { OrgFlags, Principal } from "../policy/policy";
import { grantFor } from "../policy/matrix";
import { appLink, brandedEmail, sendMail } from "../mail/mail";

// Organization plans, switched by an operator until online payment exists. Every change is written to the
// organization's own audit chain and announced to its admins.

export const ORG_PLANS = ["free", "pro"] as const;
export type OrgPlan = (typeof ORG_PLANS)[number];

export async function listOrgPlans(s: SessionInfo) {
  if (!isOperator(s.email)) throw new AppError(403, "forbidden");
  const r = await db.execute<{ id: string; name: string; slug: string; plan: string; created_at: Date; members: string; pro_requested_at: Date | null; plan_source: string | null; trial_ends_at: Date | null }>(
    sql`SELECT id, name, slug, plan, created_at, members, pro_requested_at, plan_source, trial_ends_at FROM operator_org_list()`);
  return r.rows.map((o) => ({
    id: o.id, name: o.name, slug: o.slug, plan: o.plan, createdAt: new Date(o.created_at), members: Number(o.members),
    proRequestedAt: o.pro_requested_at ? new Date(o.pro_requested_at) : null,
    planSource: (o.plan_source ?? null) as "manual" | "trial" | "ruyalab" | null,
    trialEndsAt: o.trial_ends_at ? new Date(o.trial_ends_at) : null,
  }));
}

const setInput = z.object({ orgSlug: z.string().trim().min(1).max(80), plan: z.enum(ORG_PLANS) });

export async function setOrgPlan(s: SessionInfo, input: unknown, meta: { ip?: string | null; requestId?: string | null } = {}, now = new Date()) {
  requireOperator(s, now);
  const v = setInput.safeParse(input);
  if (!v.success) throw new AppError(422, "validation_failed", "Choose an organization and a plan.");
  const o = (await db.execute<{ id: string; name: string }>(sql`SELECT id, name FROM operator_org_lookup(${v.data.orgSlug})`)).rows[0];
  if (!o) throw new AppError(404, "not_found", "No organization with that slug.");
  await withOrg(o.id, async (tx) => {
    const was = (await tx.select({ plan: orgs.plan, source: orgs.planSource }).from(orgs).where(eq(orgs.id, o.id)))[0];
    const before = was?.plan;
    // Switching a trial or Ruya Lab Pro organization to Pro still makes it manual (it then never ends on its own).
    if (before === v.data.plan && (v.data.plan === "free" || was?.source === "manual")) return;
    // An operator's choice is manual: never ended by the trial sweep or the Ruya Lab sync.
    await tx.update(orgs).set({ plan: v.data.plan, planSource: v.data.plan === "pro" ? "manual" : null, ...(v.data.plan === "pro" ? { proRequestedAt: null, proRequestedBy: null } : {}) }).where(eq(orgs.id, o.id));
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

/** An org admin asks for Pro from the plan page: recorded on the org, audited, and emailed to the operators. */
export async function requestPro(c: { principal: Principal; org: OrgFlags & { id: string; name?: string } }, meta: { ip?: string | null; requestId?: string | null } = {}) {
  // A trial counts as Free here: asking during the trial keeps Pro after it ends.
  const source = (await withOrg(c.org.id, (tx) => tx.select({ s: orgs.planSource }).from(orgs).where(eq(orgs.id, c.org.id))))[0]?.s;
  if (c.org.plan === "pro" && source !== "trial") throw new AppError(409, "already_pro", "This organization is already on Pro.");
  // Org admins only; asking for Pro changes nothing by itself, so it does not need a fresh MFA step-up.
  if (grantFor(c.principal.role, "org.settings.edit") === "N" || c.principal.tokenScopes || c.principal.breakGlassId) throw new AppError(403, "forbidden");
  const first = await withOrg(c.org.id, async (tx) => {
    const before = (await tx.select({ at: orgs.proRequestedAt }).from(orgs).where(eq(orgs.id, c.org.id)))[0]?.at ?? null;
    await tx.update(orgs).set({ proRequestedAt: new Date(), proRequestedBy: c.principal.userId }).where(eq(orgs.id, c.org.id));
    await audit(tx, { actor: { type: "user", id: c.principal.userId, ip: meta.ip }, action: "org.pro_requested", target: { type: "org", id: c.org.id }, requestId: meta.requestId });
    return !before;
  });
  const operators = (process.env.RUYA_OPERATOR_EMAILS ?? "").split(",").map((e) => e.trim()).filter(Boolean);
  if (operators.length) {
    const who = (await db.select({ email: users.email }).from(users).where(eq(users.id, c.principal.userId)))[0]?.email ?? "an admin";
    await sendMail({
      to: operators.join(","), subject: `Pro requested: ${c.org.name ?? c.org.id}`,
      text: `${who} asked to upgrade ${c.org.name ?? c.org.id} to RuyaShield Pro.\nSwitch it on the operator console: ${appLink("/operator")}`,
      html: brandedEmail({
        preheader: `${who} asked for Pro.`, title: "Pro requested",
        paragraphs: [`${who} asked to upgrade ${c.org.name ?? "an organization"} to RuyaShield Pro.`, "Switch the plan on the operator console. The organization's admins are notified when it changes."],
        button: { label: "Open the operator console", href: appLink("/operator") },
      }),
    }).catch(() => undefined);
  }
  return { first };
}
