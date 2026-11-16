import { randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { z } from "zod";
import { withOrg } from "../db/client";
import { orgs } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError } from "../errors";
import { authorize, type OrgFlags, type Principal } from "../policy/policy";
import { notifyAdmins } from "../notifications/notifications";

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };

/** Grace period before a requested deletion is finalized by the worker (finalize_org_deletions). */
export const DELETION_GRACE_DAYS = 30;
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
const reasonInput = z.string().trim().min(3, "Give a reason (at least 3 characters).").max(500);

export async function orgLifecycle(c: Ctx) {
  return withOrg(c.org.id, async (tx) => {
    const o = (await tx.select({ legalHold: orgs.legalHold, requestedAt: orgs.deletionRequestedAt, requestedBy: orgs.deletionRequestedBy })
      .from(orgs).where(eq(orgs.id, c.org.id)))[0];
    const finalizeAfter = o?.requestedAt ? new Date(o.requestedAt.getTime() + DELETION_GRACE_DAYS * 86_400_000) : null;
    return { legalHold: o?.legalHold ?? false, deletionRequestedAt: o?.requestedAt ?? null, finalizeAfter };
  });
}

/**
 * FR-059: an org admin (with step-up and the org's slug typed back) requests deletion. Access ends when the
 * worker finalizes it after the grace period; a legal hold blocks both the request and the finalization.
 * Finalization marks the org deleted; physical erasure of its rows is a manual, runbook-driven operator step.
 */
export async function requestOrgDeletion(c: Ctx & { org: { slug: string } }, input: { confirmSlug: string; reason: string }) {
  await authorize(c.principal, "org.delete", { type: "org", id: c.org.id }, c.org);
  const r = reasonInput.safeParse(input.reason);
  if (!r.success) throw new AppError(422, "validation_failed", r.error.issues[0].message);
  if (input.confirmSlug.trim() !== c.org.slug) throw new AppError(422, "validation_failed", "Type the organization's slug exactly to confirm.");
  await withOrg(c.org.id, async (tx) => {
    const o = (await tx.select().from(orgs).where(eq(orgs.id, c.org.id)).for("update"))[0];
    if (o.legalHold) throw new AppError(409, "legal_hold", "This organization is under legal hold and cannot be deleted.");
    if (o.deletionRequestedAt) throw new AppError(409, "already_requested", "Deletion is already requested.");
    await tx.update(orgs).set({ deletionRequestedAt: new Date(), deletionRequestedBy: c.principal.userId }).where(eq(orgs.id, c.org.id));
    await audit(tx, { actor: userActor(c.principal), action: "org.deletion_requested", target: { type: "org", id: c.org.id }, reason: r.data, requestId: c.principal.requestId, details: { graceDays: DELETION_GRACE_DAYS } });
    await notifyAdmins(tx, c.org.id, { kind: "org_deletion", title: `Organization deletion requested; it will be finalized after ${DELETION_GRACE_DAYS} days unless cancelled: ${r.data}`, link: "/settings/organization", sourceId: randomUUID() });
  });
}

export async function cancelOrgDeletion(c: Ctx, reason: string) {
  await authorize(c.principal, "org.delete", { type: "org", id: c.org.id }, c.org);
  const r = reasonInput.safeParse(reason);
  if (!r.success) throw new AppError(422, "validation_failed", r.error.issues[0].message);
  await withOrg(c.org.id, async (tx) => {
    const u = await tx.update(orgs).set({ deletionRequestedAt: null, deletionRequestedBy: null }).where(eq(orgs.id, c.org.id)).returning({ id: orgs.id, deletedAt: orgs.deletedAt });
    if (!u[0] || u[0].deletedAt) throw new AppError(409, "already_deleted", "This organization has already been deleted.");
    await audit(tx, { actor: userActor(c.principal), action: "org.deletion_cancelled", target: { type: "org", id: c.org.id }, reason: r.data, requestId: c.principal.requestId });
    await notifyAdmins(tx, c.org.id, { kind: "org_deletion", title: `Organization deletion cancelled: ${r.data}`, link: "/settings/organization", sourceId: randomUUID() });
  });
}

/** RS-PLAT-005: a legal hold suspends retention purges and deletion for this org until released. */
export async function setLegalHold(c: Ctx, on: boolean, reason: string) {
  await authorize(c.principal, "retention.manage", { type: "org", id: c.org.id }, c.org);
  const r = reasonInput.safeParse(reason);
  if (!r.success) throw new AppError(422, "validation_failed", r.error.issues[0].message);
  await withOrg(c.org.id, async (tx) => {
    const o = (await tx.select().from(orgs).where(eq(orgs.id, c.org.id)).for("update"))[0];
    if (on && o.deletionRequestedAt) throw new AppError(409, "deletion_pending", "Cancel the pending deletion before placing a legal hold.");
    await tx.update(orgs).set({ legalHold: on }).where(eq(orgs.id, c.org.id));
    await audit(tx, { actor: userActor(c.principal), action: on ? "retention.legal_hold_set" : "retention.legal_hold_released", target: { type: "org", id: c.org.id }, reason: r.data, requestId: c.principal.requestId, details: { before: o.legalHold, after: on } });
  });
}
