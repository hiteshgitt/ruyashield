import { randomUUID } from "node:crypto";
import { eq, sql } from "drizzle-orm";
import type { Tx } from "../db/client";
import { findings, findingStatusHistory, type FindingStatus } from "../db/schema";
import { audit, type Actor } from "../audit/audit";
import { enqueue } from "../outbox/outbox";

/** Moves a finding to a new status and records it in the append-only history and the audit log. */
export async function recordTransition(tx: Tx, t: {
  orgId: string; findingId: string; from: FindingStatus | null; to: FindingStatus; actor: Actor; reason?: string | null;
  requestId?: string; details?: Record<string, unknown>;
}) {
  if (t.from !== null) {
    await tx.update(findings).set({ status: t.to, statusChangedAt: sql`now()` }).where(eq(findings.id, t.findingId));
  }
  await tx.insert(findingStatusHistory).values({
    orgId: t.orgId, findingId: t.findingId, fromStatus: t.from, toStatus: t.to,
    actorType: t.actor.type === "user" ? "user" : "service", actorId: t.actor.type === "anonymous" ? "anonymous" : t.actor.id,
    reason: t.reason ?? null,
  });
  await audit(tx, {
    actor: t.actor, action: t.from === null ? "finding.created" : "finding.status_changed",
    target: { type: "finding", id: t.findingId }, reason: t.reason ?? undefined, requestId: t.requestId,
    details: { from: t.from, to: t.to, ...t.details },
  });
}

export type NotifyKind = "assigned" | "mentioned" | "risk_expired" | "retriage" | "verification_failed"
  | "approval_requested" | "approval_decided" | "regression" | "regression_not_run" | "regression_inconclusive";

/** Queues an in-app/email notification. The payload holds ids only; the worker resolves the recipient. */
export async function notify(tx: Tx, n: { orgId: string; userId: string | null | undefined; findingId: string; kind: NotifyKind }) {
  if (!n.userId) return;
  await enqueue(tx, {
    orgId: n.orgId, topic: "finding.notify", businessKey: `finding:${n.findingId}:${n.kind}:${n.userId}:${randomUUID()}`,
    payload: { findingId: n.findingId, userId: n.userId, kind: n.kind },
  });
}
