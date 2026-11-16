import { sql } from "drizzle-orm";
import type { Tx } from "../db/client";
import { outbox } from "../db/schema";

export type Topic = "email.invite" | "asset.reverify" | "assessment.run" | "assessment.notify" | "finding.notify" | "verification.run"
  | "remediation.sandbox" | "remediation.open_pr" | "webmonitor.publish";

/** Enqueues a message in the caller's transaction, so it exists iff the business change commits. */
export async function enqueue(tx: Tx, m: { orgId: string; topic: Topic; businessKey: string; payload: Record<string, unknown>; availableAt?: Date }) {
  const rows = await tx.insert(outbox).values({
    orgId: m.orgId, topic: m.topic, businessKey: m.businessKey, payload: m.payload,
    availableAt: m.availableAt ?? sql`now()`,
  }).returning({ id: outbox.id });
  return rows[0].id;
}

export const OUTBOX_MAX_ATTEMPTS = 5;
/** Exponential backoff: 10 s, 20 s, 40 s, 80 s … */
export const backoffMs = (attempts: number) => 10_000 * 2 ** Math.max(0, attempts - 1);
