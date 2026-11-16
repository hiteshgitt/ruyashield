import { sql } from "drizzle-orm";
import type { Tx } from "../db/client";
import { redact } from "../log";

export type Actor =
  | { type: "user"; id: string; ip?: string | null }
  | { type: "service"; id: string }
  | { type: "anonymous"; ip?: string | null };

export interface AuditEvent {
  actor: Actor;
  action: string; // e.g. "asset.verified"
  target?: { type: string; id: string } | null;
  outcome?: "success" | "denied" | "error";
  reason?: string | null;
  requestId?: string | null;
  details?: Record<string, unknown>;
}

/**
 * Appends an event to the tenant's hash chain inside the caller's transaction (RS-AUDIT-001/002).
 * The tenant is whatever app.org_id the transaction carries (null = global chain).
 * Throws on failure, so the surrounding business transaction rolls back: no action without its audit record.
 */
export async function audit(tx: Tx, ev: AuditEvent): Promise<number> {
  const actorId = ev.actor.type === "anonymous" ? null : ev.actor.id;
  const actorIp = ev.actor.type === "service" ? null : ev.actor.ip ?? null;
  const details = JSON.stringify(redact(ev.details ?? {}));
  const res = await tx.execute<{ seq: string }>(sql`
    SELECT append_audit(${ev.actor.type}, ${actorId}, ${actorIp}, ${ev.action},
      ${ev.target?.type ?? null}, ${ev.target?.id ?? null}, ${ev.outcome ?? "success"},
      ${ev.reason ?? null}, ${ev.requestId ?? null}, ${details}::jsonb) AS seq`);
  return Number(res.rows[0].seq);
}

export async function verifyChain(tx: Tx): Promise<{ checked: number; firstBrokenSeq: number | null }> {
  const res = await tx.execute<{ checked: string; first_broken_seq: string | null }>(
    sql`SELECT checked, first_broken_seq FROM verify_audit_chain()`,
  );
  const r = res.rows[0];
  return { checked: Number(r.checked), firstBrokenSeq: r.first_broken_seq === null ? null : Number(r.first_broken_seq) };
}
