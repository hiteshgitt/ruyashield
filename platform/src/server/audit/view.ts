import { desc, eq, lt, and, gte, like, type SQL } from "drizzle-orm";
import { withOrg } from "../db/client";
import { auditEvents } from "../db/schema";
import { AppError } from "../errors";
import { authorize, type OrgFlags, type Principal } from "../policy/policy";
import { csvCell } from "../reports/render";
import { audit, verifyChain } from "./audit";

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };

export const AUDIT_PAGE_SIZE = 50;
export const AUDIT_EXPORT_MAX = 10_000;

export interface AuditFilter { action?: string; outcome?: string; actorId?: string; from?: string; to?: string }

/** Validates filters strictly; anything malformed is a 422, never silently ignored. */
function filterSql(orgId: string, f: AuditFilter): SQL[] {
  const w: SQL[] = [eq(auditEvents.orgId, orgId)];
  const bad = () => new AppError(422, "invalid_filter", "One of the filters is not valid.");
  if (f.action) {
    if (!/^[a-z_.]{1,60}$/.test(f.action)) throw bad();
    w.push(like(auditEvents.action, `${f.action}%`));
  }
  if (f.outcome) {
    if (!["success", "denied", "error"].includes(f.outcome)) throw bad();
    w.push(eq(auditEvents.outcome, f.outcome));
  }
  if (f.actorId) {
    if (!/^[A-Za-z0-9_-]{1,64}$/.test(f.actorId)) throw bad();
    w.push(eq(auditEvents.actorId, f.actorId));
  }
  for (const k of ["from", "to"] as const) {
    const v = f[k];
    if (!v) continue;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(v) || Number.isNaN(Date.parse(`${v}T00:00:00Z`))) throw bad();
    const d = new Date(`${v}T00:00:00Z`);
    w.push(k === "from" ? gte(auditEvents.ts, d) : lt(auditEvents.ts, new Date(d.getTime() + 86_400_000)));
  }
  return w;
}

/** RS-AUDIT-003: org admins and security leads read their own tenant's chain, newest first. */
export async function listAuditEvents(c: Ctx, before?: number, f: AuditFilter = {}) {
  await authorize(c.principal, "audit.view", { type: "org", id: c.org.id }, c.org);
  const w = filterSql(c.org.id, f);
  if (before) w.push(lt(auditEvents.seq, before));
  return withOrg(c.org.id, (tx) => tx.select().from(auditEvents).where(and(...w))
    .orderBy(desc(auditEvents.seq)).limit(AUDIT_PAGE_SIZE));
}

const EXPORT_COLUMNS = ["seq", "ts", "actorType", "actorId", "actorIp", "action", "targetType", "targetId", "outcome", "reason", "requestId", "details", "prevHash", "hash"] as const;

/**
 * RS-AUDIT-004: export of the filtered chain (step-up). Includes hashes so a recipient can re-verify the
 * sequence. Capped at AUDIT_EXPORT_MAX rows; `truncated` says when the cap was hit. The export is itself audited.
 */
export async function exportAuditEvents(c: Ctx, format: "csv" | "json", f: AuditFilter = {}) {
  await authorize(c.principal, "audit.export", { type: "org", id: c.org.id }, c.org);
  if (format !== "csv" && format !== "json") throw new AppError(422, "validation_failed", "Use csv or json.");
  const w = filterSql(c.org.id, f);
  return withOrg(c.org.id, async (tx) => {
    const rows = await tx.select().from(auditEvents).where(and(...w)).orderBy(auditEvents.seq).limit(AUDIT_EXPORT_MAX + 1);
    const truncated = rows.length > AUDIT_EXPORT_MAX;
    const out = rows.slice(0, AUDIT_EXPORT_MAX);
    await audit(tx, {
      actor: { type: "user", id: c.principal.userId, ip: c.principal.ip }, action: "audit.exported",
      target: { type: "org", id: c.org.id }, requestId: c.principal.requestId,
      details: { format, filter: { ...f }, rows: out.length, truncated },
    });
    const body = format === "json"
      ? JSON.stringify({ orgId: c.org.id, exportedAt: new Date().toISOString(), filter: f, truncated, events: out }, null, 2)
      : [EXPORT_COLUMNS.join(","), ...out.map((r) => EXPORT_COLUMNS.map((k) => csvCell(k === "details" ? JSON.stringify(r.details) : k === "ts" ? r.ts.toISOString() : r[k])).join(","))].join("\r\n") + "\r\n";
    return { body, rows: out.length, truncated };
  });
}

/** Recomputes the tenant's hash chain and records that the check ran, with its result. */
export async function verifyOrgAuditChain(c: Ctx) {
  await authorize(c.principal, "audit.view", { type: "org", id: c.org.id }, c.org);
  return withOrg(c.org.id, async (tx) => {
    const r = await verifyChain(tx);
    await audit(tx, {
      actor: { type: "user", id: c.principal.userId, ip: c.principal.ip }, action: "audit.chain_verified",
      outcome: r.firstBrokenSeq === null ? "success" : "error", reason: r.firstBrokenSeq === null ? null : "chain_broken",
      requestId: c.principal.requestId, details: r,
    });
    return r;
  });
}
