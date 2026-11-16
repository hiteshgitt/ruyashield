import { sql } from "drizzle-orm";
import { db, withOrg } from "../db/client";
import { audit, type Actor } from "../audit/audit";

const RETENTION: Actor = { type: "service", id: "retention" };

type PurgeRow = {
  purged_org: string; n_evidence: string; n_ai_analyses: string; n_findings_scrubbed: string;
  n_audit_events: string; n_notifications: string; n_reports: string;
};

/**
 * RS-DATA retention job (daily). Orgs under legal hold are skipped by the database functions themselves.
 * Evidence and AI analyses go after 1 year, closed findings are scrubbed (rows kept) and audit events are
 * trimmed after 3 years with a chain anchor; orgs whose 30-day deletion grace has passed are marked deleted.
 * Each org gets an audit record of what was removed. Hard erasure of a deleted org is a manual runbook step.
 */
export async function runRetention(): Promise<{ orgsPurged: number; orgsDeleted: number }> {
  const purged = (await db.execute<PurgeRow>(sql`SELECT * FROM retention_purge()`)).rows;
  for (const r of purged) {
    await withOrg(r.purged_org, (tx) => audit(tx, {
      actor: RETENTION, action: "retention.purged", target: { type: "org", id: r.purged_org },
      details: {
        evidence: Number(r.n_evidence), aiAnalyses: Number(r.n_ai_analyses), findingsScrubbed: Number(r.n_findings_scrubbed),
        auditEvents: Number(r.n_audit_events), notifications: Number(r.n_notifications), reports: Number(r.n_reports),
      },
    }));
  }
  // Attack events hold visitor IPs (personal data): kept 90 days only.
  const attacks = (await db.execute<{ purged_org: string; n_events: string }>(sql`SELECT * FROM attack_events_purge()`)).rows;
  for (const r of attacks) {
    await withOrg(r.purged_org, (tx) => audit(tx, {
      actor: RETENTION, action: "attacks.purged", target: { type: "org", id: r.purged_org }, details: { events: Number(r.n_events), olderThanDays: 90 },
    }));
  }
  const deleted = (await db.execute<{ org_id: string }>(sql`SELECT org_id FROM finalize_org_deletions()`)).rows;
  for (const d of deleted) {
    await withOrg(d.org_id, (tx) => audit(tx, {
      actor: RETENTION, action: "org.deleted", target: { type: "org", id: d.org_id },
      reason: "30-day deletion grace period ended", details: { hardErasure: "pending_manual_runbook" },
    }));
  }
  return { orgsPurged: purged.length, orgsDeleted: deleted.length };
}
