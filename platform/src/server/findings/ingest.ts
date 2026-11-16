import { and, eq, gte, isNull, notInArray, sql } from "drizzle-orm";
import type { Tx } from "../db/client";
import { findingOccurrences, findings, fixproofRecords, type FindingStatus } from "../db/schema";
import type { Actor } from "../audit/audit";
import { fingerprint, type FindingCandidate } from "../assessments/checks";
import { evidenceClass, storeEvidence } from "./evidence";
import { systemTransitionAllowed, type SystemReason } from "./lifecycle";
import { notify, recordTransition } from "./record";

// Ingestion (RS-FIND-001): one finding per (org, fingerprint); every sighting adds an occurrence with its
// own evidence item. Runs inside the runner's transaction for the check that produced the candidates.

const INGEST: Actor = { type: "service", id: "finding-ingest" };
/** A `new` finding that consecutive completed covering checks no longer see becomes `stale` after this many. */
export const STALE_AFTER_MISSES = 2;

export interface IngestContext { orgId: string; assetId: string; assessmentId: string; checkRunId: string; checkKey: string }

export async function ingestFinding(tx: Tx, c: IngestContext, f: FindingCandidate): Promise<{ id: string; created: boolean; status: FindingStatus }> {
  const fp = fingerprint(c.checkKey, f.location, f.issueKey);
  const confidence = f.confidence ?? "confirmed";
  const ev = await storeEvidence(tx, { orgId: c.orgId, assessmentId: c.assessmentId, checkRunId: c.checkRunId, body: f.evidence });

  const inserted = (await tx.insert(findings).values({
    orgId: c.orgId, assetId: c.assetId, fingerprint: fp, checkKey: c.checkKey, issueKey: f.issueKey, title: f.title,
    severity: f.severity, confidence, sourceSeverity: f.severity, sourceConfidence: confidence, location: f.location,
    lastAssessmentId: c.assessmentId, evidence: f.evidence, latestEvidenceId: ev.id, remediation: f.remediation, status: "new",
  }).onConflictDoNothing({ target: [findings.orgId, findings.fingerprint] }).returning({ id: findings.id }))[0];

  if (inserted) {
    await recordTransition(tx, { orgId: c.orgId, findingId: inserted.id, from: null, to: "new", actor: INGEST, details: { assessmentId: c.assessmentId, checkKey: c.checkKey } });
    await tx.insert(findingOccurrences).values({ orgId: c.orgId, findingId: inserted.id, assessmentId: c.assessmentId, evidence: f.evidence, evidenceId: ev.id }).onConflictDoNothing();
    return { id: inserted.id, created: true, status: "new" };
  }

  const cur = (await tx.select().from(findings).where(and(eq(findings.orgId, c.orgId), eq(findings.fingerprint, fp))).for("update"))[0];
  // An analyst override (severity_reason set) stands; otherwise the check's current rating applies.
  const rating = cur.severityReason == null ? { severity: f.severity, confidence } : {};
  await tx.update(findings).set({
    lastSeen: sql`now()`, lastAssessmentId: c.assessmentId, evidence: f.evidence, latestEvidenceId: ev.id, title: f.title,
    remediation: f.remediation, sourceSeverity: f.severity, sourceConfidence: confidence, missedRuns: 0, ...rating,
  }).where(eq(findings.id, cur.id));

  let next: { to: FindingStatus; reason: SystemReason } | null = null;
  if (cur.status === "stale") next = { to: "new", reason: "seen_again" };
  else if (cur.status === "fix_pending_verification" || cur.status === "resolved_verified") next = { to: "reopened", reason: "redetected" };
  else if (cur.status === "false_positive" && cur.fpEvidenceClass && cur.fpEvidenceClass !== evidenceClass(f.evidence)) next = { to: "triaged", reason: "fp_new_evidence" };

  if (next && systemTransitionAllowed(cur.status, next.to, next.reason)) {
    await recordTransition(tx, { orgId: c.orgId, findingId: cur.id, from: cur.status, to: next.to, actor: INGEST, reason: next.reason, details: { assessmentId: c.assessmentId } });
    if (next.reason === "fp_new_evidence") await tx.update(findings).set({ fpEvidenceClass: null }).where(eq(findings.id, cur.id));
    // A re-detection after a verified fix retires that FixProof record (RS-FIXP-004); the record itself is kept.
    if (next.reason === "redetected") {
      await tx.update(fixproofRecords).set({ supersededAt: new Date(), supersededReason: "regression" })
        .where(and(eq(fixproofRecords.findingId, cur.id), isNull(fixproofRecords.supersededAt)));
    }
    if (next.reason !== "seen_again") await notify(tx, { orgId: c.orgId, userId: cur.ownerId, findingId: cur.id, kind: "retriage" });
  }
  await tx.insert(findingOccurrences).values({ orgId: c.orgId, findingId: cur.id, assessmentId: c.assessmentId, evidence: f.evidence, evidenceId: ev.id }).onConflictDoNothing();
  return { id: cur.id, created: false, status: next?.to ?? cur.status };
}

/**
 * After a check completed successfully: findings of the same asset and check that it did not report this
 * time count a miss. Errored or skipped checks never count — absence of evidence from a failed check is
 * not evidence of absence.
 */
export async function markMissed(tx: Tx, c: Omit<IngestContext, "checkRunId">, seenFingerprints: string[]) {
  const where = [eq(findings.assetId, c.assetId), eq(findings.checkKey, c.checkKey)];
  if (seenFingerprints.length) where.push(notInArray(findings.fingerprint, seenFingerprints));
  await tx.update(findings).set({ missedRuns: sql`${findings.missedRuns} + 1` }).where(and(...where));
  const goStale = await tx.select({ id: findings.id }).from(findings)
    .where(and(...where, eq(findings.status, "new"), gte(findings.missedRuns, STALE_AFTER_MISSES))).for("update");
  for (const s of goStale) {
    await recordTransition(tx, { orgId: c.orgId, findingId: s.id, from: "new", to: "stale", actor: INGEST, reason: "not_seen", details: { assessmentId: c.assessmentId } });
  }
}
