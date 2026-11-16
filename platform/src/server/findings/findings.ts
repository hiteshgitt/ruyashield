import { and, asc, desc, eq, inArray, isNull, lt, or, sql, type SQL } from "drizzle-orm";
import { z } from "zod";
import { withOrg, isUuid, type Tx } from "../db/client";
import {
  assets, evidenceItems, findingComments, findingOccurrences, findings, findingStatusHistory, memberClientGroups,
  memberships, riskAcceptances, users, type Confidence, type Criticality, type FindingStatus, type Severity,
  verificationRuns,
} from "../db/schema";
import { audit, type Actor } from "../audit/audit";
import { AppError, forbidden, notFound } from "../errors";
import { authorize, decide, type OrgFlags, type Principal, type Resource } from "../policy/policy";
import { grantFor, type Role } from "../policy/matrix";
import { evidenceClass, redactEvidence, verifyIntegrity } from "./evidence";
import { ALL_STATUSES, isOpen, USER_TRANSITIONS, userTransitionsFrom } from "./lifecycle";
import { priorityOf, prioritySql } from "./priority";
import { notify, recordTransition } from "./record";
import { areaByKey } from "../reports/areas";

// Findings & triage service (RS-FIND-002..005, RS-RISK-001..003, RS-COLLAB-001/002).
// Every read and write re-checks the caller against the finding's asset; a finding the caller may not
// see is reported as not found.

export type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
type FindingRow = typeof findings.$inferSelect;
type AssetRow = typeof assets.$inferSelect;
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
const EXPIRY: Actor = { type: "service", id: "risk-expiry" };

const SEVERITIES: readonly Severity[] = ["info", "low", "medium", "high", "critical"];
const CONFIDENCES: readonly Confidence[] = ["confirmed", "likely", "suspected", "unknown"];
const CRITICALITIES: readonly Criticality[] = ["low", "medium", "high", "critical"];
export const MIN_JUSTIFICATION = 20;
export const MAX_RISK_DAYS = 365;
const DAY_MS = 24 * 60 * 60 * 1000;

const res = (f: FindingRow, a: AssetRow): Resource => ({ type: "finding", id: f.id, clientGroupId: a.clientGroupId, ownerId: f.ownerId });
const canView = (p: Principal, f: FindingRow, a: AssetRow, org: OrgFlags) => decide(p, "finding.view", res(f, a), org).allow;

async function loadFinding(tx: Tx, c: Ctx, id: string, lock = false) {
  if (!isUuid(id)) throw notFound();
  const q = tx.select().from(findings).where(eq(findings.id, id));
  const f = (lock ? await q.for("update") : await q)[0];
  if (!f) throw notFound();
  const a = (await tx.select().from(assets).where(eq(assets.id, f.assetId)))[0];
  if (!a || !canView(c.principal, f, a, c.org)) throw notFound();
  return { f, a };
}

const isOverdue = (f: Pick<FindingRow, "dueAt" | "status">, now = new Date()) => f.dueAt != null && f.dueAt < now && isOpen(f.status);

// ---------- list (RS-FIND-005) ----------

const listInput = z.object({
  assetId: z.string().optional(),
  severity: z.string().optional(),
  confidence: z.string().optional(),
  status: z.string().optional(),
  owner: z.string().optional(),
  area: z.string().optional(),
  cursor: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
});

function badFilter(field: string): never {
  throw new AppError(422, "invalid_filter", `Unknown value for ${field}.`);
}

const encodeCursor = (score: number, id: string) => Buffer.from(`${score}|${id}`).toString("base64url");
function decodeCursor(s: string): { score: number; id: string } {
  const [score, id] = Buffer.from(s, "base64url").toString("utf8").split("|");
  const n = Number(score);
  if (!Number.isFinite(n) || !isUuid(id)) badFilter("cursor");
  return { score: n, id };
}

export async function listFindings(c: Ctx, input: unknown = {}) {
  const parsed = listInput.safeParse(input);
  if (!parsed.success) badFilter(String(parsed.error.issues[0].path[0] ?? "query"));
  const q = parsed.data;
  const p = c.principal;
  // A caller who could not see even a finding they own (no grant, or MFA missing) sees none.
  if (!decide(p, "finding.view", { type: "finding", ownerId: p.userId }, c.org).allow) throw forbidden();

  const score = prioritySql(findings.severity, findings.confidence, assets.criticality);
  const where: SQL[] = [];
  if (q.assetId) { if (!isUuid(q.assetId)) badFilter("assetId"); where.push(eq(findings.assetId, q.assetId)); }
  if (q.confidence) { if (!CONFIDENCES.includes(q.confidence as Confidence)) badFilter("confidence"); where.push(eq(findings.confidence, q.confidence as Confidence)); }
  if (q.status === "open") where.push(inArray(findings.status, ["new", "triaged", "confirmed", "in_remediation", "fix_pending_verification", "reopened"]));
  else if (q.status) { if (!ALL_STATUSES.includes(q.status as FindingStatus)) badFilter("status"); where.push(eq(findings.status, q.status as FindingStatus)); }
  if (q.area) {
    const area = areaByKey(q.area);
    if (!area || !area.checks.length) badFilter("area");
    where.push(inArray(findings.checkKey, [...area.checks]));
  }
  if (q.owner === "me") where.push(eq(findings.ownerId, p.userId));
  else if (q.owner === "none") where.push(isNull(findings.ownerId));
  else if (q.owner) { if (!isUuid(q.owner)) badFilter("owner"); where.push(eq(findings.ownerId, q.owner)); }
  // Same rule as decide() for an "S" grant, applied in SQL so paging stays exact.
  if (grantFor(p.role, "finding.view") === "S" && p.restricted) {
    const mine = eq(findings.ownerId, p.userId);
    where.push(p.clientGroupIds.length ? or(inArray(assets.clientGroupId, [...p.clientGroupIds]), mine)! : mine);
  }
  // Severity counts use every filter except severity and the cursor, so the summary strip matches the table.
  const countWhere = [...where];
  if (q.severity) { if (!SEVERITIES.includes(q.severity as Severity)) badFilter("severity"); where.push(eq(findings.severity, q.severity as Severity)); }
  if (q.cursor) {
    const k = decodeCursor(q.cursor);
    where.push(or(lt(score, k.score), and(eq(score, k.score), sql`${findings.id} > ${k.id}`))!);
  }
  const limit = q.limit ?? 50;

  return withOrg(c.org.id, async (tx) => {
    const rows = await tx.select({ f: findings, host: assets.host, assetName: assets.displayName, criticality: assets.criticality, clientGroupId: assets.clientGroupId, score })
      .from(findings).innerJoin(assets, eq(assets.id, findings.assetId))
      .where(where.length ? and(...where) : undefined)
      .orderBy(desc(score), asc(findings.id)).limit(limit + 1);
    const page = rows.slice(0, limit);
    const ownerIds = [...new Set(page.map((r) => r.f.ownerId).filter((x): x is string => !!x))];
    const owners = await memberNames(tx, c.org.id, ownerIds);
    const now = new Date();
    const counts = await tx.select({ severity: findings.severity, n: sql<number>`count(*)::int` })
      .from(findings).innerJoin(assets, eq(assets.id, findings.assetId))
      .where(countWhere.length ? and(...countWhere) : undefined).groupBy(findings.severity);
    const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const r of counts) bySeverity[r.severity] = Number(r.n);
    return {
      bySeverity,
      items: page.map((r) => ({
        ...r.f, host: r.host, assetName: r.assetName, owner: r.f.ownerId ? owners.get(r.f.ownerId) ?? null : null,
        priority: priorityOf(r.f, r.criticality), overdue: isOverdue(r.f, now),
      })),
      nextCursor: rows.length > limit ? encodeCursor(Number(page[page.length - 1].score), page[page.length - 1].f.id) : null,
    };
  });
}

/** Display names for members of this org only; ids of non-members resolve to nothing. */
async function memberNames(tx: Tx, orgId: string, ids: string[]) {
  if (!ids.length) return new Map<string, { id: string; name: string; email: string }>();
  const rows = await tx.select({ id: users.id, name: users.displayName, email: users.email }).from(memberships)
    .innerJoin(users, eq(users.id, memberships.userId))
    .where(and(eq(memberships.orgId, orgId), inArray(memberships.userId, ids)));
  return new Map(rows.map((r) => [r.id, r]));
}

// ---------- detail ----------

export async function getFinding(c: Ctx, id: string) {
  return withOrg(c.org.id, async (tx) => {
    const { f, a } = await loadFinding(tx, c, id);
    const history = await tx.select().from(findingStatusHistory).where(eq(findingStatusHistory.findingId, f.id)).orderBy(asc(findingStatusHistory.createdAt));
    const comments = await tx.select().from(findingComments).where(eq(findingComments.findingId, f.id)).orderBy(asc(findingComments.createdAt));
    const occurrences = await tx.select().from(findingOccurrences).where(eq(findingOccurrences.findingId, f.id)).orderBy(desc(findingOccurrences.seenAt)).limit(50);
    const acceptance = (await tx.select().from(riskAcceptances)
      .where(and(eq(riskAcceptances.findingId, f.id), isNull(riskAcceptances.revokedAt), isNull(riskAcceptances.expiredAt))))[0] ?? null;
    const people = await memberNames(tx, c.org.id, [...new Set([
      f.ownerId, f.severitySetBy, acceptance?.acceptedBy, ...comments.map((x) => x.authorId),
      ...history.filter((h) => h.actorType === "user").map((h) => h.actorId),
    ].filter((x): x is string => !!x && isUuid(x)))]);
    const r = res(f, a);
    const allowed = (action: Parameters<typeof decide>[1]) => decide(c.principal, action, r, c.org).allow;
    const canAssign = allowed("finding.assign");
    const assignees: { id: string; name: string; email: string }[] = [];
    if (canAssign) {
      const members = await tx.select({ id: users.id, name: users.displayName, email: users.email }).from(memberships)
        .innerJoin(users, eq(users.id, memberships.userId))
        .where(and(eq(memberships.orgId, c.org.id), isNull(users.disabledAt))).orderBy(users.email).limit(500);
      for (const m of members) if (await eligibleViewer(tx, c, m.id, r)) assignees.push(m);
    }
    return {
      finding: f, asset: a, history, comments, occurrences, acceptance, people, assignees,
      priority: priorityOf(f, a.criticality), overdue: isOverdue(f),
      transitions: userTransitionsFrom(f.status).filter((t) => allowed(t.action)).map((t) => ({ kind: t.kind, to: t.to })),
      can: {
        triage: allowed("finding.triage"), assign: canAssign, comment: allowed("finding.comment"),
        downloadRaw: allowed("evidence.download_raw"), editAsset: decide(c.principal, "asset.edit", { type: "asset", id: a.id, clientGroupId: a.clientGroupId, ownerId: a.createdBy }, c.org).allow,
      },
    };
  });
}

// ---------- transitions (RS-FIND-004, RS-RISK-001..003) ----------

const fpInput = z.object({ justification: z.string().trim() });
const riskInput = z.object({ justification: z.string().trim(), controls: z.string().trim(), expiresAt: z.union([z.string(), z.date()]) });
const noteInput = z.object({ reason: z.string().trim().max(2000).optional() }).passthrough();

function justification(raw: unknown, schema = fpInput) {
  const p = schema.safeParse(raw ?? {});
  const j = p.success ? p.data.justification : "";
  if (j.length < MIN_JUSTIFICATION) throw new AppError(422, "justification_required", `A justification of at least ${MIN_JUSTIFICATION} characters is required.`);
  if (j.length > 5000) throw new AppError(422, "justification_required", "The justification is too long.");
  return j;
}

/**
 * Applies a user-requested status change. The caller's permission for the kind is checked before the
 * state, so a role that may never do this gets 403 regardless of the finding's status.
 */
export async function transition(c: Ctx, id: string, kind: string, input: unknown = {}) {
  const def = USER_TRANSITIONS.find((t) => t.kind === kind);
  if (!def) throw new AppError(422, "transition_not_allowed", "Unknown status change.");
  const actor = userActor(c.principal);
  return withOrg(c.org.id, async (tx) => {
    const { f, a } = await loadFinding(tx, c, id, true);
    await authorize(c.principal, def.action, res(f, a), c.org);
    if (!def.from.includes(f.status)) {
      throw new AppError(422, "transition_not_allowed", `A ${f.status.replaceAll("_", " ")} finding cannot be moved this way.`);
    }
    const base = { orgId: c.org.id, findingId: f.id, from: f.status, to: def.to, actor, requestId: c.principal.requestId ?? undefined };
    switch (kind) {
      case "false_positive": {
        const j = justification(input);
        await tx.update(findings).set({ fpEvidenceClass: evidenceClass(f.evidence) }).where(eq(findings.id, f.id));
        await recordTransition(tx, { ...base, reason: j });
        break;
      }
      case "accept_risk": {
        const p = riskInput.safeParse(input ?? {});
        const j = justification(input, riskInput as unknown as typeof fpInput);
        const controls = p.success ? p.data.controls : "";
        if (!controls || controls.length > 5000) throw new AppError(422, "controls_required", "Describe the compensating controls.");
        const expiresAt = p.success ? new Date(p.data.expiresAt) : new Date(NaN);
        const now = Date.now();
        if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= now || expiresAt.getTime() > now + MAX_RISK_DAYS * DAY_MS) {
          throw new AppError(422, "invalid_expiry", `The expiry must be in the future and at most ${MAX_RISK_DAYS} days away.`);
        }
        const ra = (await tx.insert(riskAcceptances).values({
          orgId: c.org.id, findingId: f.id, justification: j, compensatingControls: controls, expiresAt, acceptedBy: c.principal.userId,
        }).returning())[0];
        await recordTransition(tx, { ...base, reason: j, details: { acceptanceId: ra.id, expiresAt: ra.expiresAt.toISOString() } });
        break;
      }
      case "revoke_risk": {
        const reason = noteInput.safeParse(input ?? {}).data?.reason || null;
        const live = await tx.update(riskAcceptances).set({ revokedAt: new Date(), revokedBy: c.principal.userId })
          .where(and(eq(riskAcceptances.findingId, f.id), isNull(riskAcceptances.revokedAt), isNull(riskAcceptances.expiredAt))).returning({ id: riskAcceptances.id });
        await recordTransition(tx, { ...base, reason: reason ?? "risk_revoked", details: { acceptanceId: live[0]?.id ?? null } });
        break;
      }
      case "reopen_false_positive":
        await tx.update(findings).set({ fpEvidenceClass: null }).where(eq(findings.id, f.id));
        await recordTransition(tx, { ...base, reason: noteInput.safeParse(input ?? {}).data?.reason || null });
        break;
      default:
        await recordTransition(tx, { ...base, reason: noteInput.safeParse(input ?? {}).data?.reason || null });
    }
    return { id: f.id, from: f.status, to: def.to };
  });
}

// ---------- severity / confidence override (RS-FIND-003) ----------

const overrideInput = z.object({ severity: z.string(), confidence: z.string(), reason: z.string().trim() });

export async function overrideSeverity(c: Ctx, id: string, input: unknown) {
  const p = overrideInput.safeParse(input ?? {});
  return withOrg(c.org.id, async (tx) => {
    const { f, a } = await loadFinding(tx, c, id, true);
    await authorize(c.principal, "finding.triage", res(f, a), c.org);
    if (!p.success || p.data.reason.length < 5) throw new AppError(422, "reason_required", "Give a reason for the change.");
    if (!SEVERITIES.includes(p.data.severity as Severity)) throw new AppError(422, "invalid_severity");
    if (!CONFIDENCES.includes(p.data.confidence as Confidence)) throw new AppError(422, "invalid_confidence");
    const next = { severity: p.data.severity as Severity, confidence: p.data.confidence as Confidence };
    await tx.update(findings).set({ ...next, severityReason: p.data.reason, severitySetBy: c.principal.userId }).where(eq(findings.id, f.id));
    await audit(tx, {
      actor: userActor(c.principal), action: "finding.severity_overridden", target: { type: "finding", id: f.id },
      reason: p.data.reason, requestId: c.principal.requestId,
      details: { from: { severity: f.severity, confidence: f.confidence }, to: next, source: { severity: f.sourceSeverity, confidence: f.sourceConfidence } },
    });
    return next;
  });
}

// ---------- assignment (RS-COLLAB-001) ----------

const assignInput = z.object({ assigneeId: z.string().nullable(), dueAt: z.union([z.string(), z.date()]).nullable().optional() });

/** Whether a member may be given this finding: they must be able to view it without already owning it. */
async function eligibleViewer(tx: Tx, c: Ctx, userId: string, r: Resource) {
  const m = (await tx.select().from(memberships).where(and(eq(memberships.orgId, c.org.id), eq(memberships.userId, userId))))[0];
  if (!m) return false;
  const groups = (await tx.select({ id: memberClientGroups.clientGroupId }).from(memberClientGroups)
    .where(and(eq(memberClientGroups.orgId, c.org.id), eq(memberClientGroups.userId, userId)))).map((g) => g.id);
  const them: Principal = { userId, orgId: c.org.id, role: m.role as Role, restricted: m.restricted, clientGroupIds: groups, mfa: true, authTime: new Date() };
  return decide(them, "finding.view", { ...r, ownerId: null }, c.org).allow;
}

export async function assign(c: Ctx, id: string, input: unknown) {
  const p = assignInput.safeParse(input ?? {});
  if (!p.success) throw new AppError(422, "assignee_not_eligible");
  const actor = userActor(c.principal);
  return withOrg(c.org.id, async (tx) => {
    const { f, a } = await loadFinding(tx, c, id, true);
    await authorize(c.principal, "finding.assign", res(f, a), c.org);
    const assignee = p.data.assigneeId || null;
    if (assignee && (!isUuid(assignee) || !(await eligibleViewer(tx, c, assignee, res(f, a))))) {
      throw new AppError(422, "assignee_not_eligible", "That person cannot see this finding's asset.");
    }
    let dueAt: Date | null = f.dueAt;
    if (p.data.dueAt !== undefined) {
      dueAt = p.data.dueAt ? new Date(p.data.dueAt) : null;
      if (dueAt && Number.isNaN(dueAt.getTime())) throw new AppError(422, "invalid_due_date");
    }
    await tx.update(findings).set({ ownerId: assignee, dueAt }).where(eq(findings.id, f.id));
    await audit(tx, {
      actor, action: "finding.assigned", target: { type: "finding", id: f.id }, requestId: c.principal.requestId,
      details: { from: f.ownerId, to: assignee, dueAt: dueAt?.toISOString() ?? null },
    });
    let status = f.status;
    if (assignee && (f.status === "confirmed" || f.status === "reopened")) {
      await recordTransition(tx, { orgId: c.org.id, findingId: f.id, from: f.status, to: "in_remediation", actor, reason: "assigned", requestId: c.principal.requestId ?? undefined });
      status = "in_remediation";
    }
    if (assignee && assignee !== f.ownerId && assignee !== c.principal.userId) await notify(tx, { orgId: c.org.id, userId: assignee, findingId: f.id, kind: "assigned" });
    return { ownerId: assignee, dueAt, status };
  });
}

// ---------- comments and mentions (RS-COLLAB-002) ----------

const MENTION_RE = /(?:^|[\s(])@([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})/g;
export const mentionedEmails = (body: string) => [...new Set([...body.matchAll(MENTION_RE)].map((m) => m[1].toLowerCase()))].slice(0, 20);

export async function addComment(c: Ctx, id: string, rawBody: unknown) {
  const body = typeof rawBody === "string" ? rawBody.trim() : "";
  return withOrg(c.org.id, async (tx) => {
    const { f, a } = await loadFinding(tx, c, id);
    await authorize(c.principal, "finding.comment", res(f, a), c.org);
    if (body.length < 1 || body.length > 5000) throw new AppError(422, "invalid_comment", "Comments must be 1–5000 characters.");
    // Mentions resolve only to members of this org who can see the finding; anything else stays plain text.
    const emails = mentionedEmails(body);
    const candidates = emails.length ? await tx.select({ id: users.id }).from(memberships).innerJoin(users, eq(users.id, memberships.userId))
      .where(and(eq(memberships.orgId, c.org.id), inArray(sql`lower(${users.email})`, emails), isNull(users.disabledAt))) : [];
    const mentions: string[] = [];
    for (const u of candidates) if (await eligibleViewer(tx, c, u.id, res(f, a)) || u.id === f.ownerId) mentions.push(u.id);
    const row = (await tx.insert(findingComments).values({ orgId: c.org.id, findingId: f.id, authorId: c.principal.userId, body, mentions }).returning())[0];
    await audit(tx, {
      actor: userActor(c.principal), action: "finding.commented", target: { type: "finding", id: f.id }, requestId: c.principal.requestId,
      details: { commentId: row.id, length: body.length, mentions: mentions.length },
    });
    for (const u of mentions) if (u !== c.principal.userId) await notify(tx, { orgId: c.org.id, userId: u, findingId: f.id, kind: "mentioned" });
    return row;
  });
}

// ---------- evidence (RS-FIND-002) ----------

/** The finding an evidence item belongs to, if the caller may see it. */
async function evidenceFinding(tx: Tx, c: Ctx, evidenceId: string) {
  if (!isUuid(evidenceId)) throw notFound();
  const e = (await tx.select().from(evidenceItems).where(eq(evidenceItems.id, evidenceId)))[0];
  if (!e) throw notFound();
  let owners = await tx.selectDistinct({ id: findingOccurrences.findingId }).from(findingOccurrences).where(eq(findingOccurrences.evidenceId, e.id));
  // Verification re-test evidence belongs to the finding that was re-tested (P6).
  if (!owners.length) owners = await tx.selectDistinct({ id: verificationRuns.findingId }).from(verificationRuns)
    .where(sql`${verificationRuns.results} @> ${JSON.stringify([{ evidenceId: e.id }])}::jsonb`);
  for (const o of owners) {
    const f = (await tx.select().from(findings).where(eq(findings.id, o.id)))[0];
    const a = f && (await tx.select().from(assets).where(eq(assets.id, f.assetId)))[0];
    if (f && a && canView(c.principal, f, a, c.org)) return { e, f, a };
  }
  throw notFound();
}

async function integrityFailed(c: Ctx, e: { id: string; sha256: string }, findingId: string) {
  // Own transaction: the record must survive a caller that throws.
  await withOrg(c.org.id, (tx) => audit(tx, {
    actor: userActor(c.principal), action: "evidence.integrity_failed", target: { type: "evidence", id: e.id }, outcome: "error",
    requestId: c.principal.requestId, details: { findingId, expected: e.sha256 },
  }));
}

/** Evidence as shown in the app: integrity-checked, with secrets and personal data redacted. */
export async function getEvidence(c: Ctx, evidenceId: string) {
  const out = await withOrg(c.org.id, async (tx) => {
    const { e, f } = await evidenceFinding(tx, c, evidenceId);
    const ok = verifyIntegrity(e);
    return {
      findingId: f.id, ok, item: {
        id: e.id, sha256: e.sha256, contentType: e.contentType, sizeBytes: e.sizeBytes, truncated: e.truncated, capturedAt: e.capturedAt,
        integrity: ok ? "verified" as const : "failed" as const, body: ok ? redactEvidence(e.body, e.contentType) : null,
      },
    };
  });
  if (!out.ok) await integrityFailed(c, out.item, out.findingId);
  return out.item;
}

/** The stored body (credentials were already redacted at capture). Requires evidence.download_raw and is audited. */
export async function getRawEvidence(c: Ctx, evidenceId: string) {
  const { e, f, a } = await withOrg(c.org.id, (tx) => evidenceFinding(tx, c, evidenceId));
  await authorize(c.principal, "evidence.download_raw", res(f, a), c.org);
  if (!verifyIntegrity(e)) {
    await integrityFailed(c, e, f.id);
    throw new AppError(409, "evidence_integrity_failed", "This evidence failed its integrity check and is withheld.");
  }
  await withOrg(c.org.id, (tx) => audit(tx, {
    actor: userActor(c.principal), action: "evidence.downloaded", target: { type: "evidence", id: e.id }, requestId: c.principal.requestId,
    details: { findingId: f.id, sha256: e.sha256, sizeBytes: e.sizeBytes },
  }));
  return { id: e.id, sha256: e.sha256, contentType: e.contentType, body: e.body };
}

// ---------- asset criticality (priority input) ----------

export async function setAssetCriticality(c: Ctx, assetId: string, value: unknown) {
  const next = value === "" || value == null ? null : String(value);
  if (next !== null && !CRITICALITIES.includes(next as Criticality)) throw new AppError(422, "invalid_criticality");
  return withOrg(c.org.id, async (tx) => {
    if (!isUuid(assetId)) throw notFound();
    const a = (await tx.select().from(assets).where(eq(assets.id, assetId)).for("update"))[0];
    if (!a) throw notFound();
    const r: Resource = { type: "asset", id: a.id, clientGroupId: a.clientGroupId, ownerId: a.createdBy };
    if (!decide(c.principal, "asset.view", r, c.org).allow) throw notFound();
    await authorize(c.principal, "asset.edit", r, c.org);
    await tx.update(assets).set({ criticality: next as Criticality | null }).where(eq(assets.id, a.id));
    await audit(tx, { actor: userActor(c.principal), action: "asset.criticality_changed", target: { type: "asset", id: a.id }, requestId: c.principal.requestId, details: { from: a.criticality, to: next } });
    return next;
  });
}

// ---------- risk expiry (scheduler) ----------

/** Expires due risk acceptances and returns their findings to triage. Cross-tenant ids come from due_risk_expiries(). */
export async function scheduleRiskExpiries(): Promise<number> {
  const { db } = await import("../db/client");
  const r = await db.execute<{ org_id: string; finding_id: string; acceptance_id: string }>(sql`SELECT * FROM due_risk_expiries()`);
  let n = 0;
  for (const row of r.rows) {
    await withOrg(row.org_id, async (tx) => {
      const ra = (await tx.update(riskAcceptances).set({ expiredAt: new Date() })
        .where(and(eq(riskAcceptances.id, row.acceptance_id), isNull(riskAcceptances.revokedAt), isNull(riskAcceptances.expiredAt), sql`${riskAcceptances.expiresAt} <= now()`))
        .returning())[0];
      if (!ra) return; // revoked or handled by another worker meanwhile
      n++;
      const f = (await tx.select().from(findings).where(eq(findings.id, row.finding_id)).for("update"))[0];
      if (f?.status === "accepted_risk") {
        await recordTransition(tx, { orgId: row.org_id, findingId: f.id, from: "accepted_risk", to: "triaged", actor: EXPIRY, reason: "risk_expired", details: { acceptanceId: ra.id } });
      }
      await audit(tx, { actor: EXPIRY, action: "risk_acceptance.expired", target: { type: "finding", id: row.finding_id }, details: { acceptanceId: ra.id, expiresAt: ra.expiresAt.toISOString() } });
      for (const u of new Set([f?.ownerId, ra.acceptedBy])) await notify(tx, { orgId: row.org_id, userId: u, findingId: row.finding_id, kind: "risk_expired" });
    });
  }
  return n;
}
