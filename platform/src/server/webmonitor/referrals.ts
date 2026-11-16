import { createHash, randomBytes, randomUUID } from "node:crypto";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg, isUuid, type Tx } from "../db/client";
import {
  assessments, assets, consents, findingOccurrences, findings, fixproofRecords, referralEvents, webmonitorReferrals,
  type ConsentSubject, type ReferralStatus,
} from "../db/schema";
import { audit, type Actor } from "../audit/audit";
import { AppError, isAppError, notFound } from "../errors";
import { authorize, type OrgFlags, type Principal } from "../policy/policy";
import { enqueue } from "../outbox/outbox";
import { parseHost } from "../assets/host";
import { log } from "../log";
import { webmonitorAdapter, type ResultSummary } from "./adapter";

// RS-WMON-001..004 on the provisional adapter (D-14). A referral is a hint from WebMonitor, never an instruction:
// it cannot start an assessment, and its text is shown to people as untrusted plain text only.

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
const PUBLISHER: Actor = { type: "service", id: "webmonitor-publisher" };
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });

export const REFERRAL_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const MAX_HANDOFF_BYTES = 16 * 1024;
/** Bumped whenever the consent wording on the landing page changes; a decision on older text is refused. */
export const CONSENT_TEXT_VERSION = "referral-consent/2026-11-01";

const hashToken = (t: string) => createHash("sha256").update(t).digest("hex");
const appUrl = (path: string) => new URL(path, process.env.APP_URL ?? "http://localhost:3200").toString();
// Control and bidi-override characters are dropped so untrusted text cannot disguise itself on the page.
const plain = (s: string) => s.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, " ").replace(/\s+/g, " ").trim();

// Only these fields are kept (FR-042). Unknown fields, including anything credential- or content-like, are dropped.
const handoffSchema = z.object({
  nonce: z.string().regex(/^[A-Za-z0-9._:-]{16,100}$/),
  externalRef: z.string().regex(/^[A-Za-z0-9._:-]{1,100}$/),
  signalType: z.string().regex(/^[a-z][a-z0-9_.]{0,49}$/),
  host: z.string().min(1).max(300),
  observedAt: z.iso.datetime({ offset: true }),
  summary: z.string().max(2000).optional().default(""),
});

export type HandoffResult =
  | { status: 202; body: { status: "received"; referralId: string; link: string; expiresAt: string } }
  | { status: 200; body: { status: "duplicate"; referralId: string } }
  | { status: number; body: { error: { code: string } } };

const err = (status: number, code: string): HandoffResult => ({ status, body: { error: { code } } });

/** RS-WMON-001: authenticates and stores a handoff. Never launches anything; the person must consent first. */
export async function receiveHandoff(h: { timestamp?: string | null; signature?: string | null }, body: string, now = new Date()): Promise<HandoffResult> {
  const auth = webmonitorAdapter().verifyHandoff(h, body, now.getTime());
  if (!auth.ok) return err(auth.status, auth.code);
  let parsed: z.infer<typeof handoffSchema>;
  let host: string;
  try {
    const r = handoffSchema.safeParse(JSON.parse(body));
    if (!r.success) return err(422, "invalid_handoff");
    parsed = r.data;
    host = parseHost(parsed.host);
  } catch (e) {
    return err(422, isAppError(e) ? "invalid_host" : "invalid_handoff");
  }
  const sha = createHash("sha256").update(body).digest("hex");
  const token = randomBytes(32).toString("base64url");
  const expires = new Date(now.getTime() + REFERRAL_TTL_MS);
  const summary = plain(parsed.summary).slice(0, 280);
  const row = (await db.execute<{ id: string; payload_sha256: string; inserted: boolean }>(sql`
    SELECT * FROM webmonitor_store_referral(${parsed.externalRef}, ${parsed.nonce}, ${sha}, ${parsed.signalType}, ${host},
      ${new Date(parsed.observedAt).toISOString()}::timestamptz, ${summary}, ${hashToken(token)}, ${expires.toISOString()}::timestamptz)`)).rows[0];
  if (!row.inserted) {
    // Same nonce: an identical retry is acknowledged; a different payload under a used nonce is a replay.
    if (row.payload_sha256 !== sha) {
      log.warn("webmonitor.replay", { referralId: row.id });
      return err(409, "nonce_reused");
    }
    return { status: 200, body: { status: "duplicate", referralId: row.id } };
  }
  log.info("webmonitor.referral_received", { referralId: row.id, signalType: parsed.signalType });
  return { status: 202, body: { status: "received", referralId: row.id, link: appUrl(`/referrals/${token}`), expiresAt: expires.toISOString() } };
}

export type ReferralView = {
  id: string; signalType: string; host: string; observedAt: Date; summary: string; status: ReferralStatus; expiresAt: Date; receivedAt: Date;
  consentTextVersion: string; assetId: string | null; assetVerified: boolean;
};

/** What the landing page may show for a token. Requires a signed-in user; the asset lookup is in their active org. */
export async function getReferralByToken(c: Ctx, token: string, now = new Date()): Promise<ReferralView> {
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(token)) throw notFound();
  const r = (await db.execute<{ id: string; signal_type: string; host: string; observed_at: string; summary: string; status: ReferralStatus; expires_at: string; consumed: boolean; received_at: string }>(
    sql`SELECT * FROM webmonitor_referral_by_token(${hashToken(token)})`)).rows[0];
  if (!r) throw notFound();
  // A used link reveals nothing more than its state.
  const status: ReferralStatus = r.status === "pending_consent" && new Date(r.expires_at) <= now ? "expired" : r.status;
  const a = await withOrg(c.org.id, async (tx) => (await tx.select({ id: assets.id, status: assets.status }).from(assets).where(eq(assets.host, r.host)).limit(1))[0]);
  return {
    id: r.id, signalType: r.signal_type, host: r.host, observedAt: new Date(r.observed_at), summary: r.consumed ? "" : r.summary, status,
    expiresAt: new Date(r.expires_at), receivedAt: new Date(r.received_at), consentTextVersion: CONSENT_TEXT_VERSION,
    assetId: a?.id ?? null, assetVerified: a?.status === "verified",
  };
}

const decisionInput = z.object({
  decision: z.enum(["consent", "decline", "delete"]),
  textVersion: z.string().max(100),
  acceptCharges: z.boolean().optional().default(false),
  shareStatus: z.boolean().optional().default(false),
});

/** RS-WMON-002: consent, decline or delete, recorded against the consent text version. The token works once. */
export async function decideReferral(c: Ctx, token: string, input: unknown, now = new Date()) {
  if (!/^[A-Za-z0-9_-]{20,100}$/.test(token)) throw notFound();
  const parsed = decisionInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "invalid_request", "Choose consent, decline or delete.");
  const d = parsed.data;
  await authorize(c.principal, "referral.consent", { type: "org", id: c.org.id }, c.org);
  if (d.textVersion !== CONSENT_TEXT_VERSION) throw new AppError(409, "consent_text_changed", "The consent wording has changed. Reload the page and review it again.");
  // Billing is out of scope (D-10): agreeing to possible charges is recorded, nothing is charged here.
  if (d.decision === "consent" && !d.acceptCharges) throw new AppError(422, "charges_consent_required", "Confirm that you understand an assessment may be charged.");
  const status = d.decision === "consent" ? "consented" : d.decision === "decline" ? "declined" : "deleted";
  const actor = userActor(c.principal);

  return withOrg(c.org.id, async (tx) => {
    const id = (await tx.execute<{ id: string | null }>(sql`
      SELECT webmonitor_claim_referral(${hashToken(token)}, ${c.org.id}::uuid, ${c.principal.userId}::uuid, ${status}, ${now.toISOString()}::timestamptz) AS id`)).rows[0]?.id;
    if (!id) throw new AppError(410, "referral_unavailable", "This link has expired or was already used.");
    const subjects: ConsentSubject[] = d.decision === "consent"
      ? ["referral_assessment", "referral_charges", ...(d.shareStatus ? ["referral_share_status" as const] : [])]
      : d.decision === "decline" ? ["referral_declined"] : [];
    for (const subject of subjects) {
      await tx.insert(consents).values({ orgId: c.org.id, subject, textVersion: CONSENT_TEXT_VERSION, userId: c.principal.userId, referralId: id, createdAt: now });
    }
    if (d.decision === "consent" && d.shareStatus) await tx.update(webmonitorReferrals).set({ shareStatus: true }).where(eq(webmonitorReferrals.id, id));
    const r = (await tx.select().from(webmonitorReferrals).where(eq(webmonitorReferrals.id, id)))[0];
    const a = (await tx.select({ id: assets.id }).from(assets).where(eq(assets.host, r.host)).limit(1))[0];
    await audit(tx, {
      actor, action: `referral.${status}`, target: { type: "referral", id }, requestId: c.principal.requestId,
      details: { textVersion: CONSENT_TEXT_VERSION, subjects, shareStatus: r.shareStatus },
    });
    return { referralId: id, status, host: r.host, assetId: a?.id ?? null };
  });
}

/** Removes a claimed referral's context. Assessments already run under it are kept; nothing more is shared. */
export async function deleteReferral(c: Ctx, referralId: string) {
  if (!isUuid(referralId)) throw notFound();
  await authorize(c.principal, "referral.consent", { type: "org", id: c.org.id }, c.org);
  return withOrg(c.org.id, async (tx) => {
    const r = (await tx.update(webmonitorReferrals).set({ status: "deleted", summary: "", shareStatus: false })
      .where(eq(webmonitorReferrals.id, referralId)).returning({ id: webmonitorReferrals.id }))[0];
    if (!r) throw notFound();
    await audit(tx, { actor: userActor(c.principal), action: "referral.deleted", target: { type: "referral", id: r.id }, requestId: c.principal.requestId });
    return { referralId: r.id, status: "deleted" as const };
  });
}

export async function listReferrals(c: Ctx) {
  await authorize(c.principal, "referral.consent", { type: "org", id: c.org.id }, c.org);
  return withOrg(c.org.id, (tx) => tx.select({
    id: webmonitorReferrals.id, host: webmonitorReferrals.host, signalType: webmonitorReferrals.signalType, status: webmonitorReferrals.status,
    shareStatus: webmonitorReferrals.shareStatus, assessmentId: webmonitorReferrals.assessmentId, decidedAt: webmonitorReferrals.decidedAt,
  }).from(webmonitorReferrals).orderBy(desc(webmonitorReferrals.receivedAt)).limit(100));
}

/** A consented referral the launching asset matches by host (TC-WMON-005). Called inside launchAssessment's transaction. */
export async function referralForLaunch(tx: Tx, referralId: string, host: string) {
  if (!isUuid(referralId)) throw new AppError(422, "referral_invalid", "Unknown referral.");
  const r = (await tx.select().from(webmonitorReferrals).where(eq(webmonitorReferrals.id, referralId)).for("update"))[0];
  if (!r) throw new AppError(422, "referral_invalid", "Unknown referral.");
  if (r.status !== "consented") throw new AppError(422, "referral_not_consented", "This referral has not been consented to.");
  if (r.host !== host) throw new AppError(422, "referral_host_mismatch", "This referral is for a different host than the asset.");
  return r;
}

/** Queues a status link-back when the person agreed to share it. Called on assessment finish and on new FixProof. */
export async function queueReferralPublish(tx: Tx, orgId: string, referralId: string | null | undefined, cause: string) {
  if (!referralId) return;
  const r = (await tx.select({ status: webmonitorReferrals.status, share: webmonitorReferrals.shareStatus }).from(webmonitorReferrals)
    .where(eq(webmonitorReferrals.id, referralId)))[0];
  if (r?.status !== "consented" || !r.share) return;
  await enqueue(tx, { orgId, topic: "webmonitor.publish", businessKey: `webmonitor:${referralId}:${cause}`, payload: { referralId } });
}

/** Referrals whose assessments contain this finding (for FixProof link-backs). */
export async function referralsForFinding(tx: Tx, findingId: string): Promise<string[]> {
  const rows = await tx.selectDistinct({ id: assessments.referralId }).from(findingOccurrences)
    .innerJoin(assessments, eq(assessments.id, findingOccurrences.assessmentId))
    .where(and(eq(findingOccurrences.findingId, findingId), sql`${assessments.referralId} IS NOT NULL`));
  return rows.map((r) => r.id!).filter(Boolean);
}

/** Builds the minimal summary. Only counts and statuses: no titles, locations, evidence or hosts beyond the ref. */
export async function buildSummary(tx: Tx, referralId: string): Promise<ResultSummary | null> {
  const r = (await tx.select().from(webmonitorReferrals).where(eq(webmonitorReferrals.id, referralId)))[0];
  if (!r) return null;
  const a = r.assessmentId ? (await tx.select({ id: assessments.id, status: assessments.status }).from(assessments).where(eq(assessments.id, r.assessmentId)))[0] : null;
  let severityCounts: ResultSummary["severityCounts"] = null;
  let fixproofStatus: string | null = null;
  if (a) {
    const ids = (await tx.selectDistinct({ id: findingOccurrences.findingId }).from(findingOccurrences).where(eq(findingOccurrences.assessmentId, a.id))).map((x) => x.id);
    severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    if (ids.length) {
      for (const f of await tx.select({ severity: findings.severity }).from(findings).where(inArray(findings.id, ids))) severityCounts[f.severity] += 1;
      fixproofStatus = (await tx.select({ s: fixproofRecords.status }).from(fixproofRecords)
        .where(and(inArray(fixproofRecords.findingId, ids), sql`${fixproofRecords.supersededAt} IS NULL`)).orderBy(desc(fixproofRecords.createdAt)).limit(1))[0]?.s ?? null;
    }
  }
  return {
    externalRef: r.externalRef, assessmentStatus: a?.status ?? null, severityCounts, fixproofStatus,
    link: appUrl(a ? `/assessments/${a.id}` : "/"),
  };
}

/** Worker handler for webmonitor.publish (RS-WMON-003). Every attempt is recorded, including "not sent". */
export async function publishReferralResult(orgId: string, payload: { referralId?: unknown }): Promise<string> {
  const id = typeof payload.referralId === "string" ? payload.referralId : "";
  if (!isUuid(id)) return "invalid_payload";
  const prepared = await withOrg(orgId, async (tx) => {
    const r = (await tx.select().from(webmonitorReferrals).where(eq(webmonitorReferrals.id, id)))[0];
    if (!r) return { skip: "missing" as const };
    // Consent can be withdrawn (deleted) between queueing and sending.
    if (r.status !== "consented" || !r.shareStatus) return { skip: "not_shared" as const };
    return { summary: (await buildSummary(tx, id))! };
  });
  if ("skip" in prepared) return prepared.skip ?? "skipped";
  let out: Awaited<ReturnType<ReturnType<typeof webmonitorAdapter>["publishResult"]>>;
  try {
    out = await webmonitorAdapter().publishResult(prepared.summary);
  } catch (e) {
    out = { sent: false, reason: "adapter_error" };
    log.warn("webmonitor.publish_error", { referralId: id, error: e instanceof Error ? e.message : String(e) });
  }
  await withOrg(orgId, async (tx) => {
    await tx.insert(referralEvents).values({
      id: randomUUID(), orgId, referralId: id, kind: out.sent ? "result_published" : "result_not_sent", summary: prepared.summary, reason: out.sent ? null : out.reason,
    });
    await audit(tx, {
      actor: PUBLISHER, action: out.sent ? "referral.result_published" : "referral.result_not_sent", target: { type: "referral", id },
      outcome: out.sent ? "success" : "error", reason: out.sent ? undefined : out.reason,
      details: { assessmentStatus: prepared.summary.assessmentStatus, fixproofStatus: prepared.summary.fixproofStatus },
    });
  });
  return out.sent ? "published" : `not_sent:${out.reason}`;
}

export type FunnelCounts = { received: number; consented: number; verified: number; assessed: number; converted: number };

/** RS-WMON-004: counts only, across all orgs. Converted = an assessment under the referral finished with results. */
export async function referralFunnel(since: Date): Promise<FunnelCounts> {
  const r = (await db.execute<Record<keyof FunnelCounts, string>>(sql`SELECT * FROM referral_funnel_counts(${since.toISOString()}::timestamptz)`)).rows[0];
  return { received: Number(r.received), consented: Number(r.consented), verified: Number(r.verified), assessed: Number(r.assessed), converted: Number(r.converted) };
}
