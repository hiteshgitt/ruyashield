import { randomBytes } from "node:crypto";
import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { z } from "zod";
import { withOrg, isUuid, type Tx } from "../db/client";
import { assets, assetVerifications, attestations, clientGroups, orgs, repositoryIntegrations, type VerificationMethod } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, isUniqueViolation, notFound } from "../errors";
import { authorize, decide, type OrgFlags, type Principal, type Resource } from "../policy/policy";
import { grantFor } from "../policy/matrix";
import { assertNotPrivate, parseHost } from "./host";
import { instructions, runCheck, TOKEN_PREFIX, type CheckDeps, type CheckOutcome } from "./check";

export const VERIFICATION_TTL_MS = 14 * 24 * 60 * 60 * 1000;
export const REVERIFY_INTERVAL_MS = 30 * 24 * 60 * 60 * 1000;
export const REVERIFY_RETRY_MS = 24 * 60 * 60 * 1000;
export const REVERIFY_MAX_FAILURES = 2;
export const METHODS: VerificationMethod[] = ["dns_txt", "http_file", "meta_tag"];

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
type AssetRow = typeof assets.$inferSelect;
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
const res = (a: AssetRow): Resource => ({ type: "asset", id: a.id, clientGroupId: a.clientGroupId, ownerId: a.createdBy });

async function loadAsset(tx: Tx, id: string, lock = false) {
  if (!isUuid(id)) throw notFound();
  const q = tx.select().from(assets).where(eq(assets.id, id));
  const a = (lock ? await q.for("update") : await q)[0];
  if (!a) throw notFound();
  return a;
}

/** Visible to the principal? Out-of-scope assets are reported as 404 so their existence is not disclosed (BOLA). */
function canView(p: Principal, a: AssetRow, org: OrgFlags) {
  return decide(p, "asset.view", res(a), org).allow;
}

const addInput = z.object({
  host: z.string(),
  displayName: z.string().trim().max(80).optional(),
  environment: z.enum(["production", "staging", "development"]).default("production"),
  clientGroupId: z.string().uuid().nullish(),
});

export async function addAsset(c: Ctx, input: unknown) {
  const parsed = addInput.safeParse(input);
  if (!parsed.success) throw new AppError(422, "validation_failed", parsed.error.issues[0].message);
  const host = parseHost(parsed.data.host);
  const clientGroupId = parsed.data.clientGroupId ?? null;
  await authorize(c.principal, "asset.edit", { type: "asset", clientGroupId }, c.org);
  await assertNotPrivate(host);
  return withOrg(c.org.id, async (tx) => {
    if (clientGroupId && !(await tx.select({ id: clientGroups.id }).from(clientGroups).where(eq(clientGroups.id, clientGroupId))).length) {
      throw new AppError(422, "validation_failed", "Unknown client group.");
    }
    // Already added: point to the existing asset instead of failing (the catch below still covers a concurrent add).
    const existing = (await tx.select({ id: assets.id }).from(assets).where(eq(assets.host, host)).limit(1))[0];
    if (existing) throw new AppError(409, "asset_exists", `${host} is already in this organization.`, { assetId: existing.id });
    const a = (await tx.insert(assets).values({
      orgId: c.org.id, host, displayName: parsed.data.displayName || host, environment: parsed.data.environment,
      clientGroupId, createdBy: c.principal.userId,
    }).returning().catch((e: unknown) => {
      if (isUniqueViolation(e)) throw new AppError(409, "asset_exists", `${host} is already in this organization.`);
      throw e;
    }))[0];
    await audit(tx, { actor: userActor(c.principal), action: "asset.created", target: { type: "asset", id: a.id }, requestId: c.principal.requestId, details: { host, environment: a.environment, clientGroupId } });
    return a;
  });
}

/**
 * Adds a connected repository as an asset so repository checks (deps.osv, ...) can run and raise findings against it.
 * No DNS/HTTP ownership challenge: the org admin connected the repository themselves, which is the proof of control.
 * The asset stays only as authorized as its integration; disabling the integration lapses it.
 */
export async function addRepositoryAsset(c: Ctx, integrationId: string) {
  if (!isUuid(integrationId)) throw notFound();
  await authorize(c.principal, "asset.edit", { type: "asset", clientGroupId: null }, c.org);
  return withOrg(c.org.id, async (tx) => {
    const i = (await tx.select().from(repositoryIntegrations).where(eq(repositoryIntegrations.id, integrationId)))[0];
    if (!i) throw notFound();
    if (i.status !== "active") throw new AppError(409, "integration_disabled", "This repository connection is disabled.");
    const host = `repo:${i.externalId}`;
    const now = new Date();
    const existing = (await tx.select().from(assets).where(eq(assets.host, host)).for("update"))[0];
    if (existing && existing.repositoryIntegrationId === i.id && existing.status === "verified") return { asset: existing, created: false };
    const fields = { status: "verified" as const, verifiedAt: now, verifiedMethod: "repository_integration", nextReverifyAt: null, reverifyFailures: 0, repositoryIntegrationId: i.id };
    const a = existing
      // Reconnected repository: relink the existing asset so its finding history carries on.
      ? (await tx.update(assets).set(fields).where(eq(assets.id, existing.id)).returning())[0]
      : (await tx.insert(assets).values({ orgId: c.org.id, kind: "repository", host, displayName: i.name, environment: "production", createdBy: c.principal.userId, ...fields }).returning())[0];
    await audit(tx, {
      actor: userActor(c.principal), action: existing ? "asset.relinked" : "asset.created", target: { type: "asset", id: a.id }, requestId: c.principal.requestId,
      details: { kind: "repository", host, integrationId: i.id, basis: "repository_integration" },
    });
    return { asset: a, created: !existing };
  });
}

export async function listAssets(c: Ctx) {
  if (grantFor(c.principal.role, "asset.view") === "N") throw new AppError(403, "forbidden");
  return withOrg(c.org.id, async (tx) => {
    const rows = await tx.select().from(assets).orderBy(assets.host);
    return rows.filter((a) => canView(c.principal, a, c.org));
  });
}

export async function getAsset(c: Ctx, id: string) {
  return withOrg(c.org.id, async (tx) => {
    const a = await loadAsset(tx, id);
    if (!canView(c.principal, a, c.org)) throw notFound();
    const verifications = await tx.select().from(assetVerifications).where(eq(assetVerifications.assetId, id)).orderBy(desc(assetVerifications.createdAt)).limit(20);
    const atts = await tx.select().from(attestations).where(eq(attestations.assetId, id)).orderBy(desc(attestations.createdAt));
    const o = (await tx.select({ a2: orgs.allowIntrusiveNetwork }).from(orgs).where(eq(orgs.id, c.org.id)))[0];
    return { asset: a, verifications, attestations: atts, eligibility: eligibilityOf(a, atts, undefined, { a2: !!o?.a2 }) };
  });
}

// ---------- ownership verification (RS-ASSET-002/003) ----------

export async function startVerification(c: Ctx, assetId: string, method: string) {
  if (!(METHODS as string[]).includes(method)) throw new AppError(422, "validation_failed", "Unknown verification method.");
  return withOrg(c.org.id, async (tx) => {
    const a = await loadAsset(tx, assetId);
    if (!canView(c.principal, a, c.org)) throw notFound();
    await authorize(c.principal, "asset.verify", res(a), c.org);
    if (a.status === "revoked") throw new AppError(409, "asset_revoked", "This asset was removed from scope.");
    if (a.kind === "repository") throw new AppError(409, "not_applicable", "Repository assets are authorized by their repository connection, not a DNS or HTTP challenge.");
    // A new challenge supersedes any open one for this asset.
    await tx.update(assetVerifications).set({ status: "expired", reason: "superseded" })
      .where(and(eq(assetVerifications.assetId, a.id), eq(assetVerifications.status, "pending")));
    const token = TOKEN_PREFIX + randomBytes(16).toString("hex");
    const v = (await tx.insert(assetVerifications).values({
      orgId: c.org.id, assetId: a.id, method: method as VerificationMethod, token,
      expiresAt: new Date(Date.now() + VERIFICATION_TTL_MS), createdBy: c.principal.userId,
    }).returning())[0];
    await audit(tx, { actor: userActor(c.principal), action: "asset.verification_started", target: { type: "asset", id: a.id }, requestId: c.principal.requestId, details: { method, verificationId: v.id } });
    return { verification: v, instructions: instructions(v.method, a.host, token) };
  });
}

/** Runs the check for a pending challenge. The network call happens outside any DB transaction. */
export async function checkVerification(c: Ctx, verificationId: string, deps: CheckDeps = {}) {
  if (!isUuid(verificationId)) throw notFound();
  // The check contacts the customer's host, so the scanning kill switch stops it too (fail safe).
  if (c.org.killScanning) {
    await withOrg(c.org.id, (tx) => audit(tx, {
      actor: userActor(c.principal), action: "authz.denied", target: { type: "asset_verification", id: verificationId },
      outcome: "denied", reason: "kill_switch_engaged", requestId: c.principal.requestId, details: { attempted: "asset.verify.check" },
    }));
    throw new AppError(423, "kill_switch_engaged", "Scanning is stopped for this organization. Release the kill switch to run checks.");
  }
  const { a, v } = await withOrg(c.org.id, async (tx) => {
    const v = (await tx.select().from(assetVerifications).where(eq(assetVerifications.id, verificationId)))[0];
    if (!v) throw notFound();
    const a = await loadAsset(tx, v.assetId);
    if (!canView(c.principal, a, c.org)) throw notFound();
    await authorize(c.principal, "asset.verify", res(a), c.org);
    if (v.status !== "pending") throw new AppError(409, "verification_closed", `This challenge is ${v.status}. Start a new one.`);
    if (v.expiresAt <= new Date()) {
      await tx.update(assetVerifications).set({ status: "expired", reason: "challenge_expired" }).where(eq(assetVerifications.id, v.id));
      throw new AppError(409, "verification_expired", "This challenge expired. Start a new one.");
    }
    const claimed = await tx.update(assetVerifications).set({ status: "checking" })
      .where(and(eq(assetVerifications.id, v.id), eq(assetVerifications.status, "pending"))).returning({ id: assetVerifications.id });
    if (!claimed.length) throw new AppError(409, "verification_busy", "A check is already running.");
    return { a, v };
  });

  let outcome: CheckOutcome;
  try {
    outcome = await runCheck(v.method, a.host, v.token, deps);
  } catch {
    outcome = { status: "error", reason: "internal_error", evidence: {} };
  }

  return withOrg(c.org.id, async (tx) => {
    // passed closes the challenge; failed/error leave it open (pending) so the user can fix and retry.
    await tx.update(assetVerifications).set({
      status: outcome.status === "passed" ? "passed" : "pending",
      reason: outcome.reason, evidence: { ...outcome.evidence, result: outcome.status }, checkedAt: new Date(),
    }).where(eq(assetVerifications.id, v.id));
    if (outcome.status === "passed") {
      await tx.update(assets).set({
        status: "verified", verifiedAt: new Date(), verifiedMethod: v.method, reverifyFailures: 0,
        nextReverifyAt: new Date(Date.now() + REVERIFY_INTERVAL_MS),
      }).where(eq(assets.id, a.id));
    }
    await audit(tx, {
      actor: userActor(c.principal), action: outcome.status === "passed" ? "asset.verified" : "asset.verification_failed",
      target: { type: "asset", id: a.id }, outcome: outcome.status === "passed" ? "success" : outcome.status === "error" ? "error" : "denied",
      reason: outcome.reason, requestId: c.principal.requestId, details: { method: v.method, verificationId: v.id },
    });
    return outcome;
  });
}

/**
 * RS-ASSET-003 periodic re-verification, run by the worker as the service principal.
 * Two consecutive failures (a day apart) lapse the asset; an inconclusive check does not count as passing.
 */
export async function reverifyAsset(orgId: string, assetId: string, deps: CheckDeps = {}) {
  const prep = await withOrg(orgId, async (tx) => {
    const a = (await tx.select().from(assets).where(eq(assets.id, assetId)))[0];
    if (!a || a.kind === "repository" || (a.status !== "verified" && a.status !== "lapsed")) return null;
    const v = (await tx.select().from(assetVerifications)
      .where(and(eq(assetVerifications.assetId, a.id), eq(assetVerifications.status, "passed")))
      .orderBy(desc(assetVerifications.checkedAt)).limit(1))[0];
    return { a, v: v ?? null };
  });
  if (!prep) return null;
  const { a, v } = prep;
  const outcome: CheckOutcome = v ? await runCheck(v.method, a.host, v.token, deps).catch(() => ({ status: "error" as const, reason: "internal_error", evidence: {} }))
    : { status: "failed", reason: "no_passed_challenge", evidence: {} };

  return withOrg(orgId, async (tx) => {
    const actor = { type: "service" as const, id: "reverifier" };
    if (outcome.status === "passed") {
      await tx.update(assets).set({ status: "verified", verifiedAt: new Date(), reverifyFailures: 0, nextReverifyAt: new Date(Date.now() + REVERIFY_INTERVAL_MS) }).where(eq(assets.id, a.id));
      await audit(tx, { actor, action: "asset.reverified", target: { type: "asset", id: a.id }, details: { method: v?.method } });
      return outcome;
    }
    const failures = a.reverifyFailures + 1;
    const lapse = failures >= REVERIFY_MAX_FAILURES;
    await tx.update(assets).set({
      reverifyFailures: failures, status: lapse ? "lapsed" : a.status,
      nextReverifyAt: new Date(Date.now() + REVERIFY_RETRY_MS),
    }).where(eq(assets.id, a.id));
    await audit(tx, {
      actor, action: lapse ? "asset.verification_lapsed" : "asset.reverify_failed", target: { type: "asset", id: a.id },
      outcome: outcome.status === "error" ? "error" : "denied", reason: outcome.reason, details: { failures, method: v?.method },
    });
    return outcome;
  });
}

// ---------- third-party authorization (RS-ASSET-004) ----------

const MAX_ATTESTATION_DAYS = 366;
const attestInput = z.object({
  partyName: z.string().trim().min(2).max(120),
  partyRole: z.string().trim().min(2).max(120),
  partyEmail: z.string().trim().toLowerCase().email("Enter the authorizing party's email"),
  relationship: z.enum(["client", "parent_company", "subsidiary", "hosting_customer", "other"]),
  allowedClasses: z.array(z.enum(["P", "A1"])).min(1, "Choose at least one permitted test class"),
  validFrom: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  validTo: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  confirm: z.literal(true, { message: "You must confirm you hold written authorization." }),
}).refine((d) => d.validTo > d.validFrom, { message: "The end date must be after the start date.", path: ["validTo"] })
  .refine((d) => (Date.parse(d.validTo) - Date.parse(d.validFrom)) / 86_400_000 <= MAX_ATTESTATION_DAYS, { message: "Authorizations can last at most 12 months.", path: ["validTo"] });

export async function recordAttestation(c: Ctx, assetId: string, input: unknown) {
  const parsed = attestInput.safeParse(input);
  if (!parsed.success) throw new AppError(422, "validation_failed", parsed.error.issues[0].message);
  const d = parsed.data;
  return withOrg(c.org.id, async (tx) => {
    const a = await loadAsset(tx, assetId);
    if (!canView(c.principal, a, c.org)) throw notFound();
    await authorize(c.principal, "asset.attest", res(a), c.org);
    const row = (await tx.insert(attestations).values({
      orgId: c.org.id, assetId: a.id, partyName: d.partyName, partyRole: d.partyRole, partyEmail: d.partyEmail,
      relationship: d.relationship, allowedClasses: d.allowedClasses, validFrom: d.validFrom, validTo: d.validTo,
      recordedBy: c.principal.userId,
    }).returning())[0];
    await audit(tx, { actor: userActor(c.principal), action: "asset.authorization_recorded", target: { type: "asset", id: a.id }, requestId: c.principal.requestId,
      details: { attestationId: row.id, partyName: d.partyName, partyEmail: d.partyEmail, allowedClasses: d.allowedClasses, validFrom: d.validFrom, validTo: d.validTo } });
    return row;
  });
}

export async function revokeAttestation(c: Ctx, attestationId: string, reason: string) {
  if (!isUuid(attestationId)) throw notFound();
  return withOrg(c.org.id, async (tx) => {
    const at = (await tx.select().from(attestations).where(eq(attestations.id, attestationId)))[0];
    if (!at) throw notFound();
    const a = await loadAsset(tx, at.assetId);
    if (!canView(c.principal, a, c.org)) throw notFound();
    await authorize(c.principal, "asset.attest", res(a), c.org);
    const r = await tx.update(attestations).set({ revokedAt: new Date() }).where(and(eq(attestations.id, at.id), isNull(attestations.revokedAt))).returning({ id: attestations.id });
    if (!r.length) throw new AppError(409, "already_revoked");
    await audit(tx, { actor: userActor(c.principal), action: "asset.authorization_revoked", target: { type: "asset", id: a.id }, reason: reason?.slice(0, 500) || null, requestId: c.principal.requestId, details: { attestationId: at.id } });
  });
}

// ---------- eligibility (consumed by later phases) ----------

export type Eligibility = { eligible: boolean; basis: "ownership" | "attestation" | null; allowedClasses: ("P" | "A1" | "A2")[]; reason: string };

/**
 * Whether an asset may be assessed at all, and which classes. X is never executable.
 * A2 (scanner M3) is granted only for a host whose ownership is verified, and only when the org has turned on
 * intrusive network checks (two-person opt-in). A third-party authorization never grants A2.
 */
export function eligibilityOf(a: AssetRow, atts: (typeof attestations.$inferSelect)[], today = new Date().toISOString().slice(0, 10), opts: { a2?: boolean } = {}): Eligibility {
  if (a.status === "revoked") return { eligible: false, basis: null, allowedClasses: [], reason: "Asset removed from scope." };
  if (a.kind === "repository") {
    // Repositories are authorized only by their connection; a written authorization cannot stand in for it.
    return a.status === "verified"
      ? { eligible: true, basis: "ownership", allowedClasses: ["P", "A1"], reason: "Repository connected by your organization." }
      : { eligible: false, basis: null, allowedClasses: [], reason: "The repository connection was disconnected." };
  }
  if (a.status === "verified") return { eligible: true, basis: "ownership", allowedClasses: opts.a2 ? ["P", "A1", "A2"] : ["P", "A1"], reason: "Ownership verified." };
  const live = atts.filter((t) => !t.revokedAt && t.validFrom <= today && today < t.validTo);
  if (live.length) {
    const classes = [...new Set(live.flatMap((t) => t.allowedClasses))].filter((x): x is "P" | "A1" => x === "P" || x === "A1");
    return { eligible: true, basis: "attestation", allowedClasses: classes, reason: "Covered by a recorded third-party authorization." };
  }
  if (a.status === "lapsed") return { eligible: false, basis: null, allowedClasses: [], reason: "Ownership verification lapsed. Re-verify to resume testing." };
  return { eligible: false, basis: null, allowedClasses: [], reason: "Not verified. Verify ownership or record written authorization." };
}

/** Scheduler helper: claims due assets by pushing next_reverify_at forward (a lease) so they are enqueued once. */
export async function leaseDueReverifications(): Promise<{ orgId: string; assetId: string }[]> {
  const { db } = await import("../db/client");
  const due = await db.execute<{ org_id: string; asset_id: string }>(sql`SELECT * FROM assets_due_reverify()`);
  const out: { orgId: string; assetId: string }[] = [];
  for (const r of due.rows) {
    const leased = await withOrg(r.org_id, (tx) => tx.update(assets).set({ nextReverifyAt: new Date(Date.now() + 60 * 60 * 1000) })
      .where(and(eq(assets.id, r.asset_id), sql`next_reverify_at <= now()`)).returning({ id: assets.id }));
    if (leased.length) out.push({ orgId: r.org_id, assetId: r.asset_id });
  }
  return out;
}
