import { randomUUID } from "node:crypto";
import { and, eq, inArray } from "drizzle-orm";
import { z } from "zod";
import { isUuid, withOrg, type Tx } from "../db/client";
import { assets, edgeConnections, findings } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, notFound } from "../errors";
import { assertPro, authorize, decide, type OrgFlags, type Principal } from "../policy/policy";
import { open, seal, secretsConfigured } from "../attacks/secretbox";
import { OPEN_STATUSES } from "../findings/lifecycle";
import { transition } from "../findings/findings";
import { requestVerification } from "../verification/verification";
import { log } from "../log";
import {
  EdgeError, FIX_KEYS, HEADER_FIXES, applyHeaderRule, assertToken, assertZoneId, inspectZone, removeHeaderRule, type FixKey,
} from "./cloudflare";

// Safe apply at the edge (Cloudflare). Connecting and applying need integration.manage, which requires a sign-in with
// MFA in the last 15 minutes: that fresh confirmation, on a screen showing the exact headers, is the approval.
// After applying, the fixed findings are marked "fix applied" and re-tested, so the result is proven, not assumed.

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
const aad = (orgId: string, id: string) => `edge_connection:${orgId}:${id}`;
const HEADER_CHECK = "http.security_headers";

const asApp = (e: unknown): never => {
  if (e instanceof EdgeError) throw new AppError(e.status === 503 ? 503 : e.status === 429 ? 429 : 422, e.code, e.message);
  throw e;
};

async function webAsset(tx: Tx, c: Ctx, assetId: string) {
  if (!isUuid(assetId)) throw notFound();
  const a = (await tx.select().from(assets).where(eq(assets.id, assetId)).limit(1))[0];
  if (!a || !decide(c.principal, "asset.view", { type: "asset", id: a.id, clientGroupId: a.clientGroupId }, c.org).allow) throw notFound();
  if (a.kind !== "domain") throw new AppError(422, "invalid_request", "Header fixes work on website assets.");
  if (a.status !== "verified") throw new AppError(422, "asset_not_verified", "Verify ownership of this website first.");
  return a;
}

async function activeConnection(tx: Tx, assetId: string) {
  return (await tx.select().from(edgeConnections).where(and(eq(edgeConnections.assetId, assetId), eq(edgeConnections.status, "active"))).limit(1))[0] ?? null;
}

export type EdgeView = {
  connection: { id: string; zoneId: string; zoneName: string; appliedFixes: FixKey[]; appliedAt: Date | null; lastError: string | null } | null;
  /** Each fix with the open findings it would resolve on this website. */
  fixes: { key: FixKey; header: string; value: string; note: string; findings: { id: string; title: string; status: string }[] }[];
};

export async function getEdge(c: Ctx, assetId: string): Promise<EdgeView> {
  return withOrg(c.org.id, async (tx) => {
    const a = await webAsset(tx, c, assetId).catch(() => null);
    if (!a) return { connection: null, fixes: [] };
    const conn = await activeConnection(tx, a.id);
    const open = await tx.select({ id: findings.id, title: findings.title, issueKey: findings.issueKey, status: findings.status }).from(findings)
      .where(and(eq(findings.assetId, a.id), eq(findings.checkKey, HEADER_CHECK), inArray(findings.status, [...OPEN_STATUSES])));
    return {
      connection: conn && {
        id: conn.id, zoneId: conn.zoneId, zoneName: conn.zoneName, appliedFixes: (conn.appliedFixes ?? []) as FixKey[],
        appliedAt: conn.appliedAt, lastError: conn.lastError,
      },
      fixes: HEADER_FIXES.map((f) => ({
        key: f.key, header: f.header, value: f.value, note: f.note,
        findings: open.filter((x) => (f.issues as readonly string[]).includes(x.issueKey)).map((x) => ({ id: x.id, title: x.title, status: x.status })),
      })),
    };
  });
}

const connectInput = z.object({
  assetId: z.string(),
  zoneId: z.string().trim().toLowerCase(),
  token: z.string().trim(),
});

export async function connectEdge(c: Ctx, input: unknown) {
  assertPro(c.org);
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  const v = connectInput.safeParse(input ?? {});
  if (!v.success) throw new AppError(422, "invalid_request", "Fill in the zone ID and token.");
  try { assertZoneId(v.data.zoneId); assertToken(v.data.token); } catch (e) { asApp(e); }
  if (!secretsConfigured()) throw new AppError(503, "secrets_unavailable", "This server cannot store tokens yet (no secrets key).");
  const a = await withOrg(c.org.id, async (tx) => {
    const x = await webAsset(tx, c, v.data.assetId);
    if (await activeConnection(tx, x.id)) throw new AppError(409, "edge_exists", "Cloudflare is already connected for this website.");
    return x;
  });
  const { zoneName } = await inspectZone(v.data.token, v.data.zoneId, a.host).catch(asApp);
  const id = randomUUID();
  return withOrg(c.org.id, async (tx) => {
    await tx.insert(edgeConnections).values({
      id, orgId: c.org.id, assetId: a.id, zoneId: v.data.zoneId, zoneName, tokenEnc: seal(v.data.token, aad(c.org.id, id)), createdBy: c.principal.userId,
    });
    await audit(tx, { actor: userActor(c.principal), action: "edge.connected", target: { type: "asset", id: a.id }, requestId: c.principal.requestId, details: { provider: "cloudflare", zoneId: v.data.zoneId, zoneName } });
    return { id, zoneName };
  });
}

const applyInput = z.object({ assetId: z.string(), fixes: z.array(z.enum(FIX_KEYS as [FixKey, ...FixKey[]])).max(FIX_KEYS.length) });

/** Sets the chosen headers on Cloudflare for this host, then marks the findings they fix as applied and re-tests them. */
export async function applyEdgeFixes(c: Ctx, input: unknown) {
  assertPro(c.org);
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  const v = applyInput.safeParse(input ?? {});
  if (!v.success || !v.data.fixes.length) throw new AppError(422, "no_fixes_selected", "Tick at least one header to apply.");
  const fixes = [...new Set(v.data.fixes)];
  const { a, conn } = await withOrg(c.org.id, async (tx) => {
    const x = await webAsset(tx, c, v.data.assetId);
    const k = await activeConnection(tx, x.id);
    if (!k) throw new AppError(409, "edge_not_connected", "Connect Cloudflare for this website first.");
    return { a: x, conn: k };
  });
  const token = open(conn.tokenEnc, aad(c.org.id, conn.id));
  try {
    await applyHeaderRule(token, conn.zoneId, a.id, a.host, fixes);
  } catch (e) {
    const code = e instanceof EdgeError ? e.code : "cloudflare_apply_failed";
    await withOrg(c.org.id, async (tx) => {
      await tx.update(edgeConnections).set({ lastError: code }).where(eq(edgeConnections.id, conn.id));
      await audit(tx, { actor: userActor(c.principal), action: "edge.apply_failed", target: { type: "asset", id: a.id }, outcome: "error", reason: code, requestId: c.principal.requestId, details: { fixes } });
    });
    asApp(e);
  }
  const now = new Date();
  await withOrg(c.org.id, async (tx) => {
    await tx.update(edgeConnections).set({ appliedFixes: fixes, appliedAt: now, appliedBy: c.principal.userId, lastError: null }).where(eq(edgeConnections.id, conn.id));
    await audit(tx, {
      actor: userActor(c.principal), action: "edge.applied", target: { type: "asset", id: a.id }, requestId: c.principal.requestId,
      details: { provider: "cloudflare", zoneId: conn.zoneId, host: a.host, headers: HEADER_FIXES.filter((f) => fixes.includes(f.key)).map((f) => `${f.header}: ${f.value}`) },
    });
  });
  const retested = await retestFixed(c, a.id, fixes, now);
  return { fixes, retested };
}

/** Walks each fixed finding to "fix applied" through the normal transitions (each one permission-checked and audited) and asks for a re-test. */
async function retestFixed(c: Ctx, assetId: string, fixes: FixKey[], at: Date): Promise<number> {
  const issues = HEADER_FIXES.filter((f) => fixes.includes(f.key)).flatMap((f) => [...f.issues]);
  const rows = await withOrg(c.org.id, (tx) => tx.select({ id: findings.id, status: findings.status }).from(findings)
    .where(and(eq(findings.assetId, assetId), eq(findings.checkKey, HEADER_CHECK), inArray(findings.issueKey, issues), inArray(findings.status, [...OPEN_STATUSES]))));
  const reason = "Header set at Cloudflare by RuyaShield.";
  const path: Record<string, string[]> = {
    new: ["triage", "confirm", "start_remediation", "mark_fix_applied"], triaged: ["confirm", "start_remediation", "mark_fix_applied"],
    confirmed: ["start_remediation", "mark_fix_applied"], reopened: ["start_remediation", "mark_fix_applied"], in_remediation: ["mark_fix_applied"], fix_pending_verification: [],
  };
  let n = 0;
  for (const f of rows) {
    try {
      for (const kind of path[f.status] ?? []) await transition(c, f.id, kind, { reason });
      await requestVerification(c, f.id, { idempotencyKey: `edge:${f.id}:${at.getTime()}` });
      n++;
    } catch (e) {
      log.warn("edge.retest_skipped", { findingId: f.id, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return n;
}

/** Deletes RuyaShield's rule on Cloudflare. The findings come back on the next scan if the headers are still missing. */
export async function undoEdgeFixes(c: Ctx, assetId: string) {
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  const { a, conn } = await withOrg(c.org.id, async (tx) => {
    const x = await webAsset(tx, c, assetId);
    const k = await activeConnection(tx, x.id);
    if (!k) throw new AppError(409, "edge_not_connected", "Cloudflare is not connected for this website.");
    return { a: x, conn: k };
  });
  const removed = await removeHeaderRule(open(conn.tokenEnc, aad(c.org.id, conn.id)), conn.zoneId, a.id).catch(asApp);
  await withOrg(c.org.id, async (tx) => {
    await tx.update(edgeConnections).set({ appliedFixes: null, appliedAt: null, lastError: null }).where(eq(edgeConnections.id, conn.id));
    await audit(tx, { actor: userActor(c.principal), action: "edge.undone", target: { type: "asset", id: a.id }, requestId: c.principal.requestId, details: { zoneId: conn.zoneId, ruleRemoved: removed } });
  });
  return { removed };
}

/** Removes the rule (if it can) and forgets the token. */
export async function disconnectEdge(c: Ctx, assetId: string) {
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  const { a, conn } = await withOrg(c.org.id, async (tx) => {
    const x = await webAsset(tx, c, assetId);
    const k = await activeConnection(tx, x.id);
    if (!k) throw new AppError(409, "edge_not_connected", "Cloudflare is not connected for this website.");
    return { a: x, conn: k };
  });
  let ruleLeft = false;
  if (conn.appliedFixes?.length) {
    try { await removeHeaderRule(open(conn.tokenEnc, aad(c.org.id, conn.id)), conn.zoneId, a.id); } catch { ruleLeft = true; }
  }
  await withOrg(c.org.id, async (tx) => {
    await tx.update(edgeConnections).set({ status: "disabled", tokenEnc: "removed", appliedFixes: null }).where(eq(edgeConnections.id, conn.id));
    await audit(tx, { actor: userActor(c.principal), action: "edge.disconnected", target: { type: "asset", id: a.id }, requestId: c.principal.requestId, details: { zoneId: conn.zoneId, ruleLeft } });
  });
  return { ruleLeft };
}
