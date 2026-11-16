import { and, asc, eq, inArray, sql } from "drizzle-orm";
import { withOrg, isUuid, type Tx } from "../db/client";
import { assets, assetSuggestions } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, notFound } from "../errors";
import { authorize, type OrgFlags, type Principal } from "../policy/policy";
import { grantFor } from "../policy/matrix";
import { addAsset } from "./assets";

/**
 * Suggested assets (scanner M5): hosts that discovery (Certificate Transparency) saw under a verified asset.
 * A suggestion is only a hint. Adding one creates an ordinary unverified asset, which must pass ownership
 * verification before any active check can run against it.
 */
type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
const MAX_PER_RUN = 500;

/** Called inside the assessment write transaction. Re-seen hosts get last_seen bumped; decisions are kept. */
export async function recordSuggestions(tx: Tx, orgId: string, sourceAssetId: string, hosts: unknown) {
  if (!Array.isArray(hosts)) return 0;
  const list = [...new Set(hosts.filter((h): h is string => typeof h === "string" && h.length <= 253))].slice(0, MAX_PER_RUN);
  if (!list.length) return 0;
  await tx.insert(assetSuggestions).values(list.map((host) => ({ orgId, sourceAssetId, host, source: "ct" })))
    .onConflictDoUpdate({ target: [assetSuggestions.orgId, assetSuggestions.host], set: { lastSeen: sql`now()` } });
  return list.length;
}

/** Open suggestions that are not already assets in the organization. */
export async function listSuggestions(c: Ctx) {
  if (grantFor(c.principal.role, "asset.view") === "N") throw new AppError(403, "forbidden");
  return withOrg(c.org.id, async (tx) => {
    const rows = await tx.select().from(assetSuggestions).where(eq(assetSuggestions.status, "suggested")).orderBy(asc(assetSuggestions.host));
    if (!rows.length) return [];
    const existing = new Set((await tx.select({ host: assets.host }).from(assets).where(inArray(assets.host, rows.map((r) => r.host)))).map((r) => r.host));
    return rows.filter((r) => !existing.has(r.host));
  });
}

async function loadOpen(tx: Tx, id: string) {
  if (!isUuid(id)) throw notFound();
  const s = (await tx.select().from(assetSuggestions).where(eq(assetSuggestions.id, id)).for("update"))[0];
  if (!s) throw notFound();
  if (s.status !== "suggested") throw new AppError(409, "already_decided", "This suggestion was already handled.");
  return s;
}

/** Adds the suggested host as an unverified asset. Ownership verification is still required before scanning. */
export async function addSuggestion(c: Ctx, id: string, environment: "production" | "staging" | "development" = "production") {
  await authorize(c.principal, "asset.edit", { type: "asset", clientGroupId: null }, c.org);
  const s = await withOrg(c.org.id, (tx) => loadOpen(tx, id));
  const asset = await addAsset(c, { host: s.host, environment });
  await withOrg(c.org.id, async (tx) => {
    await tx.update(assetSuggestions).set({ status: "added", decidedBy: c.principal.userId, decidedAt: new Date() })
      .where(and(eq(assetSuggestions.id, s.id), eq(assetSuggestions.status, "suggested")));
  });
  return asset;
}

export async function dismissSuggestion(c: Ctx, id: string) {
  await authorize(c.principal, "asset.edit", { type: "asset", clientGroupId: null }, c.org);
  return withOrg(c.org.id, async (tx) => {
    const s = await loadOpen(tx, id);
    await tx.update(assetSuggestions).set({ status: "dismissed", decidedBy: c.principal.userId, decidedAt: new Date() }).where(eq(assetSuggestions.id, s.id));
    await audit(tx, { actor: { type: "user", id: c.principal.userId, ip: c.principal.ip }, action: "asset.suggestion_dismissed", target: { type: "asset_suggestion", id: s.id }, requestId: c.principal.requestId, details: { host: s.host } });
  });
}
