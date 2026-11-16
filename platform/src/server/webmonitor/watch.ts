import { and, desc, eq, gt, inArray, isNull, lt, sql } from "drizzle-orm";
import { withOrg, type Tx } from "../db/client";
import { apiTokens, webmonitorWatchedHosts } from "../db/schema";
import { grantFor } from "../policy/matrix";
import type { OrgFlags, Principal } from "../policy/policy";
import { listAssets } from "../assets/assets";
import { createApiToken, TOKEN_MAX_DAYS } from "../tokens/tokens";

// Which sites a connected WebMonitor account watches for uptime. WebMonitor's posture call sends the host
// names of every site it monitors; each call refreshes their last sighting. A host counts as watched while it
// was seen in the last WATCH_FRESH_DAYS; rows older than WATCH_KEEP_DAYS are deleted.

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };

export const WATCH_FRESH_DAYS = 3;
export const WATCH_KEEP_DAYS = 30;
export const WEBMONITOR_TOKEN_NAME = "WebMonitor";
export const WEBMONITOR_SCOPES = ["assets:read", "findings:read"] as const;
const DAY = 86_400_000;

export const webmonitorUrl = (path = "/app") =>
  new URL(path, process.env.WEBMONITOR_URL ?? "https://webmonitor.ruyalab.com").toString();

/** The WebMonitor link that opens "Add site" with this host filled in. */
export const webmonitorAddSiteUrl = (host: string) => `${webmonitorUrl("/app")}?addSite=${encodeURIComponent(`https://${host}`)}`;

/** www.example.com and example.com are the same site for this purpose. */
export const siteKey = (host: string) => host.replace(/^www\./, "");

/** Called from the posture endpoint inside its org transaction; only for calls made with an API token. */
export async function recordWatchedHosts(tx: Tx, orgId: string, tokenId: string, hosts: string[], now = new Date()) {
  if (hosts.length) {
    await tx.insert(webmonitorWatchedHosts)
      .values(hosts.map((host) => ({ orgId, host, tokenId, firstSeenAt: now, lastSeenAt: now })))
      .onConflictDoUpdate({
        target: [webmonitorWatchedHosts.orgId, webmonitorWatchedHosts.host],
        set: { lastSeenAt: now, tokenId },
      });
  }
  await tx.delete(webmonitorWatchedHosts)
    .where(and(eq(webmonitorWatchedHosts.orgId, orgId), lt(webmonitorWatchedHosts.lastSeenAt, new Date(now.getTime() - WATCH_KEEP_DAYS * DAY))));
}

export interface WebMonitorCoverage {
  /** Domain assets this person can see, with whether WebMonitor watches them. */
  assets: { id: string; host: string; name: string; status: string; watched: boolean }[];
  /** Sites WebMonitor watches that are not RuyaShield assets yet (only for people who can add assets). */
  notInRuyaShield: string[];
  /** When WebMonitor last checked in for this org, or null if it never has (or not recently). */
  lastSeenAt: Date | null;
}

export async function webmonitorCoverage(c: Ctx, now = new Date()): Promise<WebMonitorCoverage> {
  const visible = (await listAssets(c)).filter((a) => a.kind === "domain");
  const rows = await withOrg(c.org.id, (tx) => tx.select({ host: webmonitorWatchedHosts.host, lastSeenAt: webmonitorWatchedHosts.lastSeenAt })
    .from(webmonitorWatchedHosts)
    .where(gt(webmonitorWatchedHosts.lastSeenAt, new Date(now.getTime() - WATCH_FRESH_DAYS * DAY)))
    .orderBy(desc(webmonitorWatchedHosts.lastSeenAt)));
  const watched = new Set(rows.map((r) => siteKey(r.host)));
  const canAdd = grantFor(c.principal.role, "asset.edit") !== "N";
  // Every asset the org has (not just visible ones) decides "already in RuyaShield", so a restricted member is
  // never told to add a site a colleague already added; they only see the list if they can add assets anyway.
  const known = new Set(visible.map((a) => siteKey(a.host)));
  if (canAdd && rows.length) {
    const all = await withOrg(c.org.id, (tx) => tx.execute<{ host: string }>(sql`SELECT host FROM assets WHERE kind = 'domain'`));
    for (const r of all.rows) known.add(siteKey(r.host));
  }
  const missing = new Map<string, string>();
  for (const r of rows) {
    const k = siteKey(r.host);
    if (known.has(k)) continue;
    // Prefer the bare domain when WebMonitor sent both forms.
    if (!missing.has(k) || r.host === k) missing.set(k, r.host);
  }
  return {
    assets: visible.map((a) => ({ id: a.id, host: a.host, name: a.displayName, status: a.status, watched: watched.has(siteKey(a.host)) })),
    notInRuyaShield: canAdd ? [...missing.values()].sort() : [],
    lastSeenAt: rows[0]?.lastSeenAt ?? null,
  };
}

/** Active tokens that WebMonitor has used, newest first, for the settings page. */
export async function webmonitorConnections(c: Ctx, now = new Date()) {
  return withOrg(c.org.id, async (tx) => {
    const seen = await tx.select({ tokenId: webmonitorWatchedHosts.tokenId, lastSeenAt: sql<Date>`max(${webmonitorWatchedHosts.lastSeenAt})`, sites: sql<number>`count(DISTINCT regexp_replace(${webmonitorWatchedHosts.host}, '^www\\.', ''))::int` })
      .from(webmonitorWatchedHosts)
      .where(gt(webmonitorWatchedHosts.lastSeenAt, new Date(now.getTime() - WATCH_FRESH_DAYS * DAY)))
      .groupBy(webmonitorWatchedHosts.tokenId);
    const ids = seen.map((s) => s.tokenId).filter((x): x is string => !!x);
    if (!ids.length) return [];
    const tokens = await tx.select({ id: apiTokens.id, name: apiTokens.name, prefix: apiTokens.prefix, expiresAt: apiTokens.expiresAt })
      .from(apiTokens).where(and(inArray(apiTokens.id, ids), isNull(apiTokens.revokedAt), gt(apiTokens.expiresAt, now)));
    return tokens.map((t) => {
      const s = seen.find((x) => x.tokenId === t.id)!;
      return { ...t, lastSeenAt: new Date(s.lastSeenAt), sites: Number(s.sites) };
    }).sort((a, b) => b.lastSeenAt.getTime() - a.lastSeenAt.getTime());
  });
}

/** One click: a read-only token with exactly the scopes WebMonitor needs, valid for the longest allowed time. */
export function createWebMonitorToken(c: Ctx) {
  return createApiToken(c, { name: WEBMONITOR_TOKEN_NAME, scopes: [...WEBMONITOR_SCOPES], days: TOKEN_MAX_DAYS });
}
