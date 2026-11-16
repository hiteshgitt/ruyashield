import { createHash, randomUUID } from "node:crypto";
import { and, desc, eq, gte, inArray, sql, type SQL } from "drizzle-orm";
import { z } from "zod";
import { db, isUuid, withOrg, type Tx } from "../db/client";
import { assets, attackEvents, attackSources, type AttackSourceStatus } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, forbidden, notFound } from "../errors";
import { assertPro, authorize, decide, type OrgFlags, type Principal } from "../policy/policy";
import { randomToken, sha256 } from "../auth/session";
import { notifyAdmins } from "../notifications/notifications";
import { assetScope } from "../reports/summary";
import type { FetchLike } from "../assessments/deps";
import { ATTACK_TYPES, type AttackType } from "./classify";
import { CloudflareError, MAX_LOOKBACK_MS, PAGE_LIMIT, fetchFirewallEvents, type CfEvent } from "./cloudflare";
import { geoip, type GeoLookup } from "./geoip";
import { parseBatch } from "./logparse";
import { SecretKeyMissing, open, seal, secretsConfigured } from "./secretbox";

/**
 * Attack-origin monitoring (where hostile traffic against a verified asset comes from).
 * Passive only: events are read from the customer's Cloudflare zone or pushed by an agent on their own server.
 * Nothing here probes, blocks or replays anything. Visitor IPs are personal data: only suspicious events are kept,
 * query strings are stripped, and rows are purged after 90 days. A source that cannot be read shows as "error",
 * and a period with no source shows as "no data": never as "no attacks".
 */
type Ctx = { principal: Principal; org: OrgFlags & { id: string } };
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });
const SERVICE = { type: "service" as const, id: "attack-monitor" };

export const POLL_EVERY_MS = 5 * 60_000;
export const POLL_BACKOFF_MS = 15 * 60_000;
export const SPIKE_THRESHOLD = 100; // events per asset per clock hour
export const STATS_DAYS = [1, 7, 30, 90] as const;
const aad = (orgId: string, sourceId: string) => `attack_source:${orgId}:${sourceId}`;

// ---------- sources ----------

const nameField = z.string().trim().min(1, "Name the source.").max(100);
const cfInput = z.object({
  assetId: z.string().refine(isUuid, "Pick an asset."),
  name: nameField,
  zoneId: z.string().trim().toLowerCase().regex(/^[a-f0-9]{32}$/, "The zone ID is the 32-character hex ID on the zone's Overview page."),
  token: z.string().trim().regex(/^[A-Za-z0-9_-]{30,200}$/, "Paste the API token (letters, digits, - and _)."),
});
const agentInput = z.object({ assetId: z.string().refine(isUuid, "Pick an asset."), name: nameField });

async function verifiedDomain(tx: Tx, assetId: string) {
  const a = (await tx.select().from(assets).where(eq(assets.id, assetId)).limit(1))[0];
  if (!a) throw new AppError(422, "invalid_request", "Unknown asset.");
  if (a.kind !== "domain") throw new AppError(422, "invalid_request", "Attack monitoring works on website (domain) assets.");
  if (a.status !== "verified") throw new AppError(422, "asset_not_verified", "Verify ownership of this asset before monitoring attacks on it.");
  return a;
}

export async function createCloudflareSource(c: Ctx, input: unknown) {
  assertPro(c.org);
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  const v = cfInput.safeParse(input);
  if (!v.success) throw new AppError(422, "invalid_request", v.error.issues[0].message);
  if (!secretsConfigured()) throw new AppError(422, "secrets_key_not_configured", "Set RUYA_SECRETS_KEY (32+ characters) on the server before saving a Cloudflare token.");
  const id = randomUUID();
  return withOrg(c.org.id, async (tx) => {
    await verifiedDomain(tx, v.data.assetId);
    await tx.insert(attackSources).values({
      id, orgId: c.org.id, assetId: v.data.assetId, kind: "cloudflare", name: v.data.name, cfZoneId: v.data.zoneId,
      cfTokenEnc: seal(v.data.token, aad(c.org.id, id)), createdBy: c.principal.userId, nextPollAt: new Date(),
    });
    // The token is never audited or logged.
    await audit(tx, { actor: userActor(c.principal), action: "attacks.source_created", target: { type: "attack_source", id }, requestId: c.principal.requestId, details: { kind: "cloudflare", assetId: v.data.assetId, name: v.data.name, zoneId: v.data.zoneId } });
    return { id };
  });
}

/** Creates a log-agent source. The ingest token is returned once and stored only as a SHA-256 hash. */
export async function createLogAgentSource(c: Ctx, input: unknown) {
  assertPro(c.org);
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  const v = agentInput.safeParse(input);
  if (!v.success) throw new AppError(422, "invalid_request", v.error.issues[0].message);
  const token = `rs_${randomToken(32)}`;
  const prefix = token.slice(0, 9);
  return withOrg(c.org.id, async (tx) => {
    await verifiedDomain(tx, v.data.assetId);
    const [row] = await tx.insert(attackSources).values({
      orgId: c.org.id, assetId: v.data.assetId, kind: "log_agent", name: v.data.name, ingestTokenHash: sha256(token),
      ingestPrefix: prefix, createdBy: c.principal.userId,
    }).returning({ id: attackSources.id });
    await audit(tx, { actor: userActor(c.principal), action: "attacks.source_created", target: { type: "attack_source", id: row.id }, requestId: c.principal.requestId, details: { kind: "log_agent", assetId: v.data.assetId, name: v.data.name, prefix } });
    return { id: row.id, token, prefix };
  });
}

/** Disables a source for good: the stored Cloudflare token is wiped and an agent token stops working. Events stay until purged. */
export async function disableSource(c: Ctx, id: string) {
  if (!isUuid(id)) throw notFound();
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  await withOrg(c.org.id, async (tx) => {
    const s = (await tx.select({ id: attackSources.id, kind: attackSources.kind, status: attackSources.status }).from(attackSources).where(eq(attackSources.id, id)).limit(1))[0];
    if (!s) throw notFound();
    if (s.status === "disabled") return;
    // cf_token_enc must stay non-null for the kind CHECK; overwrite it with a tombstone that cannot decrypt.
    await tx.update(attackSources).set({ status: "disabled", nextPollAt: null, lastError: null, ...(s.kind === "cloudflare" ? { cfTokenEnc: "revoked" } : {}) })
      .where(eq(attackSources.id, id));
    await audit(tx, { actor: userActor(c.principal), action: "attacks.source_disabled", target: { type: "attack_source", id }, requestId: c.principal.requestId, details: { kind: s.kind } });
  });
}

export interface SourceView {
  id: string; assetId: string; assetHost: string; kind: "cloudflare" | "log_agent"; name: string; status: AttackSourceStatus;
  zoneId: string | null; prefix: string | null; lastPolledAt: Date | null; lastEventAt: Date | null; lastError: string | null; createdAt: Date;
}

async function viewGate(c: Ctx) {
  const p = c.principal;
  if (!decide(p, "dashboard.view", { type: "org", ownerId: p.userId }, c.org).allow) throw forbidden();
  await authorize(p, "dashboard.view", { type: "org", id: c.org.id, ownerId: p.userId }, c.org);
  return assetScope(p, "dashboard.view", null);
}

export async function listSources(c: Ctx): Promise<SourceView[]> {
  assertPro(c.org);
  const scope = await viewGate(c);
  return withOrg(c.org.id, (tx) => tx.select({
    id: attackSources.id, assetId: attackSources.assetId, assetHost: assets.host, kind: attackSources.kind, name: attackSources.name,
    status: attackSources.status, zoneId: attackSources.cfZoneId, prefix: attackSources.ingestPrefix, lastPolledAt: attackSources.lastPolledAt,
    lastEventAt: attackSources.lastEventAt, lastError: attackSources.lastError, createdAt: attackSources.createdAt,
  }).from(attackSources).innerJoin(assets, eq(assets.id, attackSources.assetId))
    .where(scope.length ? and(...scope) : undefined).orderBy(desc(attackSources.createdAt)));
}

// ---------- stats ----------

export interface AttackStats {
  days: number; since: Date; assetId: string | null;
  /** "none": no active source covers this view, so zero events means "no data", not "no attacks". */
  coverage: "none" | "partial" | "full";
  sources: { total: number; active: number; error: number; pending: number };
  geoip: { country: boolean; asn: boolean };
  total: number; uniqueIps: number; countries: number; blocked: number;
  byCountry: { country: string | null; n: number }[];
  byIp: { ip: string; country: string | null; asOrg: string | null; n: number; last: Date }[];
  byAsn: { asn: number | null; asOrg: string | null; n: number }[];
  byType: { type: string; label: string; n: number }[];
  timeline: { day: string; n: number }[];
  recent: { occurredAt: Date; ip: string; country: string | null; asOrg: string | null; attackType: string; action: string; method: string | null; path: string | null; statusCode: number | null; assetHost: string }[];
}

const typeLabel = (t: string) => (ATTACK_TYPES as Record<string, string>)[t] ?? "Other";

export async function getStats(c: Ctx, opts: { assetId?: string | null; days?: number } = {}, now = new Date()): Promise<AttackStats> {
  assertPro(c.org);
  const scope = await viewGate(c);
  const days = (STATS_DAYS as readonly number[]).includes(opts.days ?? 7) ? (opts.days ?? 7) : 7;
  const assetId = opts.assetId || null;
  if (assetId && !isUuid(assetId)) throw new AppError(422, "invalid_filter", "Unknown asset.");
  const since = new Date(now.getTime() - days * 86_400_000);
  const g = await geoip();

  return withOrg(c.org.id, async (tx) => {
    const where: SQL[] = [eq(attackEvents.orgId, c.org.id), gte(attackEvents.occurredAt, since), ...scope];
    if (assetId) where.push(eq(attackEvents.assetId, assetId));
    const w = and(...where);
    const base = <T extends Record<string, unknown>>(cols: T) => tx.select(cols as never).from(attackEvents).innerJoin(assets, eq(assets.id, attackEvents.assetId)).where(w);

    const srcWhere: SQL[] = [...scope];
    if (assetId) srcWhere.push(eq(attackSources.assetId, assetId));
    const src = await tx.select({ status: attackSources.status, n: sql<number>`count(*)::int` }).from(attackSources)
      .innerJoin(assets, eq(assets.id, attackSources.assetId)).where(srcWhere.length ? and(...srcWhere) : undefined).groupBy(attackSources.status);
    const sc = (s: string) => src.find((r) => r.status === s)?.n ?? 0;
    const sources = { total: src.reduce((a, r) => a + (r.status === "disabled" ? 0 : r.n), 0), active: sc("active"), error: sc("error"), pending: sc("pending") };
    const coverage: AttackStats["coverage"] = sources.active === 0 ? "none" : sources.error + sources.pending > 0 ? "partial" : "full";

    const [tot] = (await base({
      total: sql<number>`count(*)::int`, uniqueIps: sql<number>`count(distinct ${attackEvents.ip})::int`,
      countries: sql<number>`count(distinct ${attackEvents.country})::int`,
      blocked: sql<number>`count(*) filter (where ${attackEvents.action} in ('block','drop','managed_challenge','challenge','jschallenge'))::int`,
    })) as unknown as { total: number; uniqueIps: number; countries: number; blocked: number }[];

    const byCountry = (await tx.select({ country: attackEvents.country, n: sql<number>`count(*)::int` }).from(attackEvents)
      .innerJoin(assets, eq(assets.id, attackEvents.assetId)).where(w).groupBy(attackEvents.country).orderBy(sql`count(*) desc`).limit(15));
    const byIp = (await tx.select({
      ip: attackEvents.ip, country: sql<string | null>`max(${attackEvents.country})`, asOrg: sql<string | null>`max(${attackEvents.asOrg})`,
      n: sql<number>`count(*)::int`, last: sql<Date>`max(${attackEvents.occurredAt})`,
    }).from(attackEvents).innerJoin(assets, eq(assets.id, attackEvents.assetId)).where(w).groupBy(attackEvents.ip).orderBy(sql`count(*) desc`).limit(15))
      .map((r) => ({ ...r, last: new Date(r.last) }));
    const byAsn = await tx.select({ asn: attackEvents.asn, asOrg: sql<string | null>`max(${attackEvents.asOrg})`, n: sql<number>`count(*)::int` })
      .from(attackEvents).innerJoin(assets, eq(assets.id, attackEvents.assetId)).where(w).groupBy(attackEvents.asn).orderBy(sql`count(*) desc`).limit(10);
    const byType = (await tx.select({ type: attackEvents.attackType, n: sql<number>`count(*)::int` }).from(attackEvents)
      .innerJoin(assets, eq(assets.id, attackEvents.assetId)).where(w).groupBy(attackEvents.attackType).orderBy(sql`count(*) desc`))
      .map((r) => ({ ...r, label: typeLabel(r.type) }));
    const dayRows = await tx.select({ day: sql<string>`to_char(date_trunc('day', ${attackEvents.occurredAt} at time zone 'UTC'), 'YYYY-MM-DD')`, n: sql<number>`count(*)::int` })
      .from(attackEvents).innerJoin(assets, eq(assets.id, attackEvents.assetId)).where(w).groupBy(sql`1`);
    const counts = new Map(dayRows.map((r) => [r.day, r.n]));
    const timeline: { day: string; n: number }[] = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 86_400_000).toISOString().slice(0, 10);
      timeline.push({ day: d, n: counts.get(d) ?? 0 });
    }
    const recent = await tx.select({
      occurredAt: attackEvents.occurredAt, ip: attackEvents.ip, country: attackEvents.country, asOrg: attackEvents.asOrg,
      attackType: attackEvents.attackType, action: attackEvents.action, method: attackEvents.method, path: attackEvents.path,
      statusCode: attackEvents.statusCode, assetHost: assets.host,
    }).from(attackEvents).innerJoin(assets, eq(assets.id, attackEvents.assetId)).where(w).orderBy(desc(attackEvents.occurredAt)).limit(50);

    return {
      days, since, assetId, coverage, sources, geoip: { country: g.country, asn: g.asn },
      total: tot?.total ?? 0, uniqueIps: tot?.uniqueIps ?? 0, countries: tot?.countries ?? 0, blocked: tot?.blocked ?? 0,
      byCountry, byIp, byAsn, byType, timeline, recent,
    };
  });
}

// ---------- storing events ----------

interface NewEvent {
  occurredAt: Date; ip: string; country: string | null; asn: number | null; asOrg: string | null; action: string;
  attackType: AttackType; ruleId: string | null; method: string | null; path: string | null; statusCode: number | null;
  userAgent: string | null; dedupeKey: string;
}

/** Deterministic UUID for "this asset, this hour" so a spike notifies each admin once per hour. */
export function spikeSourceId(assetId: string, at: Date): string {
  const h = createHash("sha256").update(`attack-spike:${assetId}:${at.toISOString().slice(0, 13)}`).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

async function store(tx: Tx, orgId: string, assetId: string, sourceId: string, events: NewEvent[], now: Date): Promise<number> {
  let inserted = 0;
  for (let i = 0; i < events.length; i += 500) {
    const chunk = events.slice(i, i + 500);
    const r = await tx.insert(attackEvents).values(chunk.map((e) => ({ orgId, assetId, sourceId, ...e }))).onConflictDoNothing().returning({ id: attackEvents.id });
    inserted += r.length;
  }
  if (inserted > 0) await spikeCheck(tx, orgId, assetId, now);
  return inserted;
}

async function spikeCheck(tx: Tx, orgId: string, assetId: string, now: Date) {
  const hourStart = new Date(Math.floor(now.getTime() / 3_600_000) * 3_600_000);
  const [r] = await tx.select({ n: sql<number>`count(*)::int` }).from(attackEvents)
    .where(and(eq(attackEvents.assetId, assetId), gte(attackEvents.createdAt, hourStart)));
  if ((r?.n ?? 0) < SPIKE_THRESHOLD) return;
  const [a] = await tx.select({ host: assets.host }).from(assets).where(eq(assets.id, assetId)).limit(1);
  await notifyAdmins(tx, orgId, {
    kind: "attack_spike", title: `Attack spike on ${a?.host ?? "an asset"}: ${r.n} suspicious requests this hour`,
    link: `/attacks?assetId=${assetId}&days=1`, sourceId: spikeSourceId(assetId, hourStart),
  });
}

// ---------- log agent ingest ----------

const ingestHits = new Map<string, number[]>();
export const INGEST_MAX_PER_MIN = 60;
function ingestRateLimited(sourceId: string, now: number): boolean {
  const recent = (ingestHits.get(sourceId) ?? []).filter((t) => t > now - 60_000);
  recent.push(now);
  ingestHits.set(sourceId, recent);
  if (ingestHits.size > 10_000) ingestHits.clear();
  return recent.length > INGEST_MAX_PER_MIN;
}

export interface IngestResult { received: number; stored: number; suspicious: number; unparsed: number }

/** Accepts raw access-log lines from the agent. Benign lines and raw text are discarded; only parsed suspicious events are kept. */
export async function ingest(token: string, lines: string[], now = new Date(), lookup?: GeoLookup): Promise<IngestResult> {
  if (!/^rs_[A-Za-z0-9_-]{20,100}$/.test(token)) throw new AppError(401, "invalid_token", "Invalid ingest token.");
  const res = await db.execute<{ org_id: string; source_id: string; asset_id: string; status: string }>(
    sql`SELECT org_id, source_id, asset_id, status FROM attack_source_by_ingest_hash(${sha256(token)})`,
  );
  const s = res.rows[0];
  if (!s || s.status === "disabled") throw new AppError(401, "invalid_token", "Invalid ingest token.");
  if (ingestRateLimited(s.source_id, now.getTime())) throw new AppError(429, "rate_limited", "Too many batches; send at most one per second.");
  const { events, received, unparsed } = parseBatch(lines, now);
  const geo = lookup ?? (await geoip()).lookup;
  const rows: NewEvent[] = events.map((e) => ({
    ...geo(e.ip), occurredAt: e.occurredAt, ip: e.ip, action: "logged", attackType: e.attackType, ruleId: null,
    method: e.method, path: e.path, statusCode: e.status, userAgent: e.userAgent, dedupeKey: e.dedupeKey,
  }));
  const stored = await withOrg(s.org_id, async (tx) => {
    const a = (await tx.select({ status: assets.status }).from(assets).where(eq(assets.id, s.asset_id)).limit(1))[0];
    // Ownership lapsed or revoked: stop storing visitor data for this asset.
    if (!a || a.status !== "verified") throw new AppError(403, "asset_not_verified", "The asset is no longer verified.");
    const n = rows.length ? await store(tx, s.org_id, s.asset_id, s.source_id, rows, now) : 0;
    const last = rows.reduce<Date | null>((m, e) => (!m || e.occurredAt > m ? e.occurredAt : m), null);
    await tx.update(attackSources).set({
      status: "active", lastPolledAt: now, lastError: null, ...(last ? { lastEventAt: sql`greatest(${attackSources.lastEventAt}, ${last})` } : {}),
    }).where(eq(attackSources.id, s.source_id));
    return n;
  });
  return { received, stored, suspicious: events.length, unparsed };
}

// ---------- Cloudflare poller (worker) ----------

export interface PollReport { polled: number; stored: number; errors: number; details: { source: string; reason: string; detail: string | null }[] }

/** Polls every Cloudflare source that is due. Errors mark the source "error" with a short reason; they never read as "no attacks". */
export async function pollAttackSources(fetchImpl: FetchLike = fetch as unknown as FetchLike, now = new Date(), lookup?: GeoLookup): Promise<PollReport> {
  const due = await db.execute<{ org_id: string; source_id: string }>(sql`SELECT org_id, source_id FROM attack_sources_due_poll()`);
  const report: PollReport = { polled: 0, stored: 0, errors: 0, details: [] };
  for (const d of due.rows) {
    // Lease: push next_poll_at out first so a second worker skips this row.
    const lease = await withOrg(d.org_id, async (tx) => {
      const r = await tx.update(attackSources).set({ nextPollAt: new Date(now.getTime() + POLL_BACKOFF_MS) })
        .where(and(eq(attackSources.id, d.source_id), inArray(attackSources.status, ["pending", "active", "error"]),
          sql`(${attackSources.nextPollAt} IS NULL OR ${attackSources.nextPollAt} <= ${now})`))
        .returning();
      if (!r[0]) return null;
      const a = (await tx.select({ host: assets.host, status: assets.status }).from(assets).where(eq(assets.id, r[0].assetId)).limit(1))[0];
      return { src: r[0], asset: a };
    });
    if (!lease) continue;
    report.polled++;
    const { src, asset } = lease;
    let outcome: { ok: true; events: CfEvent[] } | { ok: false; reason: string };
    if (!asset || asset.status !== "verified") outcome = { ok: false, reason: "asset_not_verified" };
    else {
      try {
        const token = open(src.cfTokenEnc ?? "", aad(d.org_id, src.id));
        const since = new Date(Math.max(src.cursorAt?.getTime() ?? 0, now.getTime() - MAX_LOOKBACK_MS));
        const events = await fetchFirewallEvents(fetchImpl, token, src.cfZoneId ?? "", since, now, asset.host);
        outcome = { ok: true, events };
      } catch (e) {
        const reason = e instanceof CloudflareError || e instanceof SecretKeyMissing ? e.message
          : e instanceof Error && /^secret_/.test(e.message) ? e.message : "cloudflare_failed";
        outcome = { ok: false, reason };
        report.details.push({ source: src.id, reason, detail: e instanceof CloudflareError ? e.detail ?? null : null });
      }
    }
    const g = lookup;
    await withOrg(d.org_id, async (tx) => {
      if (!outcome.ok) {
        report.errors++;
        await tx.update(attackSources).set({ status: "error", lastError: outcome.reason, lastPolledAt: now, nextPollAt: new Date(now.getTime() + POLL_BACKOFF_MS) })
          .where(eq(attackSources.id, src.id));
        if (src.status !== "error" || src.lastError !== outcome.reason) {
          await audit(tx, { actor: SERVICE, action: "attacks.source_error", target: { type: "attack_source", id: src.id }, outcome: "error", reason: outcome.reason });
        }
        return;
      }
      const evs = outcome.events;
      const rows: NewEvent[] = evs.map((e) => {
        // Cloudflare's own geo is used; MaxMind fills gaps when configured.
        const fill = g && (!e.country || !e.asn) ? g(e.ip) : null;
        return {
          occurredAt: e.occurredAt, ip: e.ip, country: e.country ?? fill?.country ?? null, asn: e.asn ?? fill?.asn ?? null,
          asOrg: e.asOrg ?? fill?.asOrg ?? null, action: e.action, attackType: e.attackType, ruleId: e.ruleId, method: e.method,
          path: e.path, statusCode: null, userAgent: e.userAgent, dedupeKey: e.dedupeKey,
        };
      });
      const n = rows.length ? await store(tx, d.org_id, src.assetId, src.id, rows, now) : 0;
      report.stored += n;
      const full = evs.length >= PAGE_LIMIT;
      const last = evs.length ? evs[evs.length - 1].occurredAt : null;
      // A full page means more is waiting: resume right after the last event, sooner.
      const cursor = full && last ? last : now;
      await tx.update(attackSources).set({
        status: "active", lastError: null, lastPolledAt: now, cursorAt: cursor,
        nextPollAt: new Date(now.getTime() + (full ? 60_000 : POLL_EVERY_MS)),
        ...(last ? { lastEventAt: sql`greatest(${attackSources.lastEventAt}, ${last})` } : {}),
      }).where(eq(attackSources.id, src.id));
      if (src.status !== "active") {
        await audit(tx, { actor: SERVICE, action: "attacks.source_active", target: { type: "attack_source", id: src.id } });
      }
    });
  }
  return report;
}
