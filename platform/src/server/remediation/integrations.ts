import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { and, desc, eq, sql } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg, isUuid } from "../db/client";
import { assets, repositoryIntegrations, repositoryWebhookDeliveries, type RepoScope } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, notFound } from "../errors";
import { authorize } from "../policy/policy";
import { userActor, type Ctx } from "./plans";
import { repoPath, repoTokenAad, resolveCommit } from "./repo";
import { assertRepoName, assertTokenShape, inspectRepository } from "./github";
import { seal, secretsConfigured } from "../attacks/secretbox";

// Repository integrations (RS-REMED-004, provisional local_git adapter). Least privilege: only the scopes needed to
// read code and open a change are ever requested; there is no merge or admin scope. Test commands are stored as argv
// arrays (no shell) and are snapshotted onto each sandbox run.

const SCOPES: RepoScope[] = ["contents:read", "pull_requests:write", "metadata:read"];
const argv = z.array(z.string().min(1).max(200)).min(1).max(20);

const createInput = z.object({
  name: z.string().trim().min(2).max(100),
  externalId: z.string().trim().min(1).max(100),
  defaultBranch: z.string().trim().min(1).max(100).default("main"),
  testCommands: z.array(argv).max(10).default([]),
});

export async function createIntegration(c: Ctx, input: unknown) {
  const parsed = createInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "invalid_request", parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  const d = parsed.data;
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  repoPath(d.externalId); // confined to the configured root, or 422/503
  await resolveCommit({ externalId: d.externalId, defaultBranch: d.defaultBranch }, d.defaultBranch);
  return withOrg(c.org.id, async (tx) => {
    const dup = (await tx.select({ id: repositoryIntegrations.id }).from(repositoryIntegrations)
      .where(and(eq(repositoryIntegrations.externalId, d.externalId), eq(repositoryIntegrations.status, "active"))))[0];
    if (dup) throw new AppError(409, "integration_exists", "This repository is already connected.");
    const row = (await tx.insert(repositoryIntegrations).values({
      orgId: c.org.id, type: "local_git", name: d.name, externalId: d.externalId, defaultBranch: d.defaultBranch,
      scopes: SCOPES, testCommands: d.testCommands, createdBy: c.principal.userId,
    }).returning())[0];
    await audit(tx, {
      actor: userActor(c.principal), action: "integration.created", target: { type: "repository_integration", id: row.id }, requestId: c.principal.requestId,
      details: { type: row.type, externalId: row.externalId, defaultBranch: row.defaultBranch, scopes: row.scopes, testCommands: row.testCommands },
    });
    return row;
  });
}

// ---------- GitHub (safe apply: a pull request, never a merge) ----------

const githubInput = z.object({
  name: z.string().trim().max(100).optional(),
  externalId: z.string().trim().min(3).max(140),
  token: z.string().trim().min(1).max(300),
  testCommands: z.array(argv).max(10).default([]),
});

/**
 * Connects a GitHub repository with the customer's fine-grained token (one repository; Contents and Pull requests
 * read and write). The token is checked against GitHub, then stored sealed; it is never shown again or logged.
 */
export async function createGithubIntegration(c: Ctx, input: unknown) {
  const parsed = githubInput.safeParse(input ?? {});
  if (!parsed.success) throw new AppError(422, "invalid_request", parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  const d = parsed.data;
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  const externalId = d.externalId.replace(/^https:\/\/github\.com\//i, "").replace(/\.git$/i, "").replace(/\/+$/, "");
  assertRepoName(externalId);
  assertTokenShape(d.token);
  if (!secretsConfigured()) throw new AppError(503, "secrets_unavailable", "This server cannot store tokens yet (no secrets key).");
  const info = await inspectRepository({ externalId, defaultBranch: "", type: "github", token: d.token });
  const id = randomUUID();
  const tokenEnc = seal(d.token, repoTokenAad(c.org.id, id));
  return withOrg(c.org.id, async (tx) => {
    const dup = (await tx.select({ id: repositoryIntegrations.id }).from(repositoryIntegrations)
      .where(and(eq(repositoryIntegrations.type, "github"), eq(repositoryIntegrations.externalId, externalId), eq(repositoryIntegrations.status, "active"))))[0];
    if (dup) throw new AppError(409, "integration_exists", "This repository is already connected.");
    const row = (await tx.insert(repositoryIntegrations).values({
      id, orgId: c.org.id, type: "github", name: d.name || externalId, externalId, defaultBranch: info.defaultBranch,
      scopes: SCOPES, testCommands: d.testCommands, tokenEnc, createdBy: c.principal.userId,
    }).returning())[0];
    await audit(tx, {
      actor: userActor(c.principal), action: "integration.created", target: { type: "repository_integration", id: row.id }, requestId: c.principal.requestId,
      details: { type: "github", externalId, defaultBranch: info.defaultBranch, private: info.private, tokenHasAdmin: info.admin, testCommands: row.testCommands },
    });
    return { ...row, tokenEnc: null, tokenHasAdmin: info.admin };
  });
}

export async function listIntegrations(c: Ctx) {
  const rows = await withOrg(c.org.id, (tx) => tx.select().from(repositoryIntegrations).orderBy(desc(repositoryIntegrations.createdAt)).limit(100));
  return rows.map((r) => ({ ...r, tokenEnc: null }));
}

export async function disableIntegration(c: Ctx, id: string) {
  if (!isUuid(id)) throw notFound();
  await authorize(c.principal, "integration.manage", { type: "org", id: c.org.id }, c.org);
  return withOrg(c.org.id, async (tx) => {
    const row = (await tx.update(repositoryIntegrations).set({ status: "disabled" })
      .where(and(eq(repositoryIntegrations.id, id), eq(repositoryIntegrations.status, "active"))).returning())[0];
    if (!row) throw notFound();
    // A repository asset is authorized only through its integration, so it lapses with it (runs in flight stop at the next gate).
    const lapsed = await tx.update(assets).set({ status: "lapsed" }).where(and(eq(assets.repositoryIntegrationId, id), eq(assets.status, "verified"))).returning({ id: assets.id });
    await audit(tx, { actor: userActor(c.principal), action: "integration.disabled", target: { type: "repository_integration", id }, requestId: c.principal.requestId, details: { lapsedAssets: lapsed.map((a) => a.id) } });
    return row;
  });
}

// ---------- webhook (a hint to look, never a source of truth) ----------

export const WEBHOOK_TOLERANCE_MS = 5 * 60_000;

/** Per-integration key derived from the server secret, so one leaked integration key does not sign for others. */
export function webhookKey(integrationId: string, secret = process.env.RUYA_WEBHOOK_SECRET): Buffer | null {
  if (!secret || secret.length < 32) return null;
  return createHmac("sha256", secret).update(integrationId).digest();
}

export function signWebhook(integrationId: string, ts: string, body: string, secret?: string): string {
  const key = webhookKey(integrationId, secret);
  if (!key) throw new Error("RUYA_WEBHOOK_SECRET is not configured");
  return `sha256=${createHmac("sha256", key).update(`${ts}.${body}`).digest("hex")}`;
}

export type WebhookResult = { status: number; code: string; orgId?: string; integrationId?: string };

/** Verifies and records one delivery. Returns what to do; the caller triggers observation on "accepted". */
export async function acceptWebhook(h: { integration?: string | null; delivery?: string | null; event?: string | null; timestamp?: string | null; signature?: string | null }, body: string, now = Date.now()): Promise<WebhookResult> {
  const id = h.integration ?? "";
  if (!isUuid(id) || !h.delivery || !/^[A-Za-z0-9._:-]{8,100}$/.test(h.delivery) || !h.event || !/^[a-z_.]{1,50}$/.test(h.event) || !h.timestamp || !h.signature) {
    return { status: 400, code: "invalid_headers" };
  }
  const ts = Number(h.timestamp);
  if (!Number.isFinite(ts) || Math.abs(now - ts * 1000) > WEBHOOK_TOLERANCE_MS) return { status: 401, code: "stale_timestamp" };
  const key = webhookKey(id);
  if (!key) return { status: 503, code: "webhooks_disabled" };
  const expected = Buffer.from(`sha256=${createHmac("sha256", key).update(`${h.timestamp}.${body}`).digest("hex")}`);
  const given = Buffer.from(h.signature);
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return { status: 401, code: "bad_signature" };

  const org = (await db.execute<{ org_id: string | null }>(sql`SELECT repository_integration_org(${id}::uuid) AS org_id`)).rows[0]?.org_id;
  if (!org) return { status: 404, code: "unknown_integration" };
  return withOrg(org, async (tx) => {
    const i = (await tx.select().from(repositoryIntegrations).where(eq(repositoryIntegrations.id, id)))[0];
    if (!i || i.status !== "active") return { status: 404, code: "unknown_integration" };
    const ins = await tx.insert(repositoryWebhookDeliveries).values({ orgId: org, integrationId: id, deliveryId: h.delivery!, event: h.event! })
      .onConflictDoNothing().returning({ id: repositoryWebhookDeliveries.id });
    if (!ins.length) return { status: 200, code: "duplicate", orgId: org, integrationId: id };
    await audit(tx, { actor: { type: "service", id: "repository-webhook" }, action: "integration.webhook_received", target: { type: "repository_integration", id }, details: { deliveryId: h.delivery, event: h.event } });
    return { status: 202, code: "accepted", orgId: org, integrationId: id };
  });
}
