import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { z } from "zod";
import { db, isUuid, withOrg } from "../db/client";
import { apiTokens, users } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError, notFound } from "../errors";
import { authorize, type OrgFlags, type Principal } from "../policy/policy";
import { TOKEN_SCOPES, type TokenScope } from "../policy/matrix";
import { randomToken, sha256, type SessionInfo } from "../auth/session";
import { loadPrincipal, type LoadedPrincipal } from "../principal";

type Ctx = { principal: Principal; org: OrgFlags & { id: string } };

export const TOKEN_MAX_DAYS = 366;
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });

const createInput = z.object({
  name: z.string().trim().min(1, "Name the token.").max(80),
  scopes: z.array(z.enum(TOKEN_SCOPES as [TokenScope, ...TokenScope[]])).min(1, "Pick at least one scope."),
  days: z.number().int().min(1, "Use 1 to 366 days.").max(TOKEN_MAX_DAYS, "Use 1 to 366 days."),
});

/**
 * FR-058: a read-mostly token that acts as its creator, limited to the chosen scopes.
 * The secret is returned once and stored only as a SHA-256 hash.
 */
export async function createApiToken(c: Ctx, input: unknown): Promise<{ id: string; token: string; prefix: string; expiresAt: Date }> {
  await authorize(c.principal, "token.manage", { type: "org", id: c.org.id }, c.org);
  const v = createInput.safeParse(input);
  if (!v.success) throw new AppError(422, "validation_failed", v.error.issues[0].message);
  const token = `rs_${randomToken(32)}`;
  const prefix = token.slice(0, 9);
  const expiresAt = new Date(Date.now() + v.data.days * 86_400_000);
  const scopes = [...new Set(v.data.scopes)];
  const id = await withOrg(c.org.id, async (tx) => {
    const [row] = await tx.insert(apiTokens).values({
      orgId: c.org.id, userId: c.principal.userId, name: v.data.name, prefix, tokenHash: sha256(token), scopes, expiresAt,
    }).returning({ id: apiTokens.id });
    await audit(tx, { actor: userActor(c.principal), action: "token.created", target: { type: "api_token", id: row.id }, requestId: c.principal.requestId, details: { name: v.data.name, prefix, scopes, expiresAt: expiresAt.toISOString() } });
    return row.id;
  });
  return { id, token, prefix, expiresAt };
}

export async function listApiTokens(c: Ctx) {
  await authorize(c.principal, "token.manage", { type: "org", id: c.org.id }, c.org);
  return withOrg(c.org.id, (tx) => tx.select({
    id: apiTokens.id, name: apiTokens.name, prefix: apiTokens.prefix, scopes: apiTokens.scopes, userId: apiTokens.userId,
    createdBy: users.displayName, expiresAt: apiTokens.expiresAt, createdAt: apiTokens.createdAt,
    revokedAt: apiTokens.revokedAt, lastUsedAt: apiTokens.lastUsedAt,
  }).from(apiTokens).leftJoin(users, eq(users.id, apiTokens.userId))
    .where(eq(apiTokens.orgId, c.org.id)).orderBy(desc(apiTokens.createdAt)));
}

export async function revokeApiToken(c: Ctx, tokenId: string) {
  if (!isUuid(tokenId)) throw notFound();
  await authorize(c.principal, "token.manage", { type: "api_token", id: tokenId }, c.org);
  await withOrg(c.org.id, async (tx) => {
    const r = await tx.update(apiTokens).set({ revokedAt: new Date() })
      .where(and(eq(apiTokens.id, tokenId), eq(apiTokens.orgId, c.org.id), isNull(apiTokens.revokedAt)))
      .returning({ id: apiTokens.id });
    if (!r[0]) throw notFound();
    await audit(tx, { actor: userActor(c.principal), action: "token.revoked", target: { type: "api_token", id: tokenId }, requestId: c.principal.requestId });
  });
}

/**
 * Resolves `Authorization: Bearer rs_...` to a principal. The token's user must still be an active member;
 * role and client-group scope are re-read, then narrowed to the token's scopes. Step-up actions are never
 * available to a token (authTime is the epoch), so it cannot approve, delete or administer anything.
 */
export async function resolveApiToken(
  token: string, meta: { ip?: string | null; requestId?: string | null } = {}, now = new Date(),
): Promise<LoadedPrincipal | null> {
  if (!/^rs_[A-Za-z0-9_-]{20,100}$/.test(token)) return null;
  const res = await db.execute<{ id: string; org_id: string; user_id: string; scopes: string[]; expires_at: Date; revoked_at: Date | null }>(
    sql`SELECT id, org_id, user_id, scopes, expires_at, revoked_at FROM api_token_lookup(${sha256(token)})`,
  );
  const t = res.rows[0];
  if (!t || t.revoked_at || new Date(t.expires_at) <= now) return null;
  const u = (await db.select().from(users).where(eq(users.id, t.user_id)).limit(1))[0];
  if (!u || u.disabledAt) return null;
  const session: SessionInfo = {
    idHash: "", userId: u.id, email: u.email, displayName: u.displayName, activeOrgId: t.org_id,
    mfa: true, amr: ["api_token"], authTime: new Date(0),
  };
  const loaded = await loadPrincipal(session, t.org_id, meta);
  if (!loaded) return null;
  await withOrg(t.org_id, (tx) => tx.update(apiTokens).set({ lastUsedAt: now }).where(eq(apiTokens.id, t.id)));
  return { ...loaded, principal: { ...loaded.principal, tokenScopes: t.scopes as TokenScope[] } };
}
