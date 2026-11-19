import { randomUUID } from "node:crypto";
import { and, count, desc, eq, gt, isNull, sql } from "drizzle-orm";
import { z } from "zod";
import { db, withOrg, isUuid, type Tx } from "../db/client";
import { clientGroups, invites, memberClientGroups, memberships, orgs, users } from "../db/schema";
import { audit } from "../audit/audit";
import { claimTrial } from "../plans/lifecycle";
import { AppError, notFound, isUniqueViolation } from "../errors";
import { authorize, type OrgFlags, type Principal } from "../policy/policy";
import { enqueue } from "../outbox/outbox";
import { notifyAdmins } from "../notifications/notifications";
import { randomToken, revokeUserSessions, sha256, type SessionInfo } from "../auth/session";

export const ORG_CREATE_LIMIT = 3;
export const INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;
export const ASSIGNABLE_ROLES = ["org_admin", "security_lead", "analyst", "developer", "approver", "viewer"] as const;
export type AssignableRole = (typeof ASSIGNABLE_ROLES)[number];

type Ctx = { principal: Principal; org: OrgFlags & { id: string; name: string } };
const userActor = (p: Principal) => ({ type: "user" as const, id: p.userId, ip: p.ip });

export function slugify(name: string): string {
  return name.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "org";
}

async function slugTaken(slug: string) {
  const r = await db.execute<{ t: boolean }>(sql`SELECT org_slug_taken(${slug}) AS t`);
  return r.rows[0].t;
}

const createOrgInput = z.object({
  name: z.string().trim().min(2, "Name must be at least 2 characters").max(80),
  slug: z.string().trim().toLowerCase().regex(/^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$/, "Use 3–40 lowercase letters, digits or hyphens").optional(),
});

/** RS-IAM-001/002: creator becomes org_admin; at most 3 orgs created per user on the pilot plan. */
export async function createOrg(s: SessionInfo, input: unknown, meta: { ip?: string | null; requestId?: string | null } = {}) {
  const parsed = createOrgInput.safeParse(input);
  if (!parsed.success) throw new AppError(422, "validation_failed", parsed.error.issues[0].message);
  const { name } = parsed.data;
  const slug = parsed.data.slug ?? slugify(name);

  const n = await db.execute<{ n: number }>(sql`SELECT user_created_org_count(${s.userId}) AS n`);
  if (Number(n.rows[0].n) >= ORG_CREATE_LIMIT) throw new AppError(409, "org_limit_reached", `You can create at most ${ORG_CREATE_LIMIT} organizations on the pilot plan.`);
  if (await slugTaken(slug)) {
    let suggestion = slug;
    for (let i = 2; i < 50 && (await slugTaken(suggestion)); i++) suggestion = `${slug.slice(0, 36)}-${i}`;
    throw new AppError(409, "slug_taken", "That URL name is taken.", { suggestion });
  }

  const id = randomUUID();
  await withOrg(id, async (tx) => {
    // RUYA_DEFAULT_ORG_PLAN=pro is for test databases and self-hosted installs. Otherwise the first organization a
    // person creates gets the 7-day Pro trial (RUYA_ORG_TRIAL=off turns that off), and later ones start on Free.
    const fixedPro = process.env.RUYA_DEFAULT_ORG_PLAN === "pro";
    const trialEnds = !fixedPro && process.env.RUYA_ORG_TRIAL !== "off" ? await claimTrial(tx, s.userId) : null;
    await tx.insert(orgs).values({
      id, name, slug, region: process.env.DATA_REGION ?? "default", createdBy: s.userId,
      ...(fixedPro ? { plan: "pro", planSource: "manual" as const } : trialEnds ? { plan: "pro", planSource: "trial" as const, trialEndsAt: trialEnds } : { plan: "free" }),
    });
    await tx.insert(memberships).values({ orgId: id, userId: s.userId, role: "org_admin" });
    await audit(tx, { actor: { type: "user", id: s.userId, ip: meta.ip }, action: "org.created", target: { type: "org", id }, requestId: meta.requestId, details: { name, slug } });
  }).catch((e: unknown) => {
    if (isUniqueViolation(e)) throw new AppError(409, "slug_taken", "That URL name is taken.", { suggestion: `${slug}-2` });
    throw e;
  });
  return { id, slug };
}

export async function listUserOrgs(userId: string) {
  const r = await db.execute<{ org_id: string; name: string; slug: string; role: string }>(sql`SELECT * FROM user_orgs(${userId})`);
  return r.rows.map((o) => ({ id: o.org_id, name: o.name, slug: o.slug, role: o.role }));
}

// ---------- members ----------

export async function listMembers(c: Ctx) {
  await authorize(c.principal, "members.manage", { type: "org", id: c.org.id }, c.org);
  return withOrg(c.org.id, async (tx) => {
    const rows = await tx.select({ userId: memberships.userId, role: memberships.role, restricted: memberships.restricted, joinedAt: memberships.createdAt, email: users.email, name: users.displayName })
      .from(memberships).innerJoin(users, eq(users.id, memberships.userId)).orderBy(users.email);
    const groups = await tx.select().from(memberClientGroups);
    return rows.map((r) => ({ ...r, clientGroupIds: groups.filter((g) => g.userId === r.userId).map((g) => g.clientGroupId) }));
  });
}

async function adminCount(tx: Tx) {
  const r = await tx.select({ n: count() }).from(memberships).where(eq(memberships.role, "org_admin"));
  return r[0].n;
}

export async function changeRole(c: Ctx, userId: string, role: string) {
  if (!isUuid(userId)) throw notFound();
  if (!(ASSIGNABLE_ROLES as readonly string[]).includes(role)) throw new AppError(422, "invalid_role");
  await authorize(c.principal, "members.manage", { type: "membership", id: userId }, c.org);
  await withOrg(c.org.id, async (tx) => {
    const m = (await tx.select().from(memberships).where(eq(memberships.userId, userId)).for("update"))[0];
    if (!m) throw notFound();
    if (m.role === role) return;
    if (m.role === "org_admin" && role !== "org_admin" && (await adminCount(tx)) <= 1) {
      throw new AppError(409, "last_admin", "An organization must keep at least one org admin.");
    }
    await tx.update(memberships).set({ role: role as AssignableRole }).where(eq(memberships.userId, userId));
    await audit(tx, { actor: userActor(c.principal), action: "member.role_changed", target: { type: "user", id: userId }, requestId: c.principal.requestId, details: { from: m.role, to: role } });
  });
  // Privilege changes take effect immediately: principals are reloaded per request.
}

export async function setRestricted(c: Ctx, userId: string, restricted: boolean, clientGroupIds: string[]) {
  if (!isUuid(userId) || !clientGroupIds.every(isUuid)) throw new AppError(422, "validation_failed");
  await authorize(c.principal, "members.manage", { type: "membership", id: userId }, c.org);
  await withOrg(c.org.id, async (tx) => {
    const m = (await tx.select().from(memberships).where(eq(memberships.userId, userId)))[0];
    if (!m) throw notFound();
    const valid = clientGroupIds.length ? await tx.select({ id: clientGroups.id }).from(clientGroups) : [];
    const ids = clientGroupIds.filter((g) => valid.some((v) => v.id === g));
    await tx.update(memberships).set({ restricted }).where(eq(memberships.userId, userId));
    await tx.delete(memberClientGroups).where(eq(memberClientGroups.userId, userId));
    if (ids.length) await tx.insert(memberClientGroups).values(ids.map((g) => ({ orgId: c.org.id, userId, clientGroupId: g })));
    await audit(tx, { actor: userActor(c.principal), action: "member.scope_changed", target: { type: "user", id: userId }, requestId: c.principal.requestId, details: { restricted, clientGroupIds: ids } });
  });
}

/** RS-IAM-003: removal revokes the member's sessions; the last org admin cannot be removed. */
export async function removeMember(c: Ctx, userId: string) {
  if (!isUuid(userId)) throw notFound();
  await authorize(c.principal, "members.manage", { type: "membership", id: userId }, c.org);
  await withOrg(c.org.id, async (tx) => {
    const m = (await tx.select().from(memberships).where(eq(memberships.userId, userId)).for("update"))[0];
    if (!m) throw notFound();
    if (m.role === "org_admin" && (await adminCount(tx)) <= 1) throw new AppError(409, "last_admin", "An organization must keep at least one org admin.");
    await tx.delete(memberClientGroups).where(eq(memberClientGroups.userId, userId));
    await tx.delete(memberships).where(eq(memberships.userId, userId));
    await audit(tx, { actor: userActor(c.principal), action: "member.removed", target: { type: "user", id: userId }, requestId: c.principal.requestId, details: { role: m.role } });
  });
  const revoked = await revokeUserSessions(userId);
  return { revokedSessions: revoked };
}

// ---------- invites ----------

const inviteInput = z.object({
  email: z.string().trim().toLowerCase().email("Enter a valid email").max(200),
  role: z.enum(ASSIGNABLE_ROLES),
  clientGroupIds: z.array(z.string().uuid()).max(50).default([]),
});

export async function createInvite(c: Ctx, input: unknown) {
  const parsed = inviteInput.safeParse(input);
  if (!parsed.success) throw new AppError(422, "validation_failed", parsed.error.issues[0].message);
  const { email, role, clientGroupIds } = parsed.data;
  await authorize(c.principal, "members.manage", { type: "org", id: c.org.id }, c.org);
  const token = randomToken(32);
  const appUrl = process.env.APP_URL ?? "http://localhost:3200";
  return withOrg(c.org.id, async (tx) => {
    const existing = await tx.select({ id: memberships.userId }).from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(eq(users.email, email));
    if (existing.length) throw new AppError(409, "already_member", "That person is already a member.");
    const inv = (await tx.insert(invites).values({
      orgId: c.org.id, email, role, clientGroupIds, tokenHash: sha256(token), invitedBy: c.principal.userId,
      expiresAt: new Date(Date.now() + INVITE_TTL_MS),
    }).returning({ id: invites.id }))[0];
    // The raw token lives in the outbox only until the email is sent; the worker strips it afterwards.
    await enqueue(tx, { orgId: c.org.id, topic: "email.invite", businessKey: `invite:${inv.id}`, payload: { inviteId: inv.id, to: email, orgName: c.org.name, role, link: `${appUrl}/invite/${token}` } });
    await audit(tx, { actor: userActor(c.principal), action: "member.invited", target: { type: "invite", id: inv.id }, requestId: c.principal.requestId, details: { email, role } });
    return { id: inv.id };
  });
}

export async function listInvites(c: Ctx) {
  await authorize(c.principal, "members.manage", { type: "org", id: c.org.id }, c.org);
  return withOrg(c.org.id, (tx) => tx.select({ id: invites.id, email: invites.email, role: invites.role, expiresAt: invites.expiresAt, createdAt: invites.createdAt })
    .from(invites).where(and(isNull(invites.acceptedAt), isNull(invites.revokedAt), gt(invites.expiresAt, new Date()))).orderBy(desc(invites.createdAt)));
}

export async function revokeInvite(c: Ctx, inviteId: string) {
  if (!isUuid(inviteId)) throw notFound();
  await authorize(c.principal, "members.manage", { type: "invite", id: inviteId }, c.org);
  await withOrg(c.org.id, async (tx) => {
    const r = await tx.update(invites).set({ revokedAt: new Date() }).where(and(eq(invites.id, inviteId), isNull(invites.acceptedAt), isNull(invites.revokedAt))).returning({ id: invites.id });
    if (!r.length) throw notFound();
    await audit(tx, { actor: userActor(c.principal), action: "member.invite_revoked", target: { type: "invite", id: inviteId }, requestId: c.principal.requestId });
  });
}

/** Looks up an invite for display on the accept page. Returns only what the invitee needs. */
export async function peekInvite(token: string) {
  const hash = sha256(token);
  const r = await db.execute<{ o: string | null }>(sql`SELECT invite_org(${hash}) AS o`);
  const orgId = r.rows[0]?.o;
  if (!orgId) return null;
  return withOrg(orgId, async (tx) => {
    const inv = (await tx.select().from(invites).where(eq(invites.tokenHash, hash)))[0];
    const o = (await tx.select({ name: orgs.name }).from(orgs).where(eq(orgs.id, orgId)))[0];
    if (!inv || !o) return null;
    const state = inv.acceptedAt ? "used" : inv.revokedAt ? "revoked" : inv.expiresAt <= new Date() ? "expired" : "valid";
    return { orgId, orgName: o.name, email: inv.email, role: inv.role, state };
  });
}

/** RS-IAM-002: single use, 7-day expiry, must be accepted by the invited email. */
export async function acceptInvite(s: SessionInfo, token: string, meta: { ip?: string | null; requestId?: string | null } = {}) {
  const hash = sha256(token);
  const r = await db.execute<{ o: string | null }>(sql`SELECT invite_org(${hash}) AS o`);
  const orgId = r.rows[0]?.o;
  if (!orgId) throw new AppError(404, "invite_invalid", "This invitation link is not valid.");
  const actor = { type: "user" as const, id: s.userId, ip: meta.ip };

  let mismatch: string | null = null;
  const result = await withOrg(orgId, async (tx) => {
    const inv = (await tx.select().from(invites).where(eq(invites.tokenHash, hash)).for("update"))[0];
    if (!inv || inv.revokedAt) throw new AppError(404, "invite_invalid", "This invitation link is not valid.");
    if (inv.acceptedAt) throw new AppError(409, "invite_used", "This invitation has already been used.");
    if (inv.expiresAt <= new Date()) throw new AppError(409, "invite_expired", "This invitation has expired. Ask an admin to send a new one.");
    if (inv.email !== s.email.toLowerCase()) { mismatch = inv.id; return null; }
    const already = await tx.select({ u: memberships.userId }).from(memberships).where(eq(memberships.userId, s.userId));
    if (already.length) throw new AppError(409, "already_member", "You are already a member of this organization.");
    await tx.insert(memberships).values({ orgId, userId: s.userId, role: inv.role, restricted: inv.clientGroupIds.length > 0 });
    if (inv.clientGroupIds.length) {
      const valid = await tx.select({ id: clientGroups.id }).from(clientGroups);
      const ids = inv.clientGroupIds.filter((g) => valid.some((v) => v.id === g));
      if (ids.length) await tx.insert(memberClientGroups).values(ids.map((g) => ({ orgId, userId: s.userId, clientGroupId: g })));
    }
    await tx.update(invites).set({ acceptedAt: new Date() }).where(eq(invites.id, inv.id));
    await audit(tx, { actor, action: "member.joined", target: { type: "invite", id: inv.id }, requestId: meta.requestId, details: { role: inv.role } });
    return { orgId };
  });
  if (mismatch) {
    await withOrg(orgId, (tx) => audit(tx, { actor, action: "member.invite_rejected", target: { type: "invite", id: mismatch! }, outcome: "denied", reason: "email_mismatch", requestId: meta.requestId }));
    throw new AppError(403, "invite_email_mismatch", "This invitation was sent to a different email address. Sign in with that address.");
  }
  return result!;
}

// ---------- client groups ----------

export async function listClientGroups(c: Ctx) {
  return withOrg(c.org.id, async (tx) => {
    const all = await tx.select().from(clientGroups).orderBy(clientGroups.name);
    const p = c.principal;
    return p.restricted ? all.filter((g) => p.clientGroupIds.includes(g.id)) : all;
  });
}

export async function createClientGroup(c: Ctx, name: unknown) {
  const n = z.string().trim().min(1).max(80).safeParse(name);
  if (!n.success) throw new AppError(422, "validation_failed", "Enter a name (1–80 characters).");
  await authorize(c.principal, "members.manage", { type: "org", id: c.org.id }, c.org);
  return withOrg(c.org.id, async (tx) => {
    const g = (await tx.insert(clientGroups).values({ orgId: c.org.id, name: n.data }).returning())[0];
    await audit(tx, { actor: userActor(c.principal), action: "client_group.created", target: { type: "client_group", id: g.id }, requestId: c.principal.requestId, details: { name: n.data } });
    return g;
  });
}

// ---------- kill switch (RS-PLAT-006) ----------

export async function setKillSwitch(c: Ctx, which: "scanning" | "ai", engaged: boolean, reason: string) {
  await authorize(c.principal, "killswitch.manage", { type: "org", id: c.org.id }, c.org);
  const r = z.string().trim().min(3, "Give a reason (at least 3 characters).").max(500).safeParse(reason);
  if (!r.success) throw new AppError(422, "validation_failed", r.error.issues[0].message);
  await withOrg(c.org.id, async (tx) => {
    await tx.update(orgs).set(which === "scanning" ? { killScanning: engaged } : { killAi: engaged }).where(eq(orgs.id, c.org.id));
    await audit(tx, { actor: userActor(c.principal), action: engaged ? "killswitch.engaged" : "killswitch.released", target: { type: "org", id: c.org.id }, reason: r.data, requestId: c.principal.requestId, details: { which } });
    await notifyAdmins(tx, c.org.id, { kind: "killswitch", title: `${which === "scanning" ? "Scanning" : "AI"} kill switch ${engaged ? "engaged" : "released"}: ${r.data}`, link: "/settings/safety", sourceId: randomUUID() });
  });
}

// ---------- intrusive network checks (scanner M3, class A2) ----------

export interface IntrusiveNetworkState { enabled: boolean; requestedBy: string | null; requestedAt: Date | null; pending: boolean }

export async function getIntrusiveNetwork(c: Ctx): Promise<IntrusiveNetworkState> {
  return withOrg(c.org.id, async (tx) => {
    const o = (await tx.select({ e: orgs.allowIntrusiveNetwork, by: orgs.intrusiveNetworkRequestedBy, at: orgs.intrusiveNetworkRequestedAt }).from(orgs).where(eq(orgs.id, c.org.id)))[0];
    const pending = !o?.e && !!o?.by && !!o?.at && Date.now() - o.at.getTime() < INTRUSIVE_REQUEST_TTL_MS;
    return { enabled: !!o?.e, requestedBy: o?.by ?? null, requestedAt: o?.at ?? null, pending };
  });
}

/** Pending requests older than this must be made again. */
export const INTRUSIVE_REQUEST_TTL_MS = 7 * 86_400_000;

/**
 * Turning A2 on is two-person (scope.enable_a2 = "A"): the first admin requests, a different admin confirms.
 * Turning it off, or withdrawing a request, takes one person: stopping is always the cheap direction.
 * Returns the resulting state: "requested", "enabled" or "disabled".
 */
export async function setIntrusiveNetwork(c: Ctx, enable: boolean, reason: string): Promise<"requested" | "enabled" | "disabled"> {
  const { needsSecondPerson } = await authorize(c.principal, "scope.enable_a2", { type: "org", id: c.org.id }, c.org);
  const r = z.string().trim().min(3, "Give a reason (at least 3 characters).").max(500).safeParse(reason);
  if (!r.success) throw new AppError(422, "validation_failed", r.error.issues[0].message);
  return withOrg(c.org.id, async (tx) => {
    const cur = (await tx.select({ e: orgs.allowIntrusiveNetwork, by: orgs.intrusiveNetworkRequestedBy, at: orgs.intrusiveNetworkRequestedAt }).from(orgs).where(eq(orgs.id, c.org.id)).for("update"))[0];
    const log = (action: string) => audit(tx, { actor: userActor(c.principal), action, target: { type: "org", id: c.org.id }, reason: r.data, requestId: c.principal.requestId, details: { setting: "intrusive_network" } });
    const notify = (title: string) => notifyAdmins(tx, c.org.id, { kind: "killswitch", title, link: "/settings/safety", sourceId: randomUUID() });
    if (!enable) {
      await tx.update(orgs).set({ allowIntrusiveNetwork: false, intrusiveNetworkRequestedBy: null, intrusiveNetworkRequestedAt: null }).where(eq(orgs.id, c.org.id));
      await log(cur?.e ? "org.intrusive_network_disabled" : "org.intrusive_network_request_withdrawn");
      if (cur?.e) await notify(`Intrusive network checks turned off: ${r.data}`);
      return "disabled";
    }
    if (cur?.e) throw new AppError(409, "conflict", "Intrusive network checks are already on.");
    const pending = cur?.by && cur.at && Date.now() - cur.at.getTime() < INTRUSIVE_REQUEST_TTL_MS ? cur.by : null;
    if (needsSecondPerson && pending !== null && pending === c.principal.userId) {
      throw new AppError(409, "second_person_required", "Another admin must confirm this. You cannot approve your own request.");
    }
    if (needsSecondPerson && pending === null) {
      await tx.update(orgs).set({ intrusiveNetworkRequestedBy: c.principal.userId, intrusiveNetworkRequestedAt: new Date() }).where(eq(orgs.id, c.org.id));
      await log("org.intrusive_network_requested");
      await notify(`Intrusive network checks requested — a second admin must confirm: ${r.data}`);
      return "requested";
    }
    await tx.update(orgs).set({ allowIntrusiveNetwork: true, intrusiveNetworkRequestedBy: null, intrusiveNetworkRequestedAt: null }).where(eq(orgs.id, c.org.id));
    await log("org.intrusive_network_enabled");
    await notify(`Intrusive network checks turned on: ${r.data}`);
    return "enabled";
  });
}

/** RS-FIXP-007: how often verified fixes are re-tested for regression; null turns scheduled re-tests off. */
export async function getRegressionInterval(c: Ctx): Promise<number | null> {
  return withOrg(c.org.id, async (tx) => (await tx.select({ d: orgs.regressionIntervalDays }).from(orgs).where(eq(orgs.id, c.org.id)))[0]?.d ?? null);
}

export async function setRegressionInterval(c: Ctx, days: number | null, reason: string) {
  await authorize(c.principal, "org.settings.edit", { type: "org", id: c.org.id }, c.org);
  const d = z.number().int().min(1, "Use 1 to 90 days.").max(90, "Use 1 to 90 days.").nullable().safeParse(days);
  if (!d.success) throw new AppError(422, "validation_failed", d.error.issues[0].message);
  const r = z.string().trim().min(3, "Give a reason (at least 3 characters).").max(500).safeParse(reason);
  if (!r.success) throw new AppError(422, "validation_failed", r.error.issues[0].message);
  await withOrg(c.org.id, async (tx) => {
    const before = (await tx.select({ d: orgs.regressionIntervalDays }).from(orgs).where(eq(orgs.id, c.org.id)))[0]?.d ?? null;
    await tx.update(orgs).set({ regressionIntervalDays: d.data }).where(eq(orgs.id, c.org.id));
    await audit(tx, { actor: userActor(c.principal), action: "org.regression_interval_set", target: { type: "org", id: c.org.id }, reason: r.data, requestId: c.principal.requestId, details: { before, after: d.data } });
  });
}
