import { createHash } from "node:crypto";
import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import { db, withOrg } from "../db/client";
import { memberships, orgs, users } from "../db/schema";
import { audit } from "../audit/audit";
import { AppError } from "../errors";
import { log } from "../log";
import { notifyAdmins } from "../notifications/notifications";
import { appLink, brandedEmail, sendMail } from "../mail/mail";
import { grantFor } from "../policy/matrix";
import type { OrgFlags, Principal } from "../policy/policy";

// Plans that change on their own (operators still switch plans by hand in /operator, which marks them 'manual'):
// - trial:   the first organization a person creates gets 14 days of Pro, no card. Admins are reminded 3 days and
//            1 day before the end (in-app and email); then the organization goes back to Free. One trial per person.
// - ruyalab: Ruya Lab Pro on the creator's linked Ruya Lab account (accounts.ruyalab.com) makes the organization Pro.

export const TRIAL_DAYS = 14;
const DAY = 86_400_000;
const REMINDERS = [3, 1] as const;
const SERVICE = { type: "service" as const, id: "plans" };

type Tx = Parameters<Parameters<typeof withOrg>[1]>[0];
type OrgRow = { id: string; name: string; plan: string; plan_source: string | null; trial_ends_at: Date | null; trial_reminded: number; owner_ruyalab_sub: string | null };
type RuyaLabPlan = "pro" | "free";

/** Claims this person's one trial. Returns the end date, or null when they already had one. */
export async function claimTrial(tx: Tx, userId: string, now = new Date()): Promise<Date | null> {
  const r = await tx.update(users).set({ trialUsedAt: now }).where(and(eq(users.id, userId), isNull(users.trialUsedAt))).returning({ id: users.id });
  return r.length ? new Date(now.getTime() + TRIAL_DAYS * DAY) : null;
}

export const trialDaysLeft = (org: { planSource?: string | null; trialEndsAt?: Date | null }, now = new Date()) =>
  org.planSource === "trial" && org.trialEndsAt ? Math.max(0, Math.ceil((org.trialEndsAt.getTime() - now.getTime()) / DAY)) : null;

/** An org admin of a Free organization starts the trial, if they never had one. */
export async function startTrial(c: { principal: Principal; org: OrgFlags & { id: string } }, meta: { ip?: string | null; requestId?: string | null } = {}, now = new Date()) {
  if (grantFor(c.principal.role, "org.settings.edit") === "N" || c.principal.tokenScopes || c.principal.breakGlassId) throw new AppError(403, "forbidden");
  if (c.org.plan === "pro") throw new AppError(409, "already_pro", "This organization is already on Pro.");
  return withOrg(c.org.id, async (tx) => {
    const org = (await tx.select({ trialEndsAt: orgs.trialEndsAt }).from(orgs).where(eq(orgs.id, c.org.id)))[0];
    if (org?.trialEndsAt) throw new AppError(409, "trial_used", "This organization has already had its free trial.");
    const ends = await claimTrial(tx, c.principal.userId, now);
    if (!ends) throw new AppError(409, "trial_used", "You have already used your free trial on another organization.");
    await tx.update(orgs).set({ plan: "pro", planSource: "trial", trialEndsAt: ends, trialReminded: 0 }).where(eq(orgs.id, c.org.id));
    await audit(tx, { actor: { type: "user", id: c.principal.userId, ip: meta.ip }, action: "org.plan_changed", target: { type: "org", id: c.org.id }, requestId: meta.requestId, details: { from: "free", to: "pro", source: "trial", endsAt: ends.toISOString() } });
    await notifyAdmins(tx, c.org.id, { kind: "plan_changed", title: `Your ${TRIAL_DAYS}-day RuyaShield Pro trial has started. Everything is unlocked until ${longDate(ends)}.`, link: "/settings/plan", sourceId: c.org.id });
    return { endsAt: ends };
  });
}

/** A stable UUID for one plan event, so a repeated sweep cannot notify twice (notifications.source_id is a uuid). */
const eventId = (key: string) => {
  const h = createHash("sha256").update(`plans:${key}`).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
};

const longDate = (d: Date) => d.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });

// ---------- Ruya Lab Pro ----------

export const ruyaLabConfigured = () => Boolean(process.env.RUYALAB_ISSUER && process.env.RUYALAB_CLIENT_ID && process.env.RUYALAB_CLIENT_SECRET);

async function fetchEntitlements(subs: string[]): Promise<Record<string, RuyaLabPlan>> {
  if (!subs.length || !ruyaLabConfigured()) return {};
  const res = await fetch(`${process.env.RUYALAB_ISSUER}/api/entitlements`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Basic ${Buffer.from(`${process.env.RUYALAB_CLIENT_ID}:${process.env.RUYALAB_CLIENT_SECRET}`).toString("base64")}` },
    body: JSON.stringify({ subs }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Ruya Lab entitlements answered ${res.status}`);
  return ((await res.json()) as { plans?: Record<string, RuyaLabPlan> }).plans ?? {};
}

/** What should happen to one organization now. Pure, for tests. */
export function decide(o: OrgRow, ruyalab: RuyaLabPlan | undefined, now = new Date()):
  | { change: "to_ruyalab" | "ruyalab_ended" | "trial_ended" }
  | { remind: number }
  | null {
  if (ruyalab === "pro" && o.plan_source !== "manual" && o.plan_source !== "ruyalab") return { change: "to_ruyalab" };
  if (o.plan_source === "ruyalab" && ruyalab === "free") return { change: "ruyalab_ended" };
  if (o.plan_source === "trial" && o.plan === "pro" && o.trial_ends_at) {
    const left = o.trial_ends_at.getTime() - now.getTime();
    if (left <= 0) return { change: "trial_ended" };
    const due = [...REMINDERS].reverse().find((d) => left <= d * DAY);
    if (due && (o.trial_reminded === 0 || o.trial_reminded > due)) return { remind: due };
  }
  return null;
}

const MESSAGES = {
  to_ruyalab: { to: "pro", title: "Ruya Lab Pro is active: your organization is on RuyaShield Pro, with everything unlocked." },
  ruyalab_ended: { to: "free", title: "Ruya Lab Pro has ended, so your organization is back on RuyaShield Free. Findings and assessments are unchanged." },
  trial_ended: { to: "free", title: "Your RuyaShield Pro trial has ended. Your organization is back on Free; request Pro on the plan page to unlock everything again." },
} as const;

/** Every few minutes (worker): Ruya Lab Pro, finished trials and trial reminders. */
export async function sweepOrgPlans(now = new Date()) {
  // Raw rows carry timestamps as strings; turn them into dates once.
  const rows: OrgRow[] = (await db.execute<OrgRow>(sql`SELECT * FROM plan_sweep_orgs()`)).rows
    .map((r) => ({ ...r, trial_reminded: Number(r.trial_reminded), trial_ends_at: r.trial_ends_at ? new Date(r.trial_ends_at) : null }));
  const subs = [...new Set(rows.map((r) => r.owner_ruyalab_sub).filter((s): s is string => Boolean(s)))];
  let plans: Record<string, RuyaLabPlan> = {};
  try {
    plans = await fetchEntitlements(subs);
  } catch (e) {
    // Without an answer nothing changes on Ruya Lab's account; trials still end on time.
    log.error("plans.entitlements_failed", { error: e instanceof Error ? e.message : String(e) });
  }
  const out = { changed: 0, reminded: 0 };
  for (const o of rows) {
    const d = decide(o, o.owner_ruyalab_sub ? plans[o.owner_ruyalab_sub] : undefined, now);
    if (!d) continue;
    try {
      if ("change" in d) {
        const m = MESSAGES[d.change];
        await withOrg(o.id, async (tx) => {
          await tx.update(orgs).set(d.change === "to_ruyalab"
            ? { plan: "pro", planSource: "ruyalab", proRequestedAt: null, proRequestedBy: null }
            : { plan: "free", planSource: null }).where(eq(orgs.id, o.id));
          await audit(tx, { actor: SERVICE, action: "org.plan_changed", target: { type: "org", id: o.id }, details: { from: o.plan, to: m.to, reason: d.change } });
          await notifyAdmins(tx, o.id, { kind: "plan_changed", title: m.title, link: "/settings/plan", sourceId: eventId(`${o.id}:${d.change}:${now.toISOString().slice(0, 13)}`) });
        });
        out.changed += 1;
      } else {
        const emails = await withOrg(o.id, async (tx) => {
          await tx.update(orgs).set({ trialReminded: d.remind }).where(eq(orgs.id, o.id));
          const left = d.remind === 1 ? "less than a day" : `${d.remind} days`;
          await notifyAdmins(tx, o.id, { kind: "plan_changed", title: `Your RuyaShield Pro trial ends in ${left}. Request Pro on the plan page to keep everything unlocked.`, link: "/settings/plan", sourceId: eventId(`${o.id}:trial:${d.remind}:${o.trial_ends_at?.toISOString()}`) });
          return (await tx.select({ email: users.email }).from(memberships).innerJoin(users, eq(users.id, memberships.userId))
            .where(and(eq(memberships.orgId, o.id), inArray(memberships.role, ["org_admin"])))).map((r) => r.email);
        });
        await trialEmail(o, d.remind, emails).catch((e) => log.error("plans.trial_email_failed", { error: e instanceof Error ? e.message : String(e) }));
        out.reminded += 1;
      }
    } catch (e) {
      log.error("plans.sweep_org_failed", { orgId: o.id, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}

async function trialEmail(o: OrgRow, days: number, to: string[]) {
  if (!to.length || !o.trial_ends_at) return;
  const when = days === 1 ? "tomorrow" : `in ${days} days`;
  const end = longDate(o.trial_ends_at);
  const paragraphs = [
    `The RuyaShield Pro trial for ${o.name} ends ${when}, on ${end}.`,
    "After that the organization goes back to Free: assessments and your top findings stay, while evidence, Zealot, fixes, re-tests, attacks and reports need Pro.",
    "To keep Pro, an org admin can request it on the plan page. Our team activates it.",
  ];
  await sendMail({
    to: to.join(","), subject: `Your RuyaShield Pro trial ends ${when}`,
    text: [...paragraphs, "", appLink("/settings/plan")].join("\n"),
    html: brandedEmail({ preheader: `Pro trial ends ${when}.`, title: "Your Pro trial is ending", paragraphs, button: { label: "Open the plan page", href: appLink("/settings/plan") } }),
  });
}
