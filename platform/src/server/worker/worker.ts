import { and, eq, sql } from "drizzle-orm";
import type { Transporter } from "nodemailer";
import { mailTransport } from "../mail/mail";
import { db, withOrg } from "../db/client";
import { findings, invites, memberships, outbox, processedMessages, users } from "../db/schema";
import { allowPrivateFromEnv } from "../net/egress";
import { leaseDueReverifications, reverifyAsset } from "../assets/assets";
import { runAssessment, type RunDeps } from "../assessments/assessments";
import { deliverRunFinished } from "../assessments/notify";
import { runVerification } from "../verification/verification";
import { publishReferralResult } from "../webmonitor/referrals";
import { runSandbox, type SandboxDeps } from "../remediation/plans";
import { runOpenChange } from "../remediation/approvals";
import { backoffMs, enqueue, OUTBOX_MAX_ATTEMPTS, type Topic } from "../outbox/outbox";
import { log } from "../log";
import { addInApp, channelsFor, type NotifyKindAll } from "../notifications/notifications";

export interface OutboxMessage { id: string; org_id: string; topic: Topic; business_key: string; payload: Record<string, unknown>; attempts: number }

export interface WorkerDeps { mailer?: Pick<Transporter, "sendMail">; reverify?: typeof reverifyAsset; assessment?: RunDeps; verification?: RunDeps; remediation?: SandboxDeps }

// The shared SMTP transport (Resend in production, Mailpit locally).
const mailer = mailTransport;

type Handler = (m: OutboxMessage, deps: WorkerDeps) => Promise<{ result: string; scrub?: boolean }>;

const handlers: Record<Topic, Handler> = {
  "email.invite": async (m, deps) => {
    const p = m.payload as { inviteId: string; to: string; orgName: string; role: string; link?: string };
    if (!p.link) return { result: "no_link" };
    // Do not mail an invite that was revoked or accepted after it was queued.
    const inv = await withOrg(m.org_id, (tx) => tx.select({ revokedAt: invites.revokedAt, acceptedAt: invites.acceptedAt, expiresAt: invites.expiresAt }).from(invites).where(eq(invites.id, p.inviteId)));
    if (!inv[0] || inv[0].revokedAt || inv[0].acceptedAt || inv[0].expiresAt <= new Date()) return { result: "skipped_invalid", scrub: true };
    await (deps.mailer ?? mailer()).sendMail({
      from: process.env.MAIL_FROM ?? "RuyaShield <no-reply@ruyashield.local>",
      to: p.to,
      subject: `You're invited to ${p.orgName} on RuyaShield`,
      text: `You have been invited to join ${p.orgName} on RuyaShield as ${p.role.replace("_", " ")}.\n\nAccept the invitation (valid for 7 days, for ${p.to} only):\n${p.link}\n\nIf you did not expect this, ignore this email.`,
    });
    return { result: "sent", scrub: true };
  },
  "asset.reverify": async (m, deps) => {
    const p = m.payload as { assetId: string };
    const out = await (deps.reverify ?? reverifyAsset)(m.org_id, p.assetId, { egress: { allowPrivate: allowPrivateFromEnv() } });
    return { result: out ? out.status : "skipped" };
  },
  "assessment.run": async (m, deps) => {
    // The job token is single-use in practice (claim needs status=queued); scrub it once handled.
    const result = await runAssessment(m.org_id, m.payload, deps.assessment ?? { egress: { allowPrivate: allowPrivateFromEnv() }, dns: {} });
    // Delivered a little early (clock skew): retry later rather than drop the job.
    if (result === "window_not_open") throw new Error("assessment window not open yet");
    return { result, scrub: true };
  },
  "assessment.notify": async (m, deps) => ({ result: await deliverRunFinished(m.org_id, m.payload, m.id, deps.mailer ?? mailer()) }),
  "verification.run": async (m, deps) => {
    const result = await runVerification(m.org_id, m.payload, deps.verification ?? { egress: { allowPrivate: allowPrivateFromEnv() }, dns: {} });
    return { result, scrub: true };
  },
  "remediation.sandbox": async (m, deps) => ({ result: await runSandbox(m.org_id, m.payload, deps.remediation ?? {}) }),
  "remediation.open_pr": async (m) => ({ result: await runOpenChange(m.org_id, m.payload) }),
  "webmonitor.publish": async (m) => ({ result: await publishReferralResult(m.org_id, m.payload) }),
  "finding.notify": async (m, deps) => {
    const p = m.payload as { findingId: string; userId: string; kind: string };
    // Recipient must still be a member of this org; the address is resolved here, never stored in the payload.
    const row = (await withOrg(m.org_id, (tx) => tx.select({ email: users.email, title: findings.title, status: findings.status })
      .from(memberships).innerJoin(users, eq(users.id, memberships.userId)).innerJoin(findings, eq(findings.id, p.findingId))
      .where(and(eq(memberships.orgId, m.org_id), eq(memberships.userId, p.userId)))))[0];
    if (!row) return { result: "skipped_not_member" };
    const why: Record<string, string> = {
      assigned: "You were assigned a finding",
      mentioned: "You were mentioned on a finding",
      risk_expired: "A risk acceptance expired; the finding is back in triage",
      retriage: "A finding you own needs another look",
      verification_failed: "A verification re-test found the issue is still present",
      approval_requested: "A remediation plan is waiting for your approval",
      approval_decided: "A decision was made on your remediation approval request",
      regression: "A scheduled regression re-test found a verified fix has regressed",
      regression_not_run: "A scheduled regression re-test could not run",
      regression_inconclusive: "A scheduled regression re-test was inconclusive",
    };
    const subject = `${why[p.kind] ?? "Finding update"}: ${row.title}`;
    // In-app first (idempotent per message), then email, each per the recipient's preferences (FR-056).
    const ch = await withOrg(m.org_id, async (tx) => {
      await addInApp(tx, { orgId: m.org_id, userId: p.userId, kind: p.kind as NotifyKindAll, title: subject, link: `/findings/${p.findingId}`, sourceId: m.id });
      return channelsFor(tx, m.org_id, p.userId, p.kind);
    });
    if (!ch.email) return { result: "in_app_only" };
    const link = new URL(`/findings/${p.findingId}`, process.env.APP_URL ?? "http://localhost:3200").toString();
    await (deps.mailer ?? mailer()).sendMail({
      from: process.env.MAIL_FROM ?? "RuyaShield <no-reply@ruyashield.local>",
      to: row.email,
      subject,
      text: `${why[p.kind] ?? "Finding update"}.\n\n${row.title}\nStatus: ${row.status.replaceAll("_", " ")}\n\nOpen it in RuyaShield:\n${link}\n`,
    });
    return { result: "sent" };
  },
};

/** Processes one claimed message: idempotent per (topic, message id), retried with backoff, dead after max attempts. */
export async function processMessage(m: OutboxMessage, deps: WorkerDeps = {}): Promise<"done" | "retry" | "dead" | "duplicate"> {
  const seen = await withOrg(m.org_id, (tx) => tx.select().from(processedMessages)
    .where(and(eq(processedMessages.consumer, m.topic), eq(processedMessages.messageId, m.id))));
  if (seen.length) {
    await withOrg(m.org_id, (tx) => tx.update(outbox).set({ status: "done", processedAt: new Date(), lockedUntil: null }).where(eq(outbox.id, m.id)));
    return "duplicate";
  }
  try {
    const handler = handlers[m.topic];
    if (!handler) throw new Error(`unknown topic ${m.topic}`);
    const r = await handler(m, deps);
    await withOrg(m.org_id, async (tx) => {
      await tx.insert(processedMessages).values({ consumer: m.topic, messageId: m.id, orgId: m.org_id }).onConflictDoNothing();
      // The raw invite token lives in the payload only until delivery.
      const payload = r.scrub ? { ...m.payload, link: undefined, token: undefined, delivered: r.result } : m.payload;
      await tx.update(outbox).set({ status: "done", processedAt: new Date(), lockedUntil: null, lastError: null, payload }).where(eq(outbox.id, m.id));
    });
    log.info("outbox.done", { id: m.id, topic: m.topic, result: r.result });
    return "done";
  } catch (e) {
    const msg = (e instanceof Error ? e.message : String(e)).slice(0, 500);
    const dead = m.attempts >= OUTBOX_MAX_ATTEMPTS;
    await withOrg(m.org_id, (tx) => tx.update(outbox).set({
      status: dead ? "dead" : "pending", lastError: msg, lockedUntil: null,
      availableAt: new Date(Date.now() + backoffMs(m.attempts)),
    }).where(eq(outbox.id, m.id)));
    log.warn(dead ? "outbox.dead" : "outbox.retry", { id: m.id, topic: m.topic, attempts: m.attempts, error: msg });
    return dead ? "dead" : "retry";
  }
}

export async function claimBatch(limit = 10, leaseSeconds = 60): Promise<OutboxMessage[]> {
  const r = await db.execute(sql`SELECT id, org_id, topic, business_key, payload, attempts FROM claim_outbox(${limit}, ${leaseSeconds})`);
  return r.rows as unknown as OutboxMessage[];
}

export async function runOnce(deps: WorkerDeps = {}) {
  const batch = await claimBatch();
  for (const m of batch) await processMessage(m, deps);
  return batch.length;
}

/** Enqueues re-verification for assets that are due (RS-ASSET-003). */
export async function scheduleReverifications() {
  const due = await leaseDueReverifications();
  const day = new Date().toISOString().slice(0, 13);
  for (const d of due) {
    await withOrg(d.orgId, (tx) => enqueue(tx, { orgId: d.orgId, topic: "asset.reverify", businessKey: `reverify:${d.assetId}:${day}`, payload: { assetId: d.assetId } }));
  }
  return due.length;
}
