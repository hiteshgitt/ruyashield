import { and, eq, inArray } from "drizzle-orm";
import type { Transporter } from "nodemailer";
import { withOrg, isUuid, type Tx } from "../db/client";
import { assessments, assets, findingOccurrences, findings, memberships, users, type AssessmentStatus, type Coverage, type Severity } from "../db/schema";
import { enqueue } from "../outbox/outbox";
import { OPEN_STATUSES } from "../findings/lifecycle";
import { addInApp, channelsFor, type NotifyKindAll } from "../notifications/notifications";

/**
 * Run-finished notifications (topic "assessment.notify"), queued in the same transaction that finalizes a run.
 *  - The launcher gets "assessment_complete": severity counts plus coverage. A partial or stopped run says so plainly
 *    and is never worded as clean; zero findings from a partial run reads "not a clean result".
 *  - Org admins and security leads get "new_critical_finding" (security-critical: always in-app and email)
 *    when the run created critical or high findings that did not exist before.
 * The payload holds the assessment id only; recipients and addresses are resolved at delivery.
 */
export async function queueRunFinished(tx: Tx, orgId: string, assessmentId: string) {
  await enqueue(tx, { orgId, topic: "assessment.notify", businessKey: `assessment:${assessmentId}:finished`, payload: { assessmentId } });
}

export interface RunSummaryInput {
  host: string; status: AssessmentStatus; reason: string | null; coverage: Coverage | null;
  open: Record<"critical" | "high" | "medium" | "low", number>;
}

/** Plain-language subject and body. Pure, so the honesty rules are unit-tested. */
export function runSummary(s: RunSummaryInput): { subject: string; body: string; clean: boolean } {
  const c = s.coverage;
  const ran = c ? `${c.ok} of ${c.planned} checks ran` : "no checks ran";
  const full = s.status === "completed" && !!c?.complete && c.ok === c.planned && c.planned > 0;
  const counts = `${s.open.critical} critical, ${s.open.high} high`;
  const verb = full ? "finished" : s.status === "cancelled" ? "was cancelled" : s.status === "timed_out" ? "timed out"
    : s.status === "failed" || s.status === "rejected" ? "failed" : "finished with errors";
  const subject = `Assessment of ${s.host} ${verb}: ${counts} · ${ran}`.slice(0, 300);
  const lines = [
    `Assessment of ${s.host} ${verb}.`,
    "",
    `Open findings from this run: ${s.open.critical} critical, ${s.open.high} high, ${s.open.medium} medium, ${s.open.low} low.`,
    `Coverage: ${ran}${c && c.error + c.timeout ? ` (${c.error + c.timeout} failed or timed out)` : ""}${c && c.skipped ? `, ${c.skipped} skipped` : ""}.`,
  ];
  if (!full) {
    lines.push("", `Partial result${s.reason ? ` (${s.reason.replaceAll("_", " ")})` : ""}: not every planned check ran, so this is NOT a clean result. Fix the cause and run the assessment again.`);
  } else if (s.open.critical + s.open.high + s.open.medium + s.open.low === 0) {
    lines.push("", "No open findings from the checks that ran. That is not a guarantee: these checks are non-intrusive and cannot see everything.");
  }
  return { subject, body: lines.join("\n"), clean: full };
}

const LINK = (path: string) => new URL(path, process.env.APP_URL ?? "http://localhost:3200").toString();
const FROM = () => process.env.MAIL_FROM ?? "RuyaShield <no-reply@ruyashield.local>";

export async function deliverRunFinished(orgId: string, payload: { assessmentId?: unknown }, messageId: string, mail: Pick<Transporter, "sendMail">): Promise<string> {
  const id = typeof payload.assessmentId === "string" && isUuid(payload.assessmentId) ? payload.assessmentId : null;
  if (!id) return "invalid_payload";

  const data = await withOrg(orgId, async (tx) => {
    const a = (await tx.select({ x: assessments, host: assets.host }).from(assessments).innerJoin(assets, eq(assets.id, assessments.assetId)).where(eq(assessments.id, id)))[0];
    if (!a) return null;
    // Findings seen in this run that are still open, and which of them the run created.
    const rows = await tx.selectDistinct({ id: findings.id, title: findings.title, severity: findings.severity, status: findings.status, firstSeen: findings.firstSeen })
      .from(findingOccurrences).innerJoin(findings, eq(findings.id, findingOccurrences.findingId))
      .where(and(eq(findingOccurrences.assessmentId, id), inArray(findings.status, [...OPEN_STATUSES])));
    const open = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const r of rows) if (r.severity in open) open[r.severity as keyof typeof open]++;
    const since = a.x.startedAt ?? a.x.queuedAt;
    const fresh = rows.filter((r) => (r.severity === "critical" || r.severity === "high") && r.firstSeen >= since)
      .sort((p, q) => sevRank(q.severity) - sevRank(p.severity));
    const people = await tx.select({ id: memberships.userId, role: memberships.role, email: users.email })
      .from(memberships).innerJoin(users, eq(users.id, memberships.userId)).where(eq(memberships.orgId, orgId));
    return { a, open, fresh, people };
  });
  if (!data) return "missing";
  const { a, open, fresh, people } = data;
  const host = a.host.startsWith("repo:") ? `repository ${a.host.slice(5)}` : a.host;
  const sum = runSummary({ host, status: a.x.status, reason: a.x.reason, coverage: a.x.coverage, open });
  const out: string[] = [];

  // 1. The launcher (if still a member).
  const launcher = people.find((p) => p.id === a.x.requestedBy);
  if (launcher) out.push(await send(orgId, launcher, "assessment_complete", sum.subject,
    `${sum.body}\n\nOpen it in RuyaShield:\n${LINK(`/assessments/${id}`)}\n`, `/assessments/${id}`, messageId, mail));

  // 2. New critical/high findings: every admin and security lead.
  if (fresh.length) {
    const n = (s: Severity) => fresh.filter((f) => f.severity === s).length;
    const subject = `New ${[n("critical") && `${n("critical")} critical`, n("high") && `${n("high")} high`].filter(Boolean).join(" and ")} finding${fresh.length === 1 ? "" : "s"} on ${host}`;
    const list = fresh.slice(0, 10).map((f) => `- [${f.severity}] ${f.title}\n  ${LINK(`/findings/${f.id}`)}`).join("\n");
    const body = `${subject}.\n\n${list}${fresh.length > 10 ? `\n…and ${fresh.length - 10} more` : ""}\n\nThe run that found them: ${LINK(`/assessments/${id}`)}\n`;
    const link = fresh.length === 1 ? `/findings/${fresh[0].id}` : `/findings?status=new&severity=${n("critical") ? "critical" : "high"}`;
    for (const p of people.filter((x) => x.role === "org_admin" || x.role === "security_lead")) {
      out.push(await send(orgId, p, "new_critical_finding", subject, body, link, id, mail));
    }
  }
  return out.length ? out.join(",") : "no_recipient";
}

const sevRank = (s: Severity) => ["info", "low", "medium", "high", "critical"].indexOf(s);

async function send(orgId: string, to: { id: string; email: string }, kind: NotifyKindAll, subject: string, text: string, link: string, sourceId: string, mail: Pick<Transporter, "sendMail">) {
  const ch = await withOrg(orgId, async (tx) => {
    await addInApp(tx, { orgId, userId: to.id, kind, title: subject, link, sourceId });
    return channelsFor(tx, orgId, to.id, kind);
  });
  if (!ch.email) return `${kind}:in_app`;
  await mail.sendMail({ from: FROM(), to: to.email, subject, text });
  return `${kind}:sent`;
}
