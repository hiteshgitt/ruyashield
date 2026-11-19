import { Suspense } from "react";
import { grantFor } from "@/server/policy/matrix";
import { isProOrg } from "@/server/policy/policy";
import { FREE_FINDING_LIMIT } from "@/server/findings/findings";
import { db, withOrg } from "@/server/db/client";
import { orgs, plans, users } from "@/server/db/schema";
import { TRIAL_DAYS, trialDaysLeft } from "@/server/plans/lifecycle";
import { eq } from "drizzle-orm";
import { ActionForm } from "../../_components/ActionForm";
import { requestProAction, startTrialAction } from "../../actions";
import { fmt, pageOrg } from "../../_lib/page";
import { Loading, PageHeader } from "../../_components/Page";

const ROWS: [string, string | boolean, string | boolean][] = [
  ["Ownership-verified assets and assessments", true, true],
  ["Assessments per month", "20", "300"],
  ["Security score and severity counts", true, true],
  ["Findings shown in full", `Top ${FREE_FINDING_LIMIT}`, "All"],
  ["Suggested fix from each check", true, true],
  ["Evidence (request, response, headers)", false, true],
  ["Zealot AI explanations", false, true],
  ["Fix plans, sandbox tests and approvals", false, true],
  ["FixProof re-tests and regression checks", false, true],
  ["Trends and asset map", false, true],
  ["Attack monitoring (Cloudflare, log agent)", false, true],
  ["Reports (PDF, CSV) and all exports", false, true],
  ["WebMonitor connection", true, true],
];

const cell = (v: string | boolean) => (v === true ? <span className="plan-yes" aria-label="Included">✓</span> : v === false ? <span className="plan-no" aria-label="Not included">—</span> : <b>{v}</b>);

export default function PlanPage() {
  return (
    <>
      <PageHeader title="Plan" lead="What your organization's plan includes, and how to move to Pro." />
      <Suspense fallback={<Loading />}><Plan /></Suspense>
    </>
  );
}

async function Plan() {
  const c = await pageOrg("/settings/plan");
  const pro = isProOrg(c.org);
  const canRequest = grantFor(c.principal.role, "org.settings.edit") !== "N";
  const row = (await withOrg(c.org.id, (tx) => tx.select({ requestedAt: orgs.proRequestedAt, planSource: orgs.planSource, trialEndsAt: orgs.trialEndsAt })
    .from(orgs).where(eq(orgs.id, c.org.id))))[0];
  const onTrial = pro && row?.planSource === "trial";
  const daysLeft = row ? trialDaysLeft(row) : null;
  const me = (await db.select({ trialUsedAt: users.trialUsedAt }).from(users).where(eq(users.id, c.principal.userId)))[0];
  const canTrial = !pro && canRequest && !row?.trialEndsAt && !me?.trialUsedAt;
  const limits = (await db.select().from(plans).where(eq(plans.id, c.org.plan)))[0];
  return (
    <div className="stack">
      <section className={`card plan-hero${pro ? " is-pro" : ""}`}>
        <div>
          <p className="next-kicker">Current plan</p>
          <h2 className="plan-hero-title">{onTrial ? "RuyaShield Pro trial" : row?.planSource === "ruyalab" ? "Ruya Lab Pro" : pro ? "RuyaShield Pro" : "RuyaShield Free"}</h2>
          <p className="muted small">{onTrial
            ? `Everything is unlocked until ${fmt(row!.trialEndsAt!)} (${daysLeft === 1 ? "1 day" : `${daysLeft} days`} left). After that the organization goes back to Free unless Pro is activated.`
            : row?.planSource === "ruyalab" ? "Pro comes with Ruya Lab Pro on the creator's Ruya Lab account: everything is unlocked."
            : pro ? "Everything is unlocked: every finding with evidence, Zealot, fixes, re-tests, attacks, reports and downloads."
            : `Free shows your ${FREE_FINDING_LIMIT} highest-priority findings with each check's suggested fix. Pro unlocks the rest.`}
            {limits && <> Up to {limits.maxAssessmentsPerMonth} assessments a month.</>}</p>
        </div>
        {canTrial && (
          <div>
            <ActionForm action={startTrialAction} submit={`Start your free ${TRIAL_DAYS}-day Pro trial`} className="row" />
            <p className="muted small">No card needed. One trial per person.</p>
          </div>
        )}
        {(!pro || onTrial) && (canRequest ? (
          row?.requestedAt
            ? <p className="notice ok small">Requested {fmt(row.requestedAt)}. We will switch your organization to Pro and let your admins know.</p>
            : <ActionForm action={requestProAction} submit={onTrial ? "Request Pro to keep it" : "Request Pro"} className="row" />
        ) : <p className="muted small">Ask an org admin to request Pro.</p>)}
      </section>

      <div className="card plan-table-card">
        <table className="plan-table">
          <thead><tr><th>Feature</th><th className={!pro ? "current" : undefined}>Free</th><th className={pro ? "current" : undefined}>Pro</th></tr></thead>
          <tbody>{ROWS.map(([label, free, p]) => <tr key={label}><td>{label}</td><td>{cell(free)}</td><td>{cell(p)}</td></tr>)}</tbody>
        </table>
      </div>
    </div>
  );
}
