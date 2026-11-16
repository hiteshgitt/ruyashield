import { Suspense } from "react";
import { grantFor } from "@/server/policy/matrix";
import { DELETION_GRACE_DAYS, orgLifecycle } from "@/server/orgs/lifecycle";
import { ActionForm } from "../../_components/ActionForm";
import { cancelOrgDeletionAction, legalHoldAction, requestOrgDeletionAction } from "../../actions";
import { fmt, pageOrg } from "../../_lib/page";
import { Loading, MetaChips, PageHeader, SectionHead } from "../../_components/Page";

export default function OrganizationPage() {
  return (
    <>
      <PageHeader title="Organization" />
      <Suspense fallback={<Loading />}><Organization /></Suspense>
    </>
  );
}

async function Organization() {
  const c = await pageOrg("/settings/organization");
  const canDelete = grantFor(c.principal.role, "org.delete") !== "N";
  const canHold = grantFor(c.principal.role, "retention.manage") !== "N";
  if (!canDelete && !canHold) return <p className="notice warn">Only org admins can manage the organization&apos;s lifecycle.</p>;
  const l = await orgLifecycle(c);
  return (
    <div className="stack">
      <MetaChips label="Organization">
        <li><span className="muted">Name</span> {c.org.name}</li>
        <li><span className="muted">Slug</span> <span className="mono">{c.org.slug}</span></li>
        <li><span className="muted">Legal hold</span> {l.legalHold ? "on" : "off"}</li>
        {l.deletionRequestedAt && <li><span className="muted">Deletion</span> pending</li>}
      </MetaChips>
      {canHold && (
        <section className="card" aria-labelledby="hold-h">
          <SectionHead title="Legal hold" id="hold-h" variant="setting"><span className={`badge ${l.legalHold ? "warn" : "ok"}`}>{l.legalHold ? "on" : "off"}</span></SectionHead>
          <p className="muted small">While on, retention purges skip this organization and it cannot be deleted. Changes need a recent MFA sign-in and are audited.</p>
          <ActionForm action={legalHoldAction} submit={l.legalHold ? "Release legal hold" : "Place legal hold"} variant={l.legalHold ? "secondary" : "danger"} className="row inline-form grow">
            <input type="hidden" name="on" value={l.legalHold ? "false" : "true"} />
            <input type="text" name="reason" required minLength={3} placeholder="Reason (required)" aria-label="Reason" />
          </ActionForm>
        </section>
      )}
      {canDelete && (
        <section className="card danger-zone" aria-labelledby="delete-h">
          <p className="danger-eyebrow">Danger zone</p>
          <SectionHead title="Delete organization" id="delete-h" variant="setting">{l.deletionRequestedAt && <span className="badge bad">deletion pending</span>}</SectionHead>
          {l.deletionRequestedAt ? (
            <>
              <p className="notice bad">Deletion requested {fmt(l.deletionRequestedAt)}. All access ends after {fmt(l.finalizeAfter)} unless cancelled. Data is then erased by an operator following the erasure runbook.</p>
              <ActionForm action={cancelOrgDeletionAction} submit="Cancel deletion" variant="secondary" className="row inline-form grow">
                <input type="text" name="reason" required minLength={3} placeholder="Reason (required)" aria-label="Reason" />
              </ActionForm>
            </>
          ) : l.legalHold ? (
            <p className="notice warn small">Not available while a legal hold is in place.</p>
          ) : (
            <>
              <ol className="consequences small">
                <li>A {DELETION_GRACE_DAYS}-day grace period starts. Admins are notified and can cancel during it.</li>
                <li>After the grace period, all access ends.</li>
                <li>The organization&apos;s data is then scheduled for erasure, carried out by an operator following the erasure runbook.</li>
              </ol>
              <ActionForm action={requestOrgDeletionAction} submit="Request deletion" variant="danger">
                <label>Type <code>{c.org.slug}</code> to confirm <input type="text" name="confirmSlug" required autoComplete="off" /></label>
                <label>Reason <input type="text" name="reason" required minLength={3} maxLength={500} /></label>
              </ActionForm>
            </>
          )}
        </section>
      )}
    </div>
  );
}
