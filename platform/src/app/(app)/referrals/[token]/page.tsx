import { Suspense } from "react";
import Link from "next/link";
import { getReferralByToken } from "@/server/webmonitor/referrals";
import { grantFor } from "@/server/policy/matrix";
import { isAppError } from "@/server/errors";
import { ActionForm } from "../../_components/ActionForm";
import { StatusBadge } from "../../_components/StatusBadge";
import { decideReferralAction, deleteReferralAction } from "../../actions";
import { fmt, pageOrg } from "../../_lib/page";
import { Loading, PageHeader } from "../../_components/Page";

export default function ReferralPage({ params }: PageProps<"/referrals/[token]">) {
  return (
    <>
      <PageHeader title="WebMonitor referral" lead="WebMonitor noticed something about a site and suggested a RuyaShield assessment. A referral is only a suggestion: nothing is scanned until the site is a verified asset of this organization and someone here launches an assessment." />
      <Suspense fallback={<Loading />}><Referral params={params} /></Suspense>
    </>
  );
}

async function Referral({ params }: { params: PageProps<"/referrals/[token]">["params"] }) {
  const { token } = await params;
  const c = await pageOrg(`/referrals/${token}`);
  let r;
  try { r = await getReferralByToken(c, token); } catch (e) {
    if (isAppError(e) && e.status === 404) return <p className="notice warn">This referral link is not valid.</p>;
    throw e;
  }
  const mayDecide = grantFor(c.principal.role, "referral.consent") !== "N";
  return (
    <div className="stack">
      <div className="card stack small">
        <div><strong>{r.host}</strong> <StatusBadge status={r.status} /> <span className="badge">{r.signalType}</span></div>
        <div className="muted">Observed {fmt(r.observedAt)} · received {fmt(r.receivedAt)} · link expires {fmt(r.expiresAt)}</div>
        {r.summary && (
          <>
            <div className="muted">WebMonitor&apos;s note (shown as plain text; it is not verified by RuyaShield):</div>
            <pre style={{ whiteSpace: "pre-wrap" }}>{r.summary}</pre>
          </>
        )}
        {r.assetId
          ? (r.assetVerified
            ? <div className="notice ok">This site is a verified asset. <Link href={`/assets/${r.assetId}`}>Open the asset</Link></div>
            : <div className="notice warn">This site is an asset but ownership is not verified yet. <Link href={`/assets/${r.assetId}`}>Verify ownership</Link> before an assessment can run.</div>)
          : <div className="notice warn">This site is not an asset of this organization. <Link href="/assets">Add and verify it</Link> before an assessment can run.</div>}
      </div>

      {r.status !== "pending_consent" ? <p className="muted small">This referral is {r.status.replace(/_/g, " ")}; the link cannot be used again.</p>
        : !mayDecide ? <p className="muted">Your role cannot decide referrals. Ask an org admin or security lead.</p>
        : (
          <div className="grid2">
            <ActionForm action={decideReferralAction} submit="Consent">
              <input type="hidden" name="token" value={token} />
              <input type="hidden" name="decision" value="consent" />
              <input type="hidden" name="textVersion" value={r.consentTextVersion} />
              <p className="small">I agree that this organization may run a RuyaShield assessment of <strong>{r.host}</strong>, within the scope of a verified asset, after someone here launches it.</p>
              <label className="small"><input type="checkbox" name="acceptCharges" required /> I understand an assessment started from this referral may be charged under our plan.</label>
              <label className="small"><input type="checkbox" name="shareStatus" /> Let RuyaShield tell WebMonitor the assessment status, severity counts and FixProof status (never evidence or finding details).</label>
              <p className="muted small">Consent wording {r.consentTextVersion}</p>
            </ActionForm>
            <div className="stack">
              <ActionForm action={decideReferralAction} submit="Decline" variant="secondary">
                <input type="hidden" name="token" value={token} />
                <input type="hidden" name="decision" value="decline" />
                <input type="hidden" name="textVersion" value={r.consentTextVersion} />
              </ActionForm>
              <ActionForm action={decideReferralAction} submit="Delete referral" variant="danger">
                <input type="hidden" name="token" value={token} />
                <input type="hidden" name="decision" value="delete" />
                <input type="hidden" name="textVersion" value={r.consentTextVersion} />
                <p className="muted small">Removes WebMonitor&apos;s note; only the fact that a referral was received is kept.</p>
              </ActionForm>
            </div>
          </div>
        )}
      {r.status !== "pending_consent" && r.status !== "deleted" && mayDecide && (
        <ActionForm action={deleteReferralAction} submit="Delete referral" variant="danger">
          <input type="hidden" name="referralId" value={r.id} />
        </ActionForm>
      )}
    </div>
  );
}
