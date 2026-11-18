import { randomUUID } from "node:crypto";
import { Suspense } from "react";
import Link from "next/link";
import { notFound } from "next/navigation";
import { grantFor } from "@/server/policy/matrix";
import { getAsset, METHODS } from "@/server/assets/assets";
import { assetTechnologies } from "@/server/assets/technology";
import { withOrg } from "@/server/db/client";
import type { Technology } from "@/server/assessments/technology";
import { listAssessments, listCatalogue } from "@/server/assessments/assessments";
import { instructions } from "@/server/assets/check";
import { isAppError } from "@/server/errors";
import { ActionForm } from "../../_components/ActionForm";
import { Coverage } from "../../_components/Coverage";
import { StatusBadge } from "../../_components/StatusBadge";
import { checkVerificationAction, launchAssessmentAction, recordAttestationAction, revokeAttestationAction, setCriticalityAction, startVerificationAction } from "../../actions";
import { fmt, pageOrg } from "../../_lib/page";
import { Empty, Loading } from "../../_components/Page";
import { TableWrap } from "../../_components/TableWrap";

const METHOD_LABEL: Record<string, string> = { dns_txt: "DNS TXT record", http_file: "File at /.well-known/", meta_tag: "HTML meta tag on the home page" };
const CLASS_LABEL: Record<string, string> = { P: "passive", A1: "safe active", A2: "intrusive", X: "destructive" };

export default function AssetPage({ params, searchParams }: PageProps<"/assets/[id]">) {
  return (
    <>
      <p className="small crumb"><Link href="/assets">← Assets</Link></p>
      <Suspense fallback={<Loading />}><Asset params={params} searchParams={searchParams} /></Suspense>
    </>
  );
}

async function Asset({ params, searchParams }: { params: PageProps<"/assets/[id]">["params"]; searchParams: PageProps<"/assets/[id]">["searchParams"] }) {
  const { id } = await params;
  // ?referral=<id> from a consented WebMonitor referral: the launch is linked to it (status link-back).
  const ref = (await searchParams).referral;
  const referralId = typeof ref === "string" && /^[0-9a-f-]{36}$/i.test(ref) ? ref : null;
  const c = await pageOrg(`/assets/${id}`);
  let data;
  try {
    data = await getAsset(c, id);
  } catch (e) {
    if (isAppError(e) && e.status === 404) notFound();
    throw e;
  }
  const { asset: a, verifications, attestations, eligibility: el } = data;
  const role = c.principal.role;
  const canVerify = grantFor(role, "asset.verify") !== "N";
  const canAttest = grantFor(role, "asset.attest") !== "N";
  const now = new Date();
  const pending = verifications.find((v) => v.status === "pending" && v.expiresAt > now);
  const today = now.toISOString().slice(0, 10);
  const inYear = new Date(now.getTime() + 364 * 86_400_000).toISOString().slice(0, 10);
  const canLaunch = el.eligible && grantFor(role, "assessment.launch") !== "N";
  const isRepo = a.kind === "repository";
  const stack = isRepo ? null : await withOrg(c.org.id, (tx) => assetTechnologies(tx, a.id));
  const catalogue = canLaunch ? await listCatalogue(c, a.kind) : [];
  const recent = (await listAssessments(c, { assetId: a.id })).slice(0, 5);
  const canEdit = grantFor(role, "asset.edit") !== "N";
  const liveAttestations = attestations.filter((t) => !t.revokedAt && t.validFrom <= today && today < t.validTo).length;

  const assessments = (
    <section key="assessments" aria-labelledby="h-assessments">
      <h2 id="h-assessments">Assessments</h2>
      {canLaunch && (
        <div className="card">
          <ActionForm action={launchAssessmentAction} submit="Launch assessment" pending="Queuing…">
            <input type="hidden" name="assetId" value={a.id} />
            <input type="hidden" name="idempotencyKey" value={randomUUID()} />
            {referralId && <input type="hidden" name="referralId" value={referralId} />}
            {referralId && <p className="notice ok small">This assessment is linked to the WebMonitor referral you consented to.</p>}
            <fieldset className="checks">
              <legend>Checks</legend>
              {catalogue.map((d) => {
                const allowed = d.launchable && (el.allowedClasses as readonly string[]).includes(d.class);
                return (
                  <label key={d.id} className={`check-opt${allowed ? "" : " off"}`}>
                    <input type="checkbox" name="checkIds" value={d.id} disabled={!allowed} defaultChecked={allowed} />
                    <span className="check-text">
                      <span className="check-title">{d.title}</span>
                      <span className="muted small">{isRepo ? "Reads the repository; sends only package names and versions to OSV.dev" : d.requestBudget ? `Up to ${d.requestBudget} requests` : "No requests to the site"}</span>
                      {!allowed && <span className="small check-why">{d.class === "X" ? "Prohibited, never runs" : !d.launchable ? "Not available" : "Not covered by this asset's authorization"}</span>}
                    </span>
                    <span className="class-tag" title={`Class ${d.class}: ${CLASS_LABEL[d.class] ?? d.class}`}>{d.class} · {CLASS_LABEL[d.class] ?? d.class}</span>
                  </label>
                );
              })}
            </fieldset>
            {isRepo ? (
              <p className="small muted">Scans the default branch&apos;s latest commit. No code leaves this server. You can cancel at any time.</p>
            ) : (<>
              <div className="grid2">
                <label>Base paths (optional, one per line)<textarea name="basePaths" rows={2} placeholder="/" /></label>
                <label>Excluded paths (optional)<textarea name="excludedPaths" rows={2} placeholder="/admin" /></label>
              </div>
              <p className="small muted">Traffic goes only to <code>{a.host}</code>, spaced at least 0.5 s apart, within the request budget. You can cancel at any time.</p>
            </>)}
          </ActionForm>
        </div>
      )}
      {!canLaunch && el.eligible && <p className="muted">Your role cannot launch assessments.</p>}
      {!el.eligible && <p className="muted small">Assessments can be launched once ownership is verified or a written authorization is recorded.</p>}
      {recent.length > 0 ? (
        <TableWrap className="card">
          <table><thead><tr><th>Queued</th><th>Status</th><th>Coverage</th></tr></thead><tbody>
            {recent.map(({ assessment: x }) => (
              <tr key={x.id}>
                <td><Link href={`/assessments/${x.id}`}>{fmt(x.queuedAt)}</Link></td>
                <td><StatusBadge status={x.status} /></td>
                <td className="small"><Coverage c={x.coverage} /></td>
              </tr>
            ))}
          </tbody></table>
        </TableWrap>
      ) : <Empty>No assessments of this asset yet.</Empty>}
    </section>
  );

  const ownership = isRepo ? (
    <section key="ownership" aria-labelledby="h-ownership">
      <h2 id="h-ownership">Repository connection</h2>
      <div className="card stack">
        {a.status === "verified"
          ? <div className="notice ok"><strong>Authorized</strong> through its repository connection since {fmt(a.verifiedAt)}. No DNS or HTTP challenge is needed for a repository you connected yourself.</div>
          : <div className="notice warn">The repository connection was disconnected, so this asset can no longer be scanned. Reconnect it in <Link href="/settings/integrations">Repositories</Link> and choose <em>Scan dependencies</em>.</div>}
      </div>
    </section>
  ) : (
    <section key="ownership" aria-labelledby="h-ownership">
      <h2 id="h-ownership">Ownership verification</h2>
      <div className="card stack">
        {a.status === "verified" && (
          <div className="notice ok"><strong>Verified</strong> by {METHOD_LABEL[a.verifiedMethod ?? ""] ?? a.verifiedMethod} at {fmt(a.verifiedAt)}. Re-checked automatically; next check {fmt(a.nextReverifyAt)}.</div>
        )}
        {a.status !== "verified" && !pending && (
          <p className="muted small">Prove you control <code>{a.host}</code> by publishing a one-time value, then ask RuyaShield to check it. Choose the method that suits your access: DNS, a file on the web server, or a meta tag on the home page.</p>
        )}
        {pending && (
          <PendingChallenge method={pending.method} host={a.host} token={pending.token} expiresAt={pending.expiresAt}
            lastResult={pending.checkedAt ? { at: pending.checkedAt, reason: pending.reason } : null}
            verificationId={pending.id} canVerify={canVerify} />
        )}
        {canVerify && a.status !== "revoked" && (
          <ActionForm action={startVerificationAction} submit={pending ? "Start a new challenge" : "Start verification"} variant={pending ? "secondary" : "primary"} className="row">
            <input type="hidden" name="assetId" value={a.id} />
            <label className="grow">Method<select name="method" defaultValue="dns_txt">
              {METHODS.map((m) => <option key={m} value={m}>{METHOD_LABEL[m]}</option>)}
            </select></label>
          </ActionForm>
        )}
        {!canVerify && a.status !== "verified" && <p className="muted">Ask an admin, security lead or analyst to verify this asset.</p>}
      </div>
    </section>
  );

  return (
    <>
      <div className="badge-row">
        <StatusBadge status={a.status} />
        {isRepo ? <span className="chip">repository</span> : <span className="chip">{a.environment}</span>}
      </div>
      <h1 className="mono-title">{isRepo ? a.displayName : a.host}</h1>
      {isRepo ? <p className="muted">Repository <code>{a.host.slice(5)}</code></p> : a.displayName !== a.host && <p className="muted">{a.displayName}</p>}

      <div className={`notice ${el.eligible ? "ok" : "warn"}`}>
        <strong>{el.eligible ? "Eligible for assessment" : "Not eligible for assessment"}.</strong> {el.reason}
        {el.eligible && <> Permitted classes: {el.allowedClasses.join(", ")}. Intrusive (A2) port checks are off until two admins turn them on in Settings → Safety; destructive (X) actions are never executed.</>}
      </div>

      <div className="detail">
        <aside className="detail-side card" aria-labelledby="h-readiness">
          <h2 id="h-readiness" className="card-label">Testing readiness</h2>
          <ol className="readiness">
            <li className="done"><span className="badge ok">Done</span> Asset added</li>
            <li className={a.status === "verified" ? "done" : undefined}>
              <StatusBadge status={a.status === "unverified" && pending ? "pending" : a.status} /> {isRepo ? `Repository ${a.status === "verified" ? "connected" : "disconnected"}` : `Ownership ${a.status === "verified" ? "verified" : pending ? "challenge open" : "not verified"}`}
            </li>
            <li className={liveAttestations ? "done" : undefined}>
              <span className={`badge${liveAttestations ? " ok" : ""}`}>{liveAttestations ? `${liveAttestations} active` : "None"}</span> Written authorization
            </li>
            <li className={el.eligible ? "done" : undefined}>
              <span className={`badge ${el.eligible ? "ok" : "warn"}`}>{el.eligible ? "Eligible" : "Not eligible"}</span> Assessment
            </li>
          </ol>
          <p className="muted small">Either verified ownership or an active written authorization makes an asset eligible.</p>
        </aside>

        <div className="detail-triage card" aria-labelledby="h-asset">
          <h2 id="h-asset" className="card-label">Asset</h2>
          <dl className="kv small">
            <dt>Environment</dt><dd>{a.environment}</dd>
            <dt>Criticality</dt><dd>{a.criticality ?? "not set (medium assumed for priority)"}</dd>
            {a.status === "verified" && !isRepo && <><dt>Next check</dt><dd>{fmt(a.nextReverifyAt)}</dd></>}
          </dl>
          {canEdit && (
            <ActionForm key={a.criticality ?? ""} action={setCriticalityAction} submit="Save" variant="secondary" className="row">
              <input type="hidden" name="assetId" value={a.id} />
              <label className="grow">Business criticality<select name="criticality" defaultValue={a.criticality ?? "medium"}>
                {["critical", "high", "medium", "low"].map((v) => <option key={v}>{v}</option>)}
              </select></label>
            </ActionForm>
          )}
          {grantFor(role, "finding.view") !== "N" && <p className="small"><Link href={`/findings?assetId=${a.id}&status=open`}>Open findings for this asset →</Link></p>}
          {!isRepo && <TechnologyCard stack={stack} />}
        </div>

        <div className="detail-main">
          {/* The next useful step comes first: verification until the asset is eligible, then assessments. */}
          {el.eligible ? [assessments, ownership] : [ownership, assessments]}

          {!isRepo && <section aria-labelledby="h-auth">
            <h2 id="h-auth">Recorded authorizations</h2>
            <p className="muted small">For assets you do not own (for example a client&apos;s site), record who gave written permission. RuyaShield stores the record; it does not validate the underlying document.</p>
            <TableWrap className="card">
              {attestations.length === 0 ? <Empty>No authorizations recorded.</Empty> : (
                <table><thead><tr><th>Authorized by</th><th>Classes</th><th>Valid</th><th>Status</th><th /></tr></thead><tbody>
                  {attestations.map((t) => {
                    const live = !t.revokedAt && t.validFrom <= today && today < t.validTo;
                    return (
                      <tr key={t.id}>
                        <td>{t.partyName}, {t.partyRole}<div className="muted small">{t.partyEmail} · {t.relationship.replace("_", " ")}</div></td>
                        <td className="mono small">{t.allowedClasses.join(", ")}</td>
                        <td className="small nowrap">{t.validFrom} → {t.validTo}</td>
                        <td><StatusBadge status={t.revokedAt ? "revoked" : live ? "verified" : "expired"} /></td>
                        <td>{canAttest && !t.revokedAt && (
                          <ActionForm action={revokeAttestationAction} submit="Revoke" variant="danger" className="row nowrap">
                            <input type="hidden" name="attestationId" value={t.id} />
                            <input type="text" name="reason" placeholder="Reason" aria-label="Reason" style={{ width: 140 }} />
                          </ActionForm>
                        )}</td>
                      </tr>
                    );
                  })}
                </tbody></table>
              )}
            </TableWrap>
            {canAttest && a.status !== "revoked" && (
              <details className="form-disclosure" open={attestations.length === 0 && !el.eligible ? true : undefined}>
                <summary>Record a written authorization</summary>
                <ActionForm action={recordAttestationAction} submit="Record authorization">
                  <input type="hidden" name="assetId" value={a.id} />
                  <div className="grid2">
                    <label>Authorizing person<input type="text" name="partyName" required /></label>
                    <label>Their title<input type="text" name="partyRole" required /></label>
                    <label>Their email<input type="email" name="partyEmail" required /></label>
                    <label>Relationship<select name="relationship" defaultValue="client">
                      <option value="client">Client</option><option value="parent_company">Parent company</option><option value="subsidiary">Subsidiary</option>
                      <option value="hosting_customer">Hosting customer</option><option value="other">Other</option>
                    </select></label>
                    <label>Valid from<input type="date" name="validFrom" required defaultValue={today} /></label>
                    <label>Valid to (max 12 months)<input type="date" name="validTo" required defaultValue={inYear} /></label>
                  </div>
                  <fieldset className="row">
                    <legend>Permitted test classes</legend>
                    <label className="check"><input type="checkbox" name="allowedClasses" value="P" defaultChecked /> P — passive</label>
                    <label className="check"><input type="checkbox" name="allowedClasses" value="A1" /> A1 — safe active</label>
                  </fieldset>
                  <label className="check confirm"><input type="checkbox" name="confirm" required /> I confirm we hold written authorization from this person to test this asset within these dates.</label>
                </ActionForm>
              </details>
            )}
          </section>}
        </div>

        {verifications.length > 0 && (
          <section className="detail-tail" aria-labelledby="h-history">
            <h2 id="h-history">Verification history</h2>
            <TableWrap className="card">
              <table><thead><tr><th>Method</th><th>Status</th><th>Last result</th><th>Checked</th></tr></thead><tbody>
                {verifications.map((v) => (
                  <tr key={v.id}>
                    <td>{METHOD_LABEL[v.method]}</td><td><StatusBadge status={v.status} /></td>
                    <td className="small">{v.reason ?? "—"}</td><td className="small">{fmt(v.checkedAt)}</td>
                  </tr>
                ))}
              </tbody></table>
            </TableWrap>
          </section>
        )}
      </div>
    </>
  );
}

function PendingChallenge(p: { method: string; host: string; token: string; expiresAt: Date; verificationId: string; canVerify: boolean; lastResult: { at: Date; reason: string | null } | null }) {
  const ins = instructions(p.method as Parameters<typeof instructions>[0], p.host, p.token);
  return (
    <div className="stack">
      <div className="badge-row"><span className="badge warn">Pending</span><span className="chip">{METHOD_LABEL[p.method]}</span></div>
      <ol className="flow">
        <li>
          <p className="flow-title">Publish the value</p>
          <p className="small muted">{ins.how}</p>
          <div className="field-copy"><span className="card-label">Location</span><code>{ins.where}</code></div>
          <div className="field-copy"><span className="card-label">Value</span><code>{ins.what}</code></div>
        </li>
        <li>
          <p className="flow-title">Ask RuyaShield to check it</p>
          <p className="small muted">Challenge expires {fmt(p.expiresAt)}. DNS changes can take a few minutes to appear.</p>
          {p.lastResult && <p className="notice warn small"><strong>Not verified yet.</strong> Last check {fmt(p.lastResult.at)}: {p.lastResult.reason}.</p>}
          {p.canVerify && (
            <ActionForm action={checkVerificationAction} submit="Check now" pending="Checking…">
              <input type="hidden" name="verificationId" value={p.verificationId} />
            </ActionForm>
          )}
        </li>
      </ol>
    </div>
  );
}

const CATEGORY_LABEL: Record<string, string> = { platform: "Platform", framework: "Framework", language: "Language", server: "Web server", cdn: "CDN / hosting", library: "Library", analytics: "Analytics" };

/** What the latest technology check saw: platform, framework, PHP, server, CDN, libraries. */
function TechnologyCard({ stack }: { stack: { technologies: Technology[]; seenAt: Date | null } | null }) {
  return (
    <div className="tech-card">
      <h3 className="card-label">Technology</h3>
      {!stack ? (
        <p className="muted small">Detected at the next assessment (platform, framework, PHP, server, CDN and libraries).</p>
      ) : stack.technologies.length === 0 ? (
        <p className="muted small">Nothing identifiable in the public home page.</p>
      ) : (
        <ul className="tech-list">
          {stack.technologies.map((t) => (
            <li key={t.name}>
              <span className="tech-name">{t.name}{t.version && <span className="tech-version">{t.version}</span>}</span>
              <span className="muted small">{CATEGORY_LABEL[t.category] ?? t.category}</span>
            </li>
          ))}
        </ul>
      )}
      {stack?.seenAt && <p className="muted small">Seen {fmt(stack.seenAt)}. Only what the site shows publicly.</p>}
    </div>
  );
}
