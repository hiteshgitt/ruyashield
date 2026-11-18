import Link from "next/link";
import type { EdgeView } from "@/server/edge/edge";
import { ActionForm } from "../../_components/ActionForm";
import { applyEdgeFixesAction, connectEdgeAction, disconnectEdgeAction, undoEdgeFixesAction } from "../../actions";
import { fmt } from "../../_lib/page";

/** Fix missing security headers at Cloudflare: one RuyaShield rule for this host, applied after a fresh MFA confirmation. */
export function EdgeFixes({ assetId, host, view, canManage }: { assetId: string; host: string; view: EdgeView; canManage: boolean }) {
  const conn = view.connection;
  const needed = view.fixes.filter((f) => f.findings.length > 0);
  return (
    <section aria-labelledby="h-edge">
      <h2 id="h-edge">Fix headers at Cloudflare</h2>
      <div className="card stack">
        {!conn ? (
          <>
            <p className="small">
              If {host} runs behind Cloudflare, RuyaShield can add the missing security headers there, without touching your server.
              {needed.length ? <> It would fix <strong>{needed.reduce((n, f) => n + f.findings.length, 0)} open finding{needed.reduce((n, f) => n + f.findings.length, 0) === 1 ? "" : "s"}</strong> on this site.</> : null}
              {" "}You choose the headers, confirm with your authenticator, and can undo it in one click.
            </p>
            {canManage ? (
              <>
                <ol className="small" style={{ paddingLeft: "1.1rem", margin: 0 }}>
                  <li>In Cloudflare open <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noreferrer">My Profile → API Tokens → Create Token → Create Custom Token</a>.</li>
                  <li>Permissions: <strong>Zone → Zone → Read</strong> and <strong>Zone → Transform Rules → Edit</strong>.</li>
                  <li>Zone Resources: <strong>Include → Specific zone →</strong> the zone of {host}.</li>
                  <li>Copy the zone ID from the zone&apos;s Overview page (right-hand column).</li>
                </ol>
                <ActionForm action={connectEdgeAction} submit="Connect Cloudflare">
                  <input type="hidden" name="assetId" value={assetId} />
                  <label>Zone ID<input name="zoneId" required maxLength={32} pattern="[a-fA-F0-9]{32}" className="mono" /></label>
                  <label>API token<input name="token" type="password" required maxLength={200} autoComplete="off" spellCheck={false} className="mono" /><span className="field-hint">Stored encrypted, never shown again.</span></label>
                </ActionForm>
              </>
            ) : <p className="muted small">An org admin or security lead can connect Cloudflare.</p>}
          </>
        ) : (
          <>
            <p className="small">
              Connected to Cloudflare zone <strong>{conn.zoneName}</strong>.{" "}
              {conn.appliedFixes.length
                ? <>RuyaShield&apos;s rule has been live since {conn.appliedAt ? fmt(conn.appliedAt) : "—"} and sets {conn.appliedFixes.length} header{conn.appliedFixes.length === 1 ? "" : "s"} on {host}.</>
                : <>No RuyaShield rule is live.</>}
            </p>
            {conn.lastError && <p className="notice bad small">The last attempt failed ({conn.lastError}). Check the token&apos;s permissions.</p>}
            {canManage && (
              <ActionForm action={applyEdgeFixesAction} submit={conn.appliedFixes.length ? "Update rule at Cloudflare" : "Apply at Cloudflare"}>
                <input type="hidden" name="assetId" value={assetId} />
                <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0 }}>
                  <legend className="small muted">Headers to set on {host} (you&apos;ll be asked for a fresh authenticator code if needed)</legend>
                  {view.fixes.map((f) => {
                    const on = conn.appliedFixes.includes(f.key);
                    return (
                      <label key={f.key} style={{ display: "flex", gap: 10, alignItems: "flex-start", fontWeight: 400 }}>
                        <input type="checkbox" name="fix" value={f.key} defaultChecked={on || f.findings.length > 0} style={{ width: "auto", marginTop: 4 }} />
                        <span>
                          <code>{f.header}: {f.value}</code>
                          {on && <span className="chip" style={{ marginLeft: 6 }}>live</span>}
                          <span className="small muted" style={{ display: "block" }}>{f.note}</span>
                          {f.findings.length > 0 && (
                            <span className="small" style={{ display: "block" }}>Fixes: {f.findings.map((x, i) => <span key={x.id}>{i ? ", " : ""}<Link href={`/findings/${x.id}`}>{x.title}</Link></span>)}</span>
                          )}
                        </span>
                      </label>
                    );
                  })}
                </fieldset>
                <p className="muted small" style={{ margin: 0 }}>Content-Security-Policy is not set automatically: a wrong policy breaks pages. Build it with report-only mode first.</p>
              </ActionForm>
            )}
            {canManage && (
              <div className="row">
                {conn.appliedFixes.length > 0 && (
                  <ActionForm action={undoEdgeFixesAction} submit="Undo (remove rule)" variant="secondary" className="row inline-form">
                    <input type="hidden" name="assetId" value={assetId} />
                  </ActionForm>
                )}
                <ActionForm action={disconnectEdgeAction} submit="Disconnect Cloudflare" variant="danger" className="row inline-form">
                  <input type="hidden" name="assetId" value={assetId} />
                </ActionForm>
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}
