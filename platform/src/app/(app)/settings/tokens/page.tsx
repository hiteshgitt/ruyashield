import { Suspense } from "react";
import { grantFor, TOKEN_SCOPE_ACTIONS, TOKEN_SCOPES } from "@/server/policy/matrix";
import { listApiTokens, TOKEN_MAX_DAYS } from "@/server/tokens/tokens";
import { ActionForm } from "../../_components/ActionForm";
import { createTokenAction, revokeTokenAction } from "../../actions";
import { fmt, pageOrg } from "../../_lib/page";
import { Empty, Loading, MetaChips, PageHeader } from "../../_components/Page";
import { TableWrap } from "../../_components/TableWrap";

const TONE = { active: "ok", expired: "warn", revoked: "bad" } as const;

export default function TokensPage() {
  return (
    <>
      <PageHeader title="API tokens" lead={<>A token acts as the person who created it, limited to the scopes chosen. It can only read findings and assets or generate reports: it can never approve, change settings or delete. Send it as <code>Authorization: Bearer rs_…</code>.</>} />
      <Suspense fallback={<Loading />}><Tokens /></Suspense>
    </>
  );
}

async function Tokens() {
  const c = await pageOrg("/settings/tokens");
  if (grantFor(c.principal.role, "token.manage") === "N") return <p className="notice warn">Only org admins can manage API tokens.</p>;
  const now = new Date();
  const tokens = await listApiTokens(c);
  const rows = tokens.map((t) => ({ t, status: t.revokedAt ? "revoked" as const : t.expiresAt.getTime() <= now.getTime() ? "expired" as const : "active" as const }));
  const active = rows.filter((r) => r.status === "active").length;
  return (
    <div className="split">
      <div className="split-main">
        <MetaChips label="Summary">
          <li>{active} active</li>
          <li>{rows.length - active} expired or revoked</li>
        </MetaChips>
        {rows.length === 0 ? <Empty>No tokens yet. Create one to read findings and assets or generate reports from scripts.</Empty> : (
          <TableWrap className="card">
            <table className="token-table">
              <thead><tr><th>Name</th><th>Prefix</th><th>Scopes</th><th>Created by</th><th>Expires</th><th>Last used</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>{rows.map(({ t, status }) => (
                <tr key={t.id}>
                  <td>{t.name}</td><td><code className="nowrap">{t.prefix}…</code></td>
                  <td><span className="scope-list">{t.scopes.map((s) => <span key={s} className="class-tag">{s}</span>)}</span></td>
                  <td className="small">{t.createdBy ?? "—"}</td>
                  <td className="small nowrap">{fmt(t.expiresAt)}</td><td className="small nowrap">{t.lastUsedAt ? fmt(t.lastUsedAt) : <span className="muted">never</span>}</td>
                  <td><span className={`badge ${TONE[status]}`}>{status}</span></td>
                  <td>{status === "active" && (
                    <ActionForm action={revokeTokenAction} submit="Revoke" variant="danger" className="row inline-form">
                      <input type="hidden" name="tokenId" value={t.id} />
                    </ActionForm>
                  )}</td>
                </tr>
              ))}</tbody>
            </table>
          </TableWrap>
        )}
      </div>

      <aside className="split-side">
        <div className="card">
          <h2>Create a token</h2>
          <ActionForm action={createTokenAction} submit="Create token">
            <label>Name <input type="text" name="name" required maxLength={80} /></label>
            <fieldset className="checks">
              <legend>Scopes</legend>
              {TOKEN_SCOPES.map((s) => (
                <label key={s} className="check-opt">
                  <input type="checkbox" name="scopes" value={s} />
                  <span className="check-text">
                    <span className="check-title mono">{s}</span>
                    <span className="muted small">Allows {TOKEN_SCOPE_ACTIONS[s].join(", ")}</span>
                  </span>
                </label>
              ))}
            </fieldset>
            <label>Expires in (days, up to {TOKEN_MAX_DAYS}) <input type="number" name="days" required min={1} max={TOKEN_MAX_DAYS} defaultValue={90} /></label>
            <p className="muted small">The token is shown once after creation. Copy it then: it cannot be shown again.</p>
          </ActionForm>
        </div>
      </aside>
    </div>
  );
}
