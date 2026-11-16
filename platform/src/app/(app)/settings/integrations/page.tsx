import { Suspense } from "react";
import { grantFor } from "@/server/policy/matrix";
import { listIntegrations } from "@/server/remediation/integrations";
import { ISOLATION_LABEL, sandboxAvailable } from "@/server/remediation/sandbox";
import { ActionForm } from "../../_components/ActionForm";
import { StatusBadge } from "../../_components/StatusBadge";
import { addRepositoryAssetAction, createIntegrationAction, disableIntegrationAction } from "../../actions";
import { fmt, pageOrg } from "../../_lib/page";
import { Empty, Loading, MetaChips, PageHeader, ProGate } from "../../_components/Page";
import { isProOrg } from "@/server/policy/policy";
import { TableWrap } from "../../_components/TableWrap";

export default function IntegrationsPage() {
  return (
    <>
      <PageHeader title="Repositories" lead="Connected repositories let patch plans be tested in a sandbox and, after approval, opened as a change on a new branch. RuyaShield never pushes to the default branch and never merges." />
      <Suspense fallback={<Loading />}><Integrations /></Suspense>
    </>
  );
}

async function Integrations() {
  const c = await pageOrg("/settings/integrations");
  if (!isProOrg(c.org)) {
    return (
      <ProGate title="Repositories" rows={5} features={["Dependency scanning", "Patch plans tested in a sandbox", "Changes on a new branch"]}>
        Connect a repository so fix plans can be tested in a sandbox and, after approval, opened as a change. RuyaShield never pushes to the default branch.
      </ProGate>
    );
  }
  if (grantFor(c.principal.role, "integration.manage") === "N") return <p className="notice warn">Only org admins and security leads can manage repositories.</p>;
  const rows = await listIntegrations(c);
  const active = rows.filter((r) => r.status === "active").length;
  return (
    <div className="split">
      <div className="split-main stack">
        <div className="notice warn small">
          Only the <strong>local git</strong> adapter exists in this build: it works with repositories in a directory on the RuyaShield host. GitHub and GitLab are not supported yet.
          Sandbox: {sandboxAvailable() ? ISOLATION_LABEL : "not installed on this deployment, so patch plans cannot be tested."}
        </div>
        <MetaChips label="Summary">
          <li>{active} connected</li>
          <li>{rows.length - active} disconnected</li>
        </MetaChips>
        {rows.length === 0 ? <Empty>No repositories connected yet.</Empty> : (
          <TableWrap className="card">
            <table className="repo-table"><thead><tr><th>Name</th><th>Repository</th><th>Default branch</th><th>Test commands</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td>{r.name}<div className="muted small nowrap">added {fmt(r.createdAt)}</div></td>
                  <td><code>{r.externalId}</code></td>
                  <td><span className="chip">{r.defaultBranch}</span></td>
                  <td className="small">{r.testCommands.length ? <ol className="cmd-list">{r.testCommands.map((t, i) => <li key={i}><code>{t.join(" ")}</code></li>)}</ol> : <span className="muted">none — sandbox tests unavailable</span>}</td>
                  <td><StatusBadge status={r.status} /></td>
                  <td>{r.status === "active" && (
                    <div className="row">
                      <ActionForm action={addRepositoryAssetAction} submit="Scan dependencies" className="row inline-form">
                        <input type="hidden" name="integrationId" value={r.id} />
                      </ActionForm>
                      <ActionForm action={disableIntegrationAction} submit="Disconnect" variant="danger" className="row inline-form">
                        <input type="hidden" name="integrationId" value={r.id} />
                      </ActionForm>
                    </div>
                  )}</td>
                </tr>
              ))}
            </tbody></table>
          </TableWrap>
        )}
      </div>
      <aside className="split-side">
        <div className="card">
          <h2>Connect a repository</h2>
          <ActionForm action={createIntegrationAction} submit="Connect">
            <label>Name<input name="name" required maxLength={100} /></label>
            <label>Repository directory name<input name="externalId" required maxLength={100} pattern="[A-Za-z0-9._-]+" className="mono" /><span className="field-hint">Under the configured local repository root. Letters, digits, dot, dash and underscore.</span></label>
            <label>Default branch<input name="defaultBranch" defaultValue="main" maxLength={100} className="mono" /></label>
            <label>Test commands<textarea name="testCommands" rows={3} className="mono" /><span className="field-hint">One per line, run in order without a shell (e.g. <code>npm test</code>).</span></label>
          </ActionForm>
        </div>
      </aside>
    </div>
  );
}
