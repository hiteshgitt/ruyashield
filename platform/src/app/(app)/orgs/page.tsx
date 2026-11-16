import { Suspense } from "react";
import { redirect } from "next/navigation";
import { getContext } from "@/server/context";
import { listUserOrgs } from "@/server/orgs/orgs";
import { ActionForm } from "../_components/ActionForm";
import { createOrgAction, selectOrgAction } from "../actions";
import { Loading, PageHeader } from "../_components/Page";
import { TableWrap } from "../_components/TableWrap";

export default function OrgsPage() {
  return (
    <>
      <PageHeader title="Organizations" />
      <Suspense fallback={<Loading />}><Orgs /></Suspense>
    </>
  );
}

async function Orgs() {
  const c = await getContext();
  if (!c) redirect("/auth/login?returnTo=/orgs");
  const orgs = await listUserOrgs(c.session.userId);
  return (
    <>
      <div className="card">
        {orgs.length === 0 ? <p className="muted">You are not a member of any organization yet.</p> : (
          <TableWrap label="Organizations"><table><thead><tr><th>Name</th><th>Your role</th><th /></tr></thead><tbody>
            {orgs.map((o) => (
              <tr key={o.id}>
                <td>{o.name} <span className="muted small">/{o.slug}</span></td>
                <td>{o.role.replace("_", " ")}</td>
                <td>{c.ctx?.org.id === o.id ? <span className="badge ok">Active</span> : (
                  <form action={selectOrgAction}><input type="hidden" name="orgId" value={o.id} /><button className="secondary" type="submit">Open</button></form>
                )}</td>
              </tr>
            ))}
          </tbody></table></TableWrap>
        )}
      </div>
      <div className="card">
        <h2 style={{ marginTop: 0 }}>Create an organization</h2>
        <ActionForm action={createOrgAction} submit="Create">
          <div className="grid2">
            <label>Name<input type="text" name="name" required maxLength={80} /></label>
            <label>URL slug (optional)<input type="text" name="slug" maxLength={40} pattern="[a-z0-9-]*" /></label>
          </div>
        </ActionForm>
      </div>
    </>
  );
}
