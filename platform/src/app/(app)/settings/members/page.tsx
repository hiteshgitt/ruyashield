import { Suspense } from "react";
import { grantFor, MFA_REQUIRED_ROLES } from "@/server/policy/matrix";
import { ASSIGNABLE_ROLES, listClientGroups, listInvites, listMembers } from "@/server/orgs/orgs";
import { ActionForm } from "../../_components/ActionForm";
import { changeRoleAction, createClientGroupAction, createInviteAction, removeMemberAction, revokeInviteAction } from "../../actions";
import { fmt, pageOrg } from "../../_lib/page";
import { Empty, Loading, PageHeader, SectionHead } from "../../_components/Page";
import { TableWrap } from "../../_components/TableWrap";
import { StatCard } from "../../_components/Charts";

const label = (r: string) => r.replace("_", " ");
const needsMfa = (r: string) => (MFA_REQUIRED_ROLES as ReadonlySet<string>).has(r);

/** Plain-English summary of each role, taken from the permission matrix (src/server/policy/matrix.ts). */
const ROLE_GUIDE: Record<(typeof ASSIGNABLE_ROLES)[number], { does: string; cannot: string }> = {
  org_admin: { does: "Everything: members, org settings, assets, assessments, triage and accepted risks.", cannot: "Cannot approve a change they requested themselves." },
  security_lead: { does: "Runs assessments, triages findings, accepts risks and approves fixes.", cannot: "Cannot manage members or org settings." },
  analyst: { does: "Runs assessments and triages findings for the assets they are allowed to see.", cannot: "Cannot accept risks or approve fixes." },
  developer: { does: "Sees findings, comments, prepares fixes and asks for a re-test.", cannot: "Cannot launch assessments or triage." },
  approver: { does: "Reviews and approves or rejects proposed fixes, and comments.", cannot: "Cannot change findings or run assessments." },
  viewer: { does: "Read-only access to findings, fix proof and reports.", cannot: "Cannot change anything." },
};

export default function MembersPage() {
  return (
    <>
      <PageHeader title="Members" />
      <Suspense fallback={<Loading />}><Members /></Suspense>
    </>
  );
}

async function Members() {
  const c = await pageOrg("/settings/members");
  if (grantFor(c.principal.role, "members.manage") === "N") return <p className="notice warn">Only org admins can manage members.</p>;
  const [members, invites, groups] = await Promise.all([listMembers(c), listInvites(c), listClientGroups(c)]);
  const groupName = new Map(groups.map((g) => [g.id, g.name]));
  const byRole = new Map<string, number>();
  for (const m of members) byRole.set(m.role, (byRole.get(m.role) ?? 0) + 1);
  const admins = byRole.get("org_admin") ?? 0;
  const mfa = members.filter((m) => needsMfa(m.role)).length;
  const restricted = members.filter((m) => m.restricted).length;
  return (
    <>
      <div className="stats">
        <StatCard icon="members" label="Members" value={members.length} sub={<>{admins} org admin{admins === 1 ? "" : "s"}</>} />
        <StatCard icon="shield" tone={mfa ? "warn" : "ok"} label="Must use MFA" value={mfa} sub="Admins, security leads and approvers" />
        <StatCard icon="clock" tone={invites.length ? "warn" : "ok"} label="Pending invitations" value={invites.length} sub="Single-use links, valid 7 days" />
        <StatCard icon="org" label="Client groups" value={groups.length} sub={<>{restricted} member{restricted === 1 ? "" : "s"} restricted to groups</>} />
      </div>
      <p className="muted small">Role changes and removals need a fresh sign-in.</p>

      <div className="split">
        <div className="split-main">
          <TableWrap className="card">
            <table className="member-table"><thead><tr><th>Member</th><th>Role</th><th>Joined</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
              {members.map((m) => (
                <tr key={m.userId}>
                  <td>
                    <div className="member">
                      <span className="avatar" aria-hidden="true">{(m.name || m.email).slice(0, 1).toUpperCase()}</span>
                      <div className="member-text">
                        <span className="member-name">{m.name}{m.userId === c.principal.userId && <span className="chip">you</span>}</span>
                        <span className="muted small mono member-email">{m.email}</span>
                        {(needsMfa(m.role) || m.restricted) && (
                          <span className="badge-row member-tags">
                            {needsMfa(m.role) && <span className="badge warn">MFA required</span>}
                            {m.restricted && <span className="badge warn">restricted to client groups</span>}
                            {m.clientGroupIds.map((id) => <span key={id} className="chip">{groupName.get(id) ?? "unknown group"}</span>)}
                          </span>
                        )}
                      </div>
                    </div>
                  </td>
                  <td>
                    {m.userId === c.principal.userId ? <span className="role-tag">{label(m.role)}</span> : (
                      <ActionForm key={m.role} action={changeRoleAction} submit="Change" variant="secondary" className="row inline-form">
                        <input type="hidden" name="userId" value={m.userId} />
                        <select name="role" defaultValue={m.role} aria-label={`Role for ${m.email}`}>{ASSIGNABLE_ROLES.map((r) => <option key={r} value={r}>{label(r)}</option>)}</select>
                      </ActionForm>
                    )}
                  </td>
                  <td className="small nowrap">{fmt(m.joinedAt)}</td>
                  <td>{m.userId !== c.principal.userId && (
                    <ActionForm action={removeMemberAction} submit="Remove" variant="danger" className="row inline-form">
                      <input type="hidden" name="userId" value={m.userId} />
                    </ActionForm>
                  )}</td>
                </tr>
              ))}
            </tbody></table>
          </TableWrap>

          <SectionHead title="Invitations"><span className="muted small">Pending until accepted or expired</span></SectionHead>
          {invites.length === 0 ? <Empty>No pending invitations.</Empty> : (
            <TableWrap className="card">
              <table><thead><tr><th>Email</th><th>Role</th><th>Expires</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>
                {invites.map((i) => (
                  <tr key={i.id}>
                    <td className="mono small">{i.email}</td><td><span className="role-tag">{label(i.role)}</span></td><td className="small nowrap">{fmt(i.expiresAt)}</td>
                    <td><ActionForm action={revokeInviteAction} submit="Revoke" variant="danger" className="row inline-form"><input type="hidden" name="inviteId" value={i.id} /></ActionForm></td>
                  </tr>
                ))}
              </tbody></table>
            </TableWrap>
          )}

          <section className="card panel" aria-labelledby="roles-h">
            <h3 id="roles-h">What each role can do</h3>
            <p className="muted small">Give people the smallest role that lets them do their job. Any member can also be limited to specific client groups.</p>
            <ul className="role-cards">
              {ASSIGNABLE_ROLES.map((r) => (
                <li key={r} className={`role-card role-${r}`}>
                  <span className="role-card-head">
                    <span className="role-tag">{label(r)}</span>
                    <span className="role-card-n">{byRole.get(r) ?? 0}<span className="sr-only"> members</span></span>
                  </span>
                  <span className="role-card-does">{ROLE_GUIDE[r].does}</span>
                  <span className="role-card-not">{ROLE_GUIDE[r].cannot}</span>
                  {needsMfa(r) && <span className="badge warn">MFA required</span>}
                </li>
              ))}
            </ul>
          </section>
        </div>

        <aside className="split-side stack">
          <div className="card">
            <h2>Invite a member</h2>
            <ActionForm action={createInviteAction} submit="Send invitation">
              <label>Email<input type="email" name="email" required /></label>
              <label>Role<select name="role" defaultValue="analyst">{ASSIGNABLE_ROLES.map((r) => <option key={r} value={r}>{label(r)}{needsMfa(r) ? " (MFA required)" : ""}</option>)}</select></label>
              {groups.length > 0 && (
                <fieldset className="checks">
                  <legend>Restrict to client groups (optional)</legend>
                  {groups.map((g) => (
                    <label key={g.id} className="check-opt">
                      <input type="checkbox" name="clientGroupIds" value={g.id} />
                      <span className="check-text"><span className="check-title">{g.name}</span></span>
                    </label>
                  ))}
                </fieldset>
              )}
              <p className="muted small">The link is single-use, expires in 7 days and must be accepted by this email address.</p>
            </ActionForm>
          </div>

          <div className="card">
            <h2>Client groups</h2>
            <p className="muted small">Client groups let agencies restrict members to specific clients&apos; assets.</p>
            {groups.length === 0 ? <Empty>No client groups yet.</Empty>
              : <ul className="meta-chips group-chips" aria-label="Client groups">{groups.map((g) => <li key={g.id}>{g.name}</li>)}</ul>}
            <ActionForm action={createClientGroupAction} submit="Add group" variant="secondary" className="row inline-form grow">
              <input type="text" name="name" required placeholder="Client name" aria-label="Client group name" />
            </ActionForm>
          </div>
        </aside>
      </div>
    </>
  );
}
