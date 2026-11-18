import { Suspense } from "react";
import Link from "next/link";
import { redirect } from "next/navigation";
import { getContext } from "@/server/context";
import { getAccount, soleAdminOrgs } from "@/server/account/account";
import { listUserOrgs } from "@/server/orgs/orgs";
import { ActionForm } from "../_components/ActionForm";
import {
  changePasswordAction, deleteAccountAction, newRecoveryCodesAction, resetAuthenticatorAction,
  selectOrgAction, signOutOtherSessionsAction, signOutSessionAction, updateProfileAction,
} from "../actions";
import { fmt } from "../_lib/page";
import { Loading, PageHeader } from "../_components/Page";
import { MIN_PASSWORD } from "@/server/auth/password";

export default function AccountPage() {
  return (
    <>
      <PageHeader title="Account" lead="Your own sign-in, security and devices. Organization settings are under Administration." />
      <Suspense fallback={<Loading />}><Account /></Suspense>
    </>
  );
}

const ROLE: Record<string, string> = { org_admin: "Org admin", security_lead: "Security lead", analyst: "Analyst", developer: "Developer", approver: "Approver", viewer: "Viewer" };

async function Account() {
  const c = await getContext();
  if (!c) redirect("/auth/signin?returnTo=%2Faccount");
  const s = c.session;
  const [a, orgs, blocking] = await Promise.all([getAccount(s), listUserOrgs(s.userId), soleAdminOrgs(s.userId)]);
  const initials = (a.displayName || a.email).split(/[\s@.]+/).filter(Boolean).slice(0, 2).map((p) => p[0]!.toUpperCase()).join("");
  const others = a.sessions.filter((x) => !x.current).length;

  return (
    <div className="account">
      <section className="card account-hero">
        <span className="account-avatar" aria-hidden="true">{initials || "?"}</span>
        <div className="account-hero-text">
          <h2>{a.displayName}</h2>
          <p className="muted">{a.email}</p>
          <ul className="account-chips">
            <li>{a.method === "google" ? "Signs in with Google" : "Signs in with email and password"}</li>
            <li className={a.mfaEnabled ? "ok" : "warn"}>{a.mfaEnabled ? "Two-step verification on" : "Two-step verification not set up"}</li>
            <li>Member since {fmt(a.createdAt).slice(0, 10)}</li>
          </ul>
        </div>
      </section>

      <div className="account-grid">
        <section className="card account-card" aria-labelledby="acc-profile">
          <h3 id="acc-profile">Profile</h3>
          <p className="muted small">Shown to your team on findings, comments and approvals.</p>
          <ActionForm action={updateProfileAction} submit="Save name">
            <label>Display name<input name="displayName" defaultValue={a.displayName} required maxLength={80} autoComplete="name" /></label>
            <label>Email<input value={a.email} readOnly disabled /></label>
          </ActionForm>
        </section>

        <section className="card account-card" aria-labelledby="acc-password">
          <h3 id="acc-password">Password</h3>
          {a.method === "password" ? (
            <>
              <p className="muted small">Other devices are signed out when you change it.</p>
              <ActionForm action={changePasswordAction} submit="Change password">
                <label>Current password<input name="current" type="password" required autoComplete="current-password" /></label>
                <label>New password<input name="next" type="password" required minLength={MIN_PASSWORD} maxLength={200} autoComplete="new-password" /></label>
                <label>Confirm new password<input name="confirm" type="password" required minLength={MIN_PASSWORD} maxLength={200} autoComplete="new-password" /></label>
              </ActionForm>
            </>
          ) : (
            <p className="muted small">You sign in with Google, so there is no RuyaShield password. Manage your Google password in your Google account.</p>
          )}
        </section>

        <section className="card account-card" aria-labelledby="acc-mfa">
          <h3 id="acc-mfa">Two-step verification</h3>
          <p className="small">
            <span className={`badge ${a.mfaEnabled ? "ok" : "warn"}`}>{a.mfaEnabled ? "On" : "Not set up"}</span>{" "}
            {a.mfaEnabled && <span className="muted">{a.recoveryLeft} recovery code{a.recoveryLeft === 1 ? "" : "s"} left</span>}
          </p>
          {!a.mfaEnabled && <p className="muted small">You set up an authenticator app at your next sign-in.</p>}
          {a.mfaEnabled && <>
          <div className="account-sub">
            <h4>New recovery codes</h4>
            <p className="muted small">Replaces all your recovery codes. They are shown once; keep them somewhere safe.</p>
            <ActionForm action={newRecoveryCodesAction} submit="Show new codes" variant="secondary" className="row inline-form">
              <input name="code" required inputMode="numeric" autoComplete="one-time-code" placeholder="Authenticator code" maxLength={11} aria-label="Authenticator code" />
            </ActionForm>
          </div>
          <div className="account-sub">
            <h4>Moving to a new phone</h4>
            <p className="muted small">Enter a code from your current app (or a recovery code). You are signed out everywhere and set up the authenticator on the new phone at your next sign-in.</p>
            <ActionForm action={resetAuthenticatorAction} submit="Reset authenticator" variant="danger" className="row inline-form">
              <input name="code" required autoComplete="one-time-code" placeholder="Code or recovery code" maxLength={11} aria-label="Authenticator or recovery code" />
            </ActionForm>
          </div>
          </>}
        </section>

        <section className="card account-card" aria-labelledby="acc-sessions">
          <div className="account-card-head">
            <h3 id="acc-sessions">Signed-in devices</h3>
            {others > 0 && <ActionForm action={signOutOtherSessionsAction} submit={`Sign out ${others} other${others === 1 ? "" : "s"}`} variant="secondary" className="row inline-form" />}
          </div>
          <ul className="account-sessions">
            {a.sessions.map((x) => (
              <li key={x.key}>
                <span className={`account-dot${x.current ? " current" : ""}`} aria-hidden="true" />
                <span className="account-session-text">
                  <span className="account-row-title"><b>{x.device}</b>{x.current && <span className="badge ok">This device</span>}</span>
                  <span className="muted small">{x.ip ?? "Unknown address"} · signed in {fmt(x.createdAt)} · active {fmt(x.lastSeenAt)}{x.remembered && <> · kept signed in until {fmt(x.expiresAt)}</>}</span>
                </span>
                {!x.current && (
                  <ActionForm action={signOutSessionAction} submit="Sign out" variant="secondary" className="row inline-form">
                    <input type="hidden" name="key" value={x.key} />
                  </ActionForm>
                )}
              </li>
            ))}
          </ul>
        </section>

        <section className="card account-card" aria-labelledby="acc-orgs">
          <h3 id="acc-orgs">Your organizations</h3>
          {orgs.length === 0 ? <p className="muted small">You are not in an organization yet. <Link href="/orgs">Create or join one</Link>.</p> : (
            <ul className="account-orgs">
              {orgs.map((o) => (
                <li key={o.id}>
                  <span className="org-mark" aria-hidden="true">{o.name.slice(0, 1).toUpperCase()}</span>
                  <span className="account-session-text"><span className="account-row-title"><b>{o.name}</b></span><span className="muted small">{ROLE[o.role] ?? o.role}</span></span>
                  {c.ctx?.org.id === o.id ? <span className="badge ok">Active</span> : (
                    <form action={selectOrgAction}><input type="hidden" name="orgId" value={o.id} /><button type="submit" className="secondary">Switch</button></form>
                  )}
                </li>
              ))}
            </ul>
          )}
          <p className="small"><Link href="/orgs">Manage or create organizations →</Link></p>
          <p className="small"><Link href="/notifications">Notification preferences →</Link></p>
        </section>

        <section className="card account-card account-danger" aria-labelledby="acc-delete">
          <h3 id="acc-delete">Delete account</h3>
          <p className="muted small">You leave every organization, your API tokens stop working and your sign-in details are removed. Audit records keep a placeholder for you. This cannot be undone.</p>
          {blocking.length > 0 ? (
            <p className="notice warn small">You are the only org admin of {blocking.map((o) => o.name).join(", ")}. Make someone else an admin or delete the organization first.</p>
          ) : (
            <ActionForm action={deleteAccountAction} submit="Delete my account" variant="danger">
              <label>Type your email to confirm<input name="confirm" required autoComplete="off" placeholder={a.email} /></label>
              <label>Authenticator code<input name="code" required autoComplete="one-time-code" maxLength={11} /></label>
            </ActionForm>
          )}
        </section>
      </div>
    </div>
  );
}
