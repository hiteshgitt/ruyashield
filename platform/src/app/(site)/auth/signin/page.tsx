import Link from "next/link";
import { Suspense } from "react";
import { getContext } from "@/server/context";
import { safeReturnTo } from "@/server/auth/login";
import { logoutAction } from "@/app/(app)/actions";

// Sign in or create an account. RuyaShield accounts come from Google: the first sign-in with a Google account
// creates the RuyaShield account. Google's account chooser is always shown, so any account can be picked.
export default function SignInPage({ searchParams }: PageProps<"/auth/signin">) {
  return (
    <section className="signin" aria-labelledby="signin-title">
      <div className="signin-glow" aria-hidden="true" />
      <div className="signin-grid wrap">
        <div className="signin-pitch">
          <span className="eyebrow">Website security for agencies, MSPs and teams</span>
          <p className="display signin-headline">Find the real risk. <em>Prove the fix.</em></p>
          <p className="lead">Scan the sites you own, get every finding explained with evidence, and only call a fix done after a re-test passes.</p>
          <ul className="signin-points">
            <li><span className="signin-point-icon" aria-hidden="true">01</span><span><b>Ownership-verified scanning</b>DNS or file proof before any check runs.</span></li>
            <li><span className="signin-point-icon" aria-hidden="true">02</span><span><b>Zealot explains each finding</b>Plain answers with cited evidence.</span></li>
            <li><span className="signin-point-icon" aria-hidden="true">03</span><span><b>FixProof re-tests every fix</b>Tamper-evident records you can share.</span></li>
          </ul>
          <Link className="signin-wm" href="/#webmonitor">
            <span className="signin-wm-dot" aria-hidden="true" />
            <span><b>Use WebMonitor?</b> Connect it after signing in to see findings next to uptime.</span>
            <span aria-hidden="true">→</span>
          </Link>
        </div>
        <div className="signin-card">
          <Suspense fallback={<p className="signin-muted">Loading…</p>}><Card searchParams={searchParams} /></Suspense>
        </div>
      </div>
    </section>
  );
}

const GoogleMark = () => (
  <svg viewBox="0 0 48 48" width="20" height="20" aria-hidden="true">
    <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
    <path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
    <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z" />
    <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z" />
  </svg>
);

async function Card({ searchParams }: { searchParams: PageProps<"/auth/signin">["searchParams"] }) {
  const sp = await searchParams;
  const returnTo = safeReturnTo(typeof sp.returnTo === "string" ? sp.returnTo : "/");
  const isNew = sp.new === "1";
  const c = await getContext();
  const login = `/auth/login?returnTo=${encodeURIComponent(returnTo)}`;

  if (c) {
    return (
      <>
        {/* eslint-disable-next-line @next/next/no-img-element -- static 128 px mark */}
        <img src="/brand/ruyashield-mark-128.png" alt="" width={56} height={56} className="signin-mark" />
        <h1 id="signin-title" className="signin-title">You are signed in</h1>
        <p className="signin-muted">Signed in as <b className="signin-strong">{c.session.email}</b>.</p>
        <div className="signin-actions">
          <a className="btn btn-primary" href={c.ctx ? "/dashboard" : "/orgs"}>Continue <span aria-hidden="true">→</span></a>
          <form action={logoutAction}><button type="submit" className="btn btn-ghost">Use a different account</button></form>
        </div>
      </>
    );
  }

  return (
    <>
      {sp.signedOut === "1" && <p className="signin-status" role="status">You are signed out.</p>}
      {/* eslint-disable-next-line @next/next/no-img-element -- static 128 px mark */}
      <img src="/brand/ruyashield-mark-128.png" alt="" width={56} height={56} className="signin-mark" />
      <h1 id="signin-title" className="signin-title">{isNew ? "Create your account" : "Welcome to RuyaShield"}</h1>
      <p className="signin-muted">Sign in or create an account with Google. Your first sign-in creates your RuyaShield account.</p>
      <a className="signin-google" href={login}><GoogleMark /> Continue with Google</a>
      <p className="signin-hint">You can choose any Google account, or add another one, on the next screen.</p>
      <ol className="signin-steps">
        <li><span>1</span>Sign in with Google</li>
        <li><span>2</span>Set up your authenticator app</li>
        <li><span>3</span>Create or join an organization</li>
      </ol>
      <p className="signin-foot">New organizations start on the <b className="signin-strong">Free</b> plan. Pro adds reports and downloads.</p>
    </>
  );
}
