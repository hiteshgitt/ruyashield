import { Suspense } from "react";
import { getContext } from "@/server/context";
import { safeReturnTo } from "@/server/auth/login";
import { logoutAction } from "../../actions";
import { Loading, PageHeader } from "../../_components/Page";

// Sign in or create an account. RuyaShield accounts come from Google: the first sign-in with a Google account
// creates the RuyaShield account. Google's account chooser is always shown, so any account can be picked.
export default function SignInPage({ searchParams }: PageProps<"/auth/signin">) {
  return (
    <div className="card stack signin-card">
      <Suspense fallback={<Loading />}><SignIn searchParams={searchParams} /></Suspense>
    </div>
  );
}

async function SignIn({ searchParams }: { searchParams: PageProps<"/auth/signin">["searchParams"] }) {
  const sp = await searchParams;
  const returnTo = safeReturnTo(typeof sp.returnTo === "string" ? sp.returnTo : "/");
  const isNew = sp.new === "1";
  const c = await getContext();
  const login = `/auth/login?returnTo=${encodeURIComponent(returnTo)}`;

  if (c) {
    return (
      <>
        <PageHeader title="You are signed in" lead={<>Signed in as <strong>{c.session.email}</strong>.</>} />
        <div className="row">
          <a className="button" href={c.ctx ? "/dashboard" : "/orgs"}>Continue</a>
          <form action={logoutAction}><button type="submit" className="secondary">Sign out to use a different account</button></form>
        </div>
      </>
    );
  }

  return (
    <>
      {sp.signedOut === "1" && <p className="notice ok" role="status">You are signed out.</p>}
      <PageHeader
        title={isNew ? "Create your RuyaShield account" : "Sign in or create an account"}
        lead="RuyaShield uses your Google account. Signing in with a Google account for the first time creates your RuyaShield account."
      />
      <a className="button signin-google" href={login}>Continue with Google</a>
      <ul className="muted small signin-notes">
        <li>Google lets you pick any of your accounts, or add another one, on the next screen.</li>
        <li>New accounts set up an authenticator app (two-step verification) and then create or join an organization.</li>
        <li>New organizations start on the Free plan.</li>
      </ul>
    </>
  );
}
