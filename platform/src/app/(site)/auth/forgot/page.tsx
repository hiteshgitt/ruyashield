import { Suspense } from "react";
import Link from "next/link";
import { forgotPasswordAction } from "../actions";
import { AuthShell } from "../_shell";

export default function ForgotPage({ searchParams }: PageProps<"/auth/forgot">) {
  return <Suspense fallback={null}><ForgotPageBody searchParams={searchParams} /></Suspense>;
}

async function ForgotPageBody({ searchParams }: { searchParams: PageProps<"/auth/forgot">["searchParams"] }) {
  const sp = await searchParams;
  const email = typeof sp.email === "string" ? sp.email.slice(0, 200) : "";
  const msg = typeof sp.msg === "string" ? sp.msg.slice(0, 200) : "";
  return (
    <AuthShell label="Reset your password">
      <h1 className="signin-title">Reset your password</h1>
      {sp.sent === "1" ? (
        <>
          <p className="signin-status" role="status">If <b>{email || "that address"}</b> has a RuyaShield password account, a reset link is on its way. It works for 30 minutes.</p>
          <p className="signin-muted">Signed up with Google? Use <Link href="/auth/signin">Continue with Google</Link> instead; there is no password to reset.</p>
        </>
      ) : (
        <>
          <p className="signin-muted">Enter the email you sign in with. We send a link to choose a new password; signing in still needs your authenticator code.</p>
          {sp.error && <p className="signin-error" role="alert">{msg || "Something went wrong. Please try again."}</p>}
          <form action={forgotPasswordAction} className="signin-form">
            <label>Email<input name="email" type="email" required maxLength={200} autoComplete="email" defaultValue={email} /></label>
            <button type="submit" className="btn btn-primary signin-submit">Send reset link</button>
          </form>
        </>
      )}
      <p className="signin-switch"><Link href="/auth/signin">← Back to sign in</Link></p>
    </AuthShell>
  );
}
