import Link from "next/link";
import { MIN_PASSWORD } from "@/server/auth/password";
import { resetPasswordAction } from "../actions";
import { AuthShell } from "../_shell";

export default async function ResetPage({ searchParams }: PageProps<"/auth/reset">) {
  const sp = await searchParams;
  const token = typeof sp.token === "string" ? sp.token.slice(0, 200) : "";
  const msg = typeof sp.msg === "string" ? sp.msg.slice(0, 200) : "";
  return (
    <AuthShell label="Choose a new password">
      <h1 className="signin-title">Choose a new password</h1>
      {!token ? (
        <p className="signin-error" role="alert">This link is incomplete. <Link href="/auth/forgot">Ask for a new one</Link>.</p>
      ) : (
        <>
          {sp.error && <p className="signin-error" role="alert">{msg} {sp.error === "link_expired" && <Link href="/auth/forgot">Ask for a new link</Link>}</p>}
          <form action={resetPasswordAction} className="signin-form">
            <input type="hidden" name="token" value={token} />
            <label>New password<input name="password" type="password" required minLength={MIN_PASSWORD} maxLength={200} autoComplete="new-password" /></label>
            <label>Confirm new password<input name="confirm" type="password" required minLength={MIN_PASSWORD} maxLength={200} autoComplete="new-password" /></label>
            <p className="signin-hint left">At least {MIN_PASSWORD} characters. Every other signed-in device is signed out.</p>
            <button type="submit" className="btn btn-primary signin-submit">Save new password</button>
          </form>
        </>
      )}
      <p className="signin-switch"><Link href="/auth/signin">← Back to sign in</Link></p>
    </AuthShell>
  );
}
