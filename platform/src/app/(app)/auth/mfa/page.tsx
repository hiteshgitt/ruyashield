import { Suspense } from "react";
import { cookies } from "next/headers";
import { connection } from "next/server";
import { redirect } from "next/navigation";
import { getSession } from "@/server/context";
import { challengeFor, PENDING_COOKIE, pendingReveal } from "@/server/auth/mfa";
import { safeReturnTo } from "@/server/auth/login";
import { Loading, PageHeader } from "../../_components/Page";
import { MfaForm } from "./MfaForm";
import { confirmRecoverySaved, verifyLoginCode, verifyStepUpCode } from "./actions";

export default function MfaPage({ searchParams }: PageProps<"/auth/mfa">) {
  return (
    <div className="card" style={{ maxWidth: 520 }}>
      <Suspense fallback={<Loading />}>
        <Body searchParams={searchParams} />
      </Suspense>
    </div>
  );
}

async function Body({ searchParams }: { searchParams: PageProps<"/auth/mfa">["searchParams"] }) {
  await connection();
  const sp = await searchParams;

  if (sp.stepUp === "1") {
    const session = await getSession();
    if (!session) return <Expired />;
    const returnTo = safeReturnTo(typeof sp.returnTo === "string" ? sp.returnTo : "/");
    return (
      <>
        <PageHeader title="Confirm it’s you" lead="This action needs a fresh code from your authenticator app." />
        <MfaForm action={verifyStepUpCode} returnTo={returnTo} submit="Confirm" allowRecovery />
      </>
    );
  }

  const challenge = await challengeFor((await cookies()).get(PENDING_COOKIE)?.value);
  if (!challenge) {
    const session = await getSession();
    if (!session) return <Expired />;
    const reveal = await pendingReveal(session.userId);
    // Already signed in and nothing left to show: this page has no job.
    if (!reveal) redirect("/");
    return (
      <>
        <PageHeader title="Save your recovery codes" lead="Two-step verification is on." />
        <div className="stack">
          <p>
            Each code signs you in once if you lose your phone. Keep them somewhere safe, such as a password manager.{" "}
            <strong>They are shown only now.</strong>
          </p>
          <pre style={{ userSelect: "all", columns: 2, padding: "12px 16px" }}>{reveal.codes.join("\n")}</pre>
          <form action={confirmRecoverySaved}><button type="submit">I have saved them, continue</button></form>
        </div>
      </>
    );
  }

  if (challenge.kind === "verify") {
    return (
      <>
        <PageHeader title="Two-step verification" lead={<>Signed in with Google as <strong>{challenge.email}</strong>. Enter the code from your authenticator app.</>} />
        <MfaForm action={verifyLoginCode} submit="Verify" allowRecovery />
      </>
    );
  }

  return (
    <>
      <PageHeader title="Set up two-step verification" lead={<>RuyaShield needs a code from an authenticator app at every sign-in for <strong>{challenge.email}</strong>.</>} />
      <ol className="stack" style={{ paddingLeft: "1.2rem" }}>
        <li>Install an authenticator app, for example Google Authenticator, Microsoft Authenticator or 1Password.</li>
        <li>
          Scan this QR code with the app.
          <div style={{ width: 200, height: 200, margin: "12px 0", background: "#fff", padding: 8, borderRadius: 8 }}
            dangerouslySetInnerHTML={{ __html: challenge.qrSvg }} />
          Can’t scan? Enter this key instead: <code style={{ userSelect: "all", wordBreak: "break-all" }}>{challenge.secret.match(/.{1,4}/g)?.join(" ")}</code>
        </li>
        <li>Enter the 6-digit code the app shows.</li>
      </ol>
      <MfaForm action={verifyLoginCode} submit="Turn on and sign in" allowRecovery={false} />
    </>
  );
}

function Expired() {
  return (
    <>
      <PageHeader title="Sign-in expired" />
      <p className="notice warn">This sign-in step has expired or was opened in a different browser.</p>
      <p><a href="/auth/login">Sign in again</a></p>
    </>
  );
}
