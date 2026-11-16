import { Suspense } from "react";
import { messageFor } from "../../_lib/messages";
import { PageHeader } from "../../_components/Page";

export default function AuthErrorPage({ searchParams }: PageProps<"/auth/error">) {
  return (
    <div className="card" style={{ maxWidth: 480 }}>
      <PageHeader title="Sign-in problem" />
      <Suspense fallback={null}><Message searchParams={searchParams} /></Suspense>
      <p><a href="/auth/signin">Try signing in again</a></p>
    </div>
  );
}

async function Message({ searchParams }: { searchParams: PageProps<"/auth/error">["searchParams"] }) {
  const code = (await searchParams).code;
  return <p className="notice bad">{messageFor(typeof code === "string" ? code.slice(0, 64) : "login_failed")}</p>;
}
