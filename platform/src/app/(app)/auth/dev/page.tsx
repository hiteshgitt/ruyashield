import { Suspense } from "react";
import { connection } from "next/server";
import { providerKind } from "@/server/auth/login";
import { Loading, PageHeader } from "../../_components/Page";

export default function DevLoginPage({ searchParams }: PageProps<"/auth/dev">) {
  return (
    <div className="card" style={{ maxWidth: 440 }}>
      <PageHeader title="Development sign-in" />
      <p className="notice warn">Local development identity provider. It is refused in production; real deployments use OIDC.</p>
      <Suspense fallback={<Loading />}>
        <DevForm searchParams={searchParams} />
      </Suspense>
    </div>
  );
}

async function DevForm({ searchParams }: { searchParams: PageProps<"/auth/dev">["searchParams"] }) {
  await connection(); // provider is a runtime setting; never decide it at build time
  let dev = false;
  try { dev = providerKind() === "dev"; } catch { /* dev provider refused in production: fail closed */ }
  if (!dev) return <p className="notice bad">Development sign-in is disabled in this environment.</p>;
  const sp = await searchParams;
  const state = typeof sp.state === "string" ? sp.state : "";
  if (!state) return <p className="notice bad">Missing sign-in state. <a href="/auth/login">Start again</a>.</p>;
  return (
    <form method="post" action="/auth/callback" className="stack">
      <input type="hidden" name="state" value={state} />
      <label>Email<input type="email" name="email" required autoComplete="email" defaultValue="admin@example.test" /></label>
      <label>Display name<input type="text" name="name" defaultValue="Dev Admin" /></label>
      <label className="check"><input type="checkbox" name="mfa" defaultChecked /> Signed in with MFA (simulated for development)</label>
      <div><button type="submit">Sign in</button></div>
    </form>
  );
}
