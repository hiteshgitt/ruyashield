import { Suspense } from "react";
import { getSession } from "@/server/context";
import { peekInvite } from "@/server/orgs/orgs";
import { ActionForm } from "../../_components/ActionForm";
import { acceptInviteAction } from "../../actions";
import { Loading, PageHeader } from "../../_components/Page";

const STATE_TEXT: Record<string, string> = {
  used: "This invitation has already been used.", revoked: "This invitation was revoked.", expired: "This invitation has expired. Ask for a new one.",
};

export default function InvitePage({ params }: PageProps<"/invite/[token]">) {
  return (
    <>
      <PageHeader title="Invitation" />
      <Suspense fallback={<Loading />}><Invite params={params} /></Suspense>
    </>
  );
}

async function Invite({ params }: { params: PageProps<"/invite/[token]">["params"] }) {
  const { token } = await params;
  const inv = token.length <= 200 ? await peekInvite(token) : null;
  if (!inv) return <p className="notice bad">This invitation link is not valid.</p>;
  if (inv.state !== "valid") return <p className="notice warn">{STATE_TEXT[inv.state]}</p>;
  const s = await getSession();
  return (
    <div className="card stack">
      <p>You have been invited to join <strong>{inv.orgName}</strong> as <strong>{inv.role.replace("_", " ")}</strong>.</p>
      <p className="muted small">The invitation is for {inv.email}; you must be signed in with that email to accept.</p>
      {s ? (
        <ActionForm action={acceptInviteAction} submit="Accept invitation">
          <input type="hidden" name="token" value={token} />
        </ActionForm>
      ) : (
        <p><a className="button" href={`/auth/login?returnTo=${encodeURIComponent(`/invite/${token}`)}`}>Sign in to accept</a></p>
      )}
    </div>
  );
}
