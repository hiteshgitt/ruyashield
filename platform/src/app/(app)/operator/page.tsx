import { Suspense } from "react";
import { redirect } from "next/navigation";
import { getContext } from "@/server/context";
import { BREAK_GLASS_MAX_MINUTES, isOperator, listBreakGlass } from "@/server/operator/breakglass";
import { ActionForm } from "../_components/ActionForm";
import { endBreakGlassAction, startBreakGlassAction } from "../actions";
import { fmt } from "../_lib/page";
import { Loading, PageHeader } from "../_components/Page";
import { TableWrap } from "../_components/TableWrap";

export default function OperatorPage() {
  return (
    <>
      <PageHeader title="Operator support access" lead={<>Time-boxed, read-only access to one organization for support. It needs a fresh MFA sign-in and a reason, is written to that organization&apos;s audit log and is announced to its admins.</>} />
      <Suspense fallback={<Loading />}><Operator /></Suspense>
    </>
  );
}

async function Operator() {
  const c = await getContext();
  if (!c) redirect("/auth/login?returnTo=%2Foperator");
  if (!isOperator(c.session.email)) return <p className="notice warn">Not available.</p>;
  const bg = c.ctx?.principal.breakGlassId ? c.ctx : null;
  const history = bg ? await listBreakGlass(c.session, bg.org.id) : [];
  return (
    <div className="stack">
      {bg ? (
        <div className="card stack">
          <h2 style={{ margin: 0 }}>Active: {bg.org.name}</h2>
          <ActionForm action={endBreakGlassAction} submit="End access" variant="danger" className="row">
            <input type="hidden" name="orgId" value={bg.org.id} />
          </ActionForm>
          <TableWrap>
            <table>
              <thead><tr><th>Started</th><th>Expires</th><th>Ended</th><th>Reason</th></tr></thead>
              <tbody>{history.map((h) => (
                <tr key={h.id}><td>{fmt(h.startedAt)}</td><td>{fmt(h.expiresAt)}</td><td>{fmt(h.endedAt)}</td><td>{h.reason}</td></tr>
              ))}</tbody>
            </table>
          </TableWrap>
        </div>
      ) : (
        <div className="card stack">
          <h2 style={{ margin: 0 }}>Start support access</h2>
          <ActionForm action={startBreakGlassAction} submit="Start read-only access" variant="danger">
            <label>Organization slug <input type="text" name="orgSlug" required maxLength={80} /></label>
            <label>Reason (ticket reference) <input type="text" name="reason" required minLength={10} maxLength={500} /></label>
            <label>Minutes <input type="number" name="minutes" required min={5} max={BREAK_GLASS_MAX_MINUTES} defaultValue={30} /></label>
          </ActionForm>
        </div>
      )}
    </div>
  );
}
