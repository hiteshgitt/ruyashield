"use client";
import { useActionState, useEffect } from "react";
import type { MfaState } from "./actions";

type Props = { action: (prev: MfaState, f: FormData) => Promise<MfaState>; returnTo?: string; submit: string; allowRecovery: boolean };

export function MfaForm({ action, returnTo, submit, allowRecovery }: Props) {
  const [state, formAction, pending] = useActionState(action, null);
  // After a plain verification, continue automatically. A new enrollment waits until the codes are saved.
  const next = state?.done && !state.done.recoveryCodes ? state.done.returnTo : null;
  useEffect(() => { if (next) window.location.assign(next); }, [next]);

  if (state?.done?.recoveryCodes) {
    return (
      <div className="stack">
        <p className="notice ok" role="status">Your authenticator is set up.</p>
        <p>
          Save these recovery codes somewhere safe, such as a password manager. Each one signs you in once if you lose
          your phone. <strong>They are shown only now.</strong>
        </p>
        <pre style={{ userSelect: "all", columns: 2, padding: "12px 16px" }}>{state.done.recoveryCodes.join("\n")}</pre>
        <div><a className="button" href={state.done.returnTo}>I have saved them, continue</a></div>
      </div>
    );
  }
  if (state?.done) {
    return (
      <div className="stack">
        {state.done.usedRecovery && <p className="notice warn">You used a recovery code. It cannot be used again.</p>}
        <p className="notice ok" role="status">Verified. <a href={state.done.returnTo}>Continue</a></p>
      </div>
    );
  }

  return (
    <form action={formAction} className="stack">
      {returnTo && <input type="hidden" name="returnTo" value={returnTo} />}
      <label>
        {allowRecovery ? "6-digit code from your authenticator app, or a recovery code" : "6-digit code from your authenticator app"}
        <input
          name="code" required autoFocus autoComplete="one-time-code" spellCheck={false}
          inputMode={allowRecovery ? "text" : "numeric"} maxLength={allowRecovery ? 11 : 6}
          pattern={allowRecovery ? "[0-9]{6}|[A-Za-z2-7]{5}-?[A-Za-z2-7]{5}" : "[0-9]{6}"}
          style={{ fontSize: "1.25rem", letterSpacing: "0.2em", maxWidth: 220 }}
        />
      </label>
      <div><button type="submit" disabled={pending}>{pending ? "Checking…" : submit}</button></div>
      {state?.error && (
        <p className="notice bad" role="alert">
          {state.error} {state.expired && <a href="/auth/login">Sign in again</a>}
        </p>
      )}
    </form>
  );
}
