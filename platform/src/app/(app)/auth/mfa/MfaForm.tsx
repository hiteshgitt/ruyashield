"use client";
import { useActionState } from "react";
import type { MfaState } from "./actions";

type Props = { action: (prev: MfaState, f: FormData) => Promise<MfaState>; returnTo?: string; submit: string; allowRecovery: boolean };

export function MfaForm({ action, returnTo, submit, allowRecovery }: Props) {
  const [state, formAction, pending] = useActionState(action, null);
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
