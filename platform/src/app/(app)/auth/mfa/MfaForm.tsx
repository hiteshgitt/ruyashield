"use client";
import { useActionState } from "react";
import type { MfaState } from "./actions";

type Props = {
  action: (prev: MfaState, f: FormData) => Promise<MfaState>; returnTo?: string; submit: string; allowRecovery: boolean;
  /** Sign-in only: offer "Keep me signed in on this device". */
  offerRemember?: boolean;
};

export function MfaForm({ action, returnTo, submit, allowRecovery, offerRemember }: Props) {
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
      {offerRemember && (
        <div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontWeight: 400 }}>
            <input type="checkbox" name="remember" style={{ width: "auto", margin: 0 }} />
            Keep me signed in on this device for 30 days
          </label>
          <p className="muted" style={{ fontSize: "0.85rem", margin: "4px 0 0" }}>
            Don’t tick this on a shared computer. Sensitive changes still ask for a fresh code.
          </p>
        </div>
      )}
      <div><button type="submit" disabled={pending}>{pending ? "Checking…" : submit}</button></div>
      {state?.error && (
        <p className="notice bad" role="alert">
          {state.error} {state.expired && <a href="/auth/login">Sign in again</a>}
        </p>
      )}
    </form>
  );
}
