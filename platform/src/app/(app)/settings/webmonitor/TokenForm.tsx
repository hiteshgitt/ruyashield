"use client";
import { useActionState, useState } from "react";
import { usePathname } from "next/navigation";
import type { ActionState } from "../../_lib/action";

/** Creates the WebMonitor token, then shows it once with a copy button and a link that opens WebMonitor's connect dialog. */
export function WebMonitorTokenForm({ action, connectUrl }: { action: (prev: ActionState) => Promise<ActionState>; connectUrl: string }) {
  const [state, formAction, isPending] = useActionState(action, null);
  const [copied, setCopied] = useState(false);
  const path = usePathname();
  const copy = async (s: string) => {
    try {
      await navigator.clipboard.writeText(s);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard blocked: the token stays selectable.
    }
  };
  return (
    <div className="stack">
      {!state?.secret && (
        <form action={formAction}>
          <button type="submit" disabled={isPending}>{isPending ? "Creating…" : "Create token for WebMonitor"}</button>
        </form>
      )}
      {state?.error && (
        <p className="notice bad" role="alert">
          {state.error}{" "}
          {state.stepUp && <a href={`/auth/login?stepUp=1&returnTo=${encodeURIComponent(path)}`}>Re-authenticate</a>}
        </p>
      )}
      {state?.secret && (
        <>
          <p className="notice warn" role="status">{state.ok}</p>
          <p className="notice"><code style={{ userSelect: "all", wordBreak: "break-all" }}>{state.secret}</code></p>
          <div className="row">
            <button type="button" className="secondary" onClick={() => copy(state.secret!)}>{copied ? "Copied" : "Copy token"}</button>
            <a className="button" href={connectUrl} target="_blank" rel="noopener noreferrer">Open WebMonitor to paste it →</a>
          </div>
        </>
      )}
    </div>
  );
}
