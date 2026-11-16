"use client";
import { useActionState } from "react";
import { usePathname } from "next/navigation";
import type { ActionState } from "../_lib/action";

type Props = {
  action: (prev: ActionState, f: FormData) => Promise<ActionState>;
  submit: string;
  pending?: string;
  variant?: "primary" | "secondary" | "danger";
  className?: string;
  children?: React.ReactNode;
};

export function ActionForm({ action, submit, pending, variant = "primary", className, children }: Props) {
  const [state, formAction, isPending] = useActionState(action, null);
  const path = usePathname();
  return (
    <form action={formAction} className={className ?? "stack"}>
      {children}
      <div><button type="submit" disabled={isPending} className={variant === "primary" ? undefined : variant}>{isPending ? (pending ?? "Working…") : submit}</button></div>
      {state?.error && (
        <p className="notice bad" role="alert">
          {state.error}{" "}
          {state.stepUp && <a href={`/auth/login?stepUp=1&returnTo=${encodeURIComponent(path)}`}>Re-authenticate</a>}
        </p>
      )}
      {state?.ok && <p className={`notice ${state.tone ?? "ok"}`} role="status">{state.ok}</p>}
      {state?.secret && <p className="notice warn"><code style={{ userSelect: "all", wordBreak: "break-all" }}>{state.secret}</code></p>}
    </form>
  );
}
