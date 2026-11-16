import type { ReactNode } from "react";

/** The sign-in backdrop with one centered card (forgot / reset password). */
export function AuthShell({ children, label }: { children: ReactNode; label: string }) {
  return (
    <section className="signin" aria-label={label}>
      <div className="signin-glow" aria-hidden="true" />
      <div className="signin-grid single wrap">
        <div className="signin-card">
          {/* eslint-disable-next-line @next/next/no-img-element -- static 128 px mark */}
          <img src="/brand/ruyashield-mark-128.png" alt="" width={56} height={56} className="signin-mark" />
          {children}
        </div>
      </div>
    </section>
  );
}
