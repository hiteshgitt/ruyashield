import type { Coverage as Cov } from "@/server/db/schema";

/**
 * "N of M checks ok" with a thin bar drawn from the same numbers (aria-hidden; the text carries the information).
 * Anything short of every planned check succeeding gets the warning tone, so partial coverage never looks complete.
 */
export function Coverage({ c }: { c: Cov | null }) {
  if (!c) return <span className="muted">—</span>;
  const full = c.complete && c.ok === c.planned;
  const pct = c.planned ? Math.round((c.ok / c.planned) * 100) : 0;
  return (
    <span className={`cov ${full ? "ok" : "warn"}`}>
      <span className="cov-bar" aria-hidden="true"><span style={{ width: `${pct}%` }} /></span>
      <span>{c.ok}/{c.planned} checks ok{!full && <span className="muted"> · partial</span>}</span>
    </span>
  );
}
