const TONE: Record<string, string> = {
  verified: "ok", passed: "ok", unverified: "warn", pending: "warn", checking: "warn", lapsed: "bad",
  failed: "bad", error: "bad", revoked: "bad", expired: "",
  queued: "warn", running: "warn", cancelling: "warn", cancelled: "", completed: "ok", completed_with_errors: "warn",
  timed_out: "bad", rejected: "bad", ok: "ok", timeout: "bad", skipped: "",
  open: "bad", resolved: "ok", accepted_risk: "", false_positive: "",
  new: "bad", triaged: "warn", confirmed: "bad", in_remediation: "warn", fix_pending_verification: "warn",
  resolved_verified: "ok", reopened: "bad", stale: "", likely: "warn", suspected: "", unknown: "",
  inconclusive: "warn", unavailable: "bad", partially_verified: "warn", not_run: "", superseded: "",
  critical: "bad", high: "bad", medium: "warn", low: "", info: "",
};

export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge ${TONE[status] ?? ""}`}>{status.replace(/_/g, " ")}</span>;
}
