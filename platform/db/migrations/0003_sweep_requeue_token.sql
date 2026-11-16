-- Lease-expiry requeue no longer copies an outbox payload in SQL: the copied job token could
-- already be scrubbed by the worker. sweepAssessments() now enqueues the retry with a freshly
-- signed token (if that fails the run stays queued and the window-expiry rule cancels it).
CREATE OR REPLACE FUNCTION sweep_assessments()
RETURNS TABLE (org_id uuid, assessment_id uuid, from_status text, to_status text, reason text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
#variable_conflict use_column
DECLARE r record;
BEGIN
  FOR r IN
    SELECT a.id, a.org_id, a.status, a.attempts, a.lease_until, (o.kill_scanning OR s.kill_scanning) AS killed,
           sv.window_end
    FROM assessments a
    JOIN orgs o ON o.id = a.org_id
    JOIN assets s ON s.id = a.asset_id
    JOIN scope_versions sv ON sv.id = a.scope_version_id
    WHERE a.status IN ('queued','running','cancelling')
    FOR UPDATE OF a SKIP LOCKED
  LOOP
    org_id := r.org_id; assessment_id := r.id; from_status := r.status;
    IF r.killed AND r.status = 'queued' THEN
      UPDATE assessments SET status = 'cancelled', reason = 'kill_switch_engaged', finished_at = now() WHERE id = r.id;
      to_status := 'cancelled'; reason := 'kill_switch_engaged'; RETURN NEXT;
    ELSIF r.killed AND r.status = 'running' THEN
      UPDATE assessments SET status = 'cancelling', reason = 'kill_switch_engaged', cancel_requested_at = now() WHERE id = r.id;
      to_status := 'cancelling'; reason := 'kill_switch_engaged'; RETURN NEXT;
    ELSIF r.status = 'queued' AND r.window_end < now() THEN
      UPDATE assessments SET status = 'cancelled', reason = 'window_expired', finished_at = now() WHERE id = r.id;
      to_status := 'cancelled'; reason := 'window_expired'; RETURN NEXT;
    ELSIF r.status = 'running' AND r.lease_until < now() THEN
      IF r.attempts < 3 AND r.window_end > now() THEN
        UPDATE assessments SET status = 'queued', lease_until = NULL, reason = 'worker_lease_expired' WHERE id = r.id;
        to_status := 'queued'; reason := 'worker_lease_expired'; RETURN NEXT;
      ELSE
        UPDATE assessments SET status = 'timed_out', reason = 'worker_lease_expired', finished_at = now(), lease_until = NULL WHERE id = r.id;
        to_status := 'timed_out'; reason := 'worker_lease_expired'; RETURN NEXT;
      END IF;
    ELSIF r.status = 'cancelling' AND (r.lease_until IS NULL OR r.lease_until < now()) THEN
      UPDATE assessments SET status = 'cancelled', finished_at = now(), lease_until = NULL WHERE id = r.id;
      to_status := 'cancelled'; reason := 'cancel_completed_by_sweep'; RETURN NEXT;
    END IF;
  END LOOP;
END $$;

REVOKE ALL ON FUNCTION sweep_assessments FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sweep_assessments TO ruya_app;
