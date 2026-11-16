-- P5 follow-up: the sandbox lease sweep needs to find running runs across tenants (same pattern as 0005).
CREATE OR REPLACE FUNCTION stuck_sandbox_runs(before timestamptz)
RETURNS TABLE (id uuid, org_id uuid) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, org_id FROM sandbox_runs WHERE status = 'running' AND started_at < before LIMIT 200
$$;

REVOKE ALL ON FUNCTION stuck_sandbox_runs FROM PUBLIC;
GRANT EXECUTE ON FUNCTION stuck_sandbox_runs TO ruya_app;
