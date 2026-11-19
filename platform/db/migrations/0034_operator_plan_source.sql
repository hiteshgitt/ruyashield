-- Operator console: show where each organization's Pro comes from (operator, trial, Ruya Lab Pro) and when a
-- trial ends. Requests made during a trial sort first too, since the trial will end.
DROP FUNCTION operator_org_list();
CREATE FUNCTION operator_org_list()
RETURNS TABLE (id uuid, name text, slug text, plan text, created_at timestamptz, members bigint, pro_requested_at timestamptz,
  plan_source text, trial_ends_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.id, o.name, o.slug, o.plan, o.created_at,
    (SELECT count(*) FROM memberships m WHERE m.org_id = o.id), o.pro_requested_at, o.plan_source, o.trial_ends_at
  FROM orgs o WHERE o.deleted_at IS NULL ORDER BY o.pro_requested_at DESC NULLS LAST, o.created_at DESC
$$;
REVOKE ALL ON FUNCTION operator_org_list FROM PUBLIC;
GRANT EXECUTE ON FUNCTION operator_org_list TO ruya_app;
