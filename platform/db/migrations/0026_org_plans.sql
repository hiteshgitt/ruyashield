-- Free and Pro plans for organizations. Pro unlocks the download features (reports, raw evidence, audit
-- export); Free keeps scanning, findings, the dashboard and Zealot. Operators switch an organization's plan
-- from the operator console until online payment exists.
INSERT INTO plans (id, max_assessments_per_month, max_requests_per_assessment) VALUES
  ('free', 20, 200),
  ('pro', 300, 200)
ON CONFLICT (id) DO NOTHING;

-- Organizations created during the pilot keep everything they had: they become Pro.
UPDATE orgs SET plan = 'pro' WHERE plan = 'pilot';
ALTER TABLE orgs ALTER COLUMN plan SET DEFAULT 'free';
ALTER TABLE orgs ADD CONSTRAINT orgs_plan_known FOREIGN KEY (plan) REFERENCES plans (id);

-- Operator console: every live organization with its plan. Called only after the app has checked that the
-- signed-in person is an operator (RUYA_OPERATOR_EMAILS).
CREATE OR REPLACE FUNCTION operator_org_list()
RETURNS TABLE (id uuid, name text, slug text, plan text, created_at timestamptz, members bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.id, o.name, o.slug, o.plan, o.created_at,
    (SELECT count(*) FROM memberships m WHERE m.org_id = o.id)
  FROM orgs o WHERE o.deleted_at IS NULL ORDER BY o.created_at DESC
$$;
REVOKE ALL ON FUNCTION operator_org_list FROM PUBLIC;
GRANT EXECUTE ON FUNCTION operator_org_list TO ruya_app;
