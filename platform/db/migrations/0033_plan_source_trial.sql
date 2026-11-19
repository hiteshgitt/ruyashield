-- Where an organization's Pro comes from: 'manual' (an operator), 'trial' (14 days for the first organization a
-- person creates) or 'ruyalab' (Ruya Lab Pro on the creator's linked Ruya Lab account). Only trial and ruyalab Pro
-- end on their own. users.trial_used_at: one trial per person, whichever organization it went to.
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS plan_source text CHECK (plan_source IN ('manual', 'trial', 'ruyalab'));
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS trial_ends_at timestamptz;
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS trial_reminded int NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_used_at timestamptz;
UPDATE orgs SET plan_source = 'manual' WHERE plan = 'pro' AND plan_source IS NULL;

-- Worker: organizations whose plan can change on its own, with the creator's Ruya Lab account (if linked).
CREATE OR REPLACE FUNCTION plan_sweep_orgs()
RETURNS TABLE (id uuid, name text, plan text, plan_source text, trial_ends_at timestamptz, trial_reminded int, owner_ruyalab_sub text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.id, o.name, o.plan, o.plan_source, o.trial_ends_at, o.trial_reminded, u.ruyalab_sub
  FROM orgs o LEFT JOIN users u ON u.id = o.created_by
  WHERE o.deleted_at IS NULL AND (o.plan_source IN ('trial', 'ruyalab') OR u.ruyalab_sub IS NOT NULL)
$$;
REVOKE ALL ON FUNCTION plan_sweep_orgs FROM PUBLIC;
GRANT EXECUTE ON FUNCTION plan_sweep_orgs TO ruya_app;
