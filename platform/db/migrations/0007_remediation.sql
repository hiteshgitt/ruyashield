-- RuyaShield P5: remediation plans, sandbox tests, approvals and pull-request hand-off (RS-REMED-001..005,
-- RS-APPR-001..004). Blueprint §6.
-- RuyaShield never merges and never deploys. A change reaches a repository only as a branch + pull request, only
-- after a recorded approval of the exact plan+diff hash, and only through the service identity.

-- ---------- repository integrations (RS-REMED-002) ----------
-- type 'local_git' is a provisional adapter for a git repository under the server's RUYA_LOCAL_REPO_ROOT. It is
-- not a GitHub/GitLab integration. scopes records the least-privilege grant the adapter is limited to; the adapter
-- refuses anything outside it (no merge, push only to ruyashield/*). No tokens are stored.
CREATE TABLE repository_integrations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL,
  type            text NOT NULL CHECK (type IN ('local_git')),
  name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  external_id     text NOT NULL CHECK (external_id ~ '^[A-Za-z0-9._-]{1,100}$'),
  default_branch  text NOT NULL DEFAULT 'main' CHECK (default_branch ~ '^[A-Za-z0-9._/-]{1,100}$'),
  scopes          text[] NOT NULL DEFAULT ARRAY['contents:read','pull_requests:write','metadata:read']
                  CHECK (scopes <@ ARRAY['contents:read','pull_requests:write','metadata:read']),
  -- Fixed sandbox commands, configured by an admin. Never taken from a plan or from model output.
  test_commands   jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(test_commands) = 'array'),
  status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, type, external_id)
);

-- ---------- remediation plans (RS-REMED-001) ----------
CREATE TABLE remediation_plans (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id               uuid NOT NULL,
  finding_id           uuid NOT NULL REFERENCES findings(id),
  type                 text NOT NULL CHECK (type IN ('guided','patch')),
  state                text NOT NULL DEFAULT 'draft' CHECK (state IN (
                         'draft','proposed','sandbox_testing','test_passed','test_failed','awaiting_approval',
                         'approved','rejected','change_submitted','applied_by_customer','merged_observed',
                         'closed_unmerged','verifying','completed','remediation_failed')),
  title                text NOT NULL CHECK (length(title) BETWEEN 3 AND 200),
  description          text NOT NULL CHECK (length(description) <= 20000),
  affected_components  jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(affected_components) = 'array'),
  rollback_notes       text NOT NULL DEFAULT '' CHECK (length(rollback_notes) <= 10000),
  verification_checks  text[] NOT NULL DEFAULT '{}',
  integration_id       uuid REFERENCES repository_integrations(id),
  base_commit          text CHECK (base_commit ~ '^[0-9a-f]{40}$'),
  diff                 text CHECK (length(diff) <= 262144),
  diff_sha256          text CHECK (diff_sha256 ~ '^[0-9a-f]{64}$'),
  -- canonical-JSON hash of everything an approver approves (plan fields + diff). Recomputed on every edit.
  content_sha256       text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  version              int NOT NULL DEFAULT 1,
  -- provenance when drafted from an AI recommendation (RS-AI-004); the plan is still human-owned.
  ai_analysis_id       uuid REFERENCES ai_analyses(id),
  ai_claim_id          uuid REFERENCES ai_claims(id),
  created_by           uuid NOT NULL,
  updated_by           uuid NOT NULL,
  idempotency_key      text NOT NULL,
  created_at           timestamptz NOT NULL DEFAULT now(),
  updated_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, idempotency_key),
  CHECK (type <> 'patch' OR (diff IS NOT NULL AND diff_sha256 IS NOT NULL AND integration_id IS NOT NULL AND base_commit IS NOT NULL)),
  CHECK (type <> 'guided' OR diff IS NULL)
);
CREATE INDEX remediation_plans_finding ON remediation_plans (finding_id, created_at DESC);

-- Allowed state changes (blueprint §6 remediation state machine). Anything else is refused by the database.
CREATE OR REPLACE FUNCTION remediation_plan_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.org_id <> OLD.org_id OR NEW.finding_id <> OLD.finding_id OR NEW.type <> OLD.type OR NEW.created_by <> OLD.created_by THEN
    RAISE EXCEPTION 'remediation plan identity is immutable';
  END IF;
  IF NEW.state <> OLD.state AND NOT (OLD.state, NEW.state) IN (
      ('draft','proposed'),
      ('proposed','sandbox_testing'), ('sandbox_testing','test_passed'), ('sandbox_testing','test_failed'),
      ('test_failed','proposed'), ('test_passed','proposed'),
      ('proposed','awaiting_approval'), ('test_passed','awaiting_approval'),
      ('awaiting_approval','approved'), ('awaiting_approval','rejected'), ('awaiting_approval','proposed'),
      ('approved','proposed'), ('rejected','proposed'),
      ('approved','change_submitted'), ('approved','applied_by_customer'),
      ('change_submitted','merged_observed'), ('change_submitted','closed_unmerged'), ('closed_unmerged','proposed'),
      ('merged_observed','verifying'), ('applied_by_customer','verifying'),
      ('verifying','completed'), ('verifying','remediation_failed'), ('remediation_failed','proposed')) THEN
    RAISE EXCEPTION 'remediation plan cannot move from % to %', OLD.state, NEW.state;
  END IF;
  IF NEW.content_sha256 <> OLD.content_sha256 AND OLD.state NOT IN ('draft','proposed','test_failed','test_passed','awaiting_approval','approved','rejected','closed_unmerged','remediation_failed') THEN
    RAISE EXCEPTION 'a remediation plan in state % cannot be edited', OLD.state;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER remediation_plans_guard BEFORE UPDATE ON remediation_plans FOR EACH ROW EXECUTE FUNCTION remediation_plan_guard();
CREATE TRIGGER remediation_plans_no_delete BEFORE DELETE ON remediation_plans FOR EACH ROW EXECUTE FUNCTION ai_append_only();

CREATE TABLE remediation_plan_history (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL,
  plan_id     uuid NOT NULL REFERENCES remediation_plans(id),
  from_state  text,
  to_state    text NOT NULL,
  content_sha256 text NOT NULL,
  actor_type  text NOT NULL CHECK (actor_type IN ('user','service')),
  actor_id    text NOT NULL,
  reason      text,
  details     jsonb NOT NULL DEFAULT '{}',
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX remediation_plan_history_plan ON remediation_plan_history (plan_id, created_at);
CREATE TRIGGER remediation_plan_history_no_change BEFORE UPDATE OR DELETE ON remediation_plan_history FOR EACH ROW EXECUTE FUNCTION ai_append_only();

-- ---------- sandbox runs (RS-REMED-003) ----------
CREATE TABLE sandbox_runs (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL,
  plan_id          uuid NOT NULL REFERENCES remediation_plans(id),
  patch_sha256     text NOT NULL CHECK (patch_sha256 ~ '^[0-9a-f]{64}$'),
  content_sha256   text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  base_commit      text NOT NULL CHECK (base_commit ~ '^[0-9a-f]{40}$'),
  status           text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed')),
  result           text CHECK (result IN ('test_passed','test_failed','apply_failed','timeout','error')),
  reason           text,
  isolation        text NOT NULL,
  limits           jsonb NOT NULL,
  commands         jsonb NOT NULL,
  exit_code        int,
  egress_blocked   boolean NOT NULL DEFAULT true,
  logs_evidence_id uuid REFERENCES evidence_items(id),
  requested_by     uuid NOT NULL,
  idempotency_key  text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  started_at       timestamptz,
  finished_at      timestamptz,
  UNIQUE (org_id, idempotency_key),
  CHECK ((status = 'completed') = (result IS NOT NULL))
);
CREATE INDEX sandbox_runs_plan ON sandbox_runs (plan_id, created_at DESC);

-- ---------- approvals (RS-APPR-001..004) ----------
-- policy: two_person (requester may not decide) or single_approver (org opted out of approver_must_differ;
-- self-approval still needs step-up and is labelled in FixProof).
CREATE TABLE approvals (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid NOT NULL,
  subject_type       text NOT NULL CHECK (subject_type IN ('remediation_plan')),
  subject_id         uuid NOT NULL REFERENCES remediation_plans(id),
  subject_sha256     text NOT NULL CHECK (subject_sha256 ~ '^[0-9a-f]{64}$'),
  policy             text NOT NULL CHECK (policy IN ('two_person','single_approver')),
  untested_override  boolean NOT NULL DEFAULT false,
  sandbox_run_id     uuid REFERENCES sandbox_runs(id),
  requester_id       uuid NOT NULL,
  request_note       text,
  state              text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','rejected','expired','invalidated','revoked','consumed')),
  approver_id        uuid,
  self_approved      boolean NOT NULL DEFAULT false,
  decision_reason    text,
  auth_time          timestamptz,
  session_ref        text,
  decided_at         timestamptz,
  expires_at         timestamptz NOT NULL,
  consumed_at        timestamptz,
  revoked_by         uuid,
  revoked_at         timestamptz,
  end_reason         text,
  idempotency_key    text NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, idempotency_key),
  CHECK (state NOT IN ('approved','rejected','consumed','revoked') OR (approver_id IS NOT NULL AND decided_at IS NOT NULL AND auth_time IS NOT NULL)),
  CHECK (state <> 'rejected' OR length(coalesce(decision_reason, '')) >= 5),
  CHECK (self_approved = (approver_id IS NOT NULL AND approver_id = requester_id)),
  CHECK (NOT self_approved OR policy = 'single_approver')
);
-- One live approval per plan.
CREATE UNIQUE INDEX approvals_one_live ON approvals (subject_id) WHERE state IN ('pending','approved');
CREATE INDEX approvals_org_state ON approvals (org_id, state, created_at DESC);

CREATE OR REPLACE FUNCTION approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.subject_id <> OLD.subject_id OR NEW.subject_sha256 <> OLD.subject_sha256 OR NEW.requester_id <> OLD.requester_id
     OR NEW.policy <> OLD.policy OR NEW.org_id <> OLD.org_id OR NEW.expires_at <> OLD.expires_at THEN
    RAISE EXCEPTION 'approval subject is immutable';
  END IF;
  IF OLD.state IN ('rejected','expired','invalidated','revoked','consumed') THEN
    RAISE EXCEPTION 'approval in state % is final', OLD.state;
  END IF;
  IF NEW.state <> OLD.state AND NOT (OLD.state, NEW.state) IN (
      ('pending','approved'), ('pending','rejected'), ('pending','expired'), ('pending','invalidated'),
      ('approved','revoked'), ('approved','consumed'), ('approved','expired'), ('approved','invalidated')) THEN
    RAISE EXCEPTION 'approval cannot move from % to %', OLD.state, NEW.state;
  END IF;
  IF OLD.state = 'approved' AND (NEW.approver_id IS DISTINCT FROM OLD.approver_id OR NEW.decided_at IS DISTINCT FROM OLD.decided_at) THEN
    RAISE EXCEPTION 'an approval decision is immutable';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER approvals_guard BEFORE UPDATE ON approvals FOR EACH ROW EXECUTE FUNCTION approval_guard();
CREATE TRIGGER approvals_no_delete BEFORE DELETE ON approvals FOR EACH ROW EXECUTE FUNCTION ai_append_only();

-- ---------- code changes / pull requests (RS-REMED-004/005) ----------
-- Exactly one change per approval: the approval is consumed in the same transaction that records the change.
CREATE TABLE code_changes (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL,
  plan_id         uuid NOT NULL REFERENCES remediation_plans(id),
  approval_id     uuid NOT NULL UNIQUE REFERENCES approvals(id),
  integration_id  uuid NOT NULL REFERENCES repository_integrations(id),
  diff_sha256     text NOT NULL CHECK (diff_sha256 ~ '^[0-9a-f]{64}$'),
  base_commit     text NOT NULL CHECK (base_commit ~ '^[0-9a-f]{40}$'),
  branch          text NOT NULL CHECK (branch ~ '^ruyashield/[A-Za-z0-9._/-]{1,150}$'),
  head_sha        text CHECK (head_sha ~ '^[0-9a-f]{40}$'),
  pr_url          text,
  state           text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','open','merged','closed','failed')),
  merge_sha       text CHECK (merge_sha ~ '^[0-9a-f]{40}$'),
  error           text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  observed_at     timestamptz
);
CREATE INDEX code_changes_open ON code_changes (state) WHERE state = 'open';

-- Signed webhook deliveries are recorded once (replay protection).
CREATE TABLE repository_webhook_deliveries (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL,
  integration_id  uuid NOT NULL REFERENCES repository_integrations(id),
  delivery_id     text NOT NULL CHECK (length(delivery_id) BETWEEN 8 AND 100),
  event           text NOT NULL,
  received_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (integration_id, delivery_id)
);

-- ---------- row-level security ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['repository_integrations','remediation_plans','remediation_plan_history','sandbox_runs','approvals','code_changes','repository_webhook_deliveries']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id())', t);
  END LOOP;
END $$;

-- ---------- sweeps (worker, cross-tenant; ids only) ----------
CREATE OR REPLACE FUNCTION expired_approvals(at timestamptz)
RETURNS TABLE (id uuid, org_id uuid) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, org_id FROM approvals WHERE state IN ('pending','approved') AND expires_at <= at LIMIT 200
$$;
CREATE OR REPLACE FUNCTION open_code_changes()
RETURNS TABLE (id uuid, org_id uuid) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, org_id FROM code_changes WHERE state = 'open' LIMIT 200
$$;
-- The webhook endpoint is unauthenticated until the signature is checked; it needs the integration's org first.
CREATE OR REPLACE FUNCTION repository_integration_org(integration uuid)
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM repository_integrations WHERE id = integration AND status = 'active'
$$;

-- ---------- grants ----------
GRANT SELECT, INSERT, UPDATE ON repository_integrations, remediation_plans, sandbox_runs, approvals, code_changes TO ruya_app;
GRANT SELECT, INSERT ON remediation_plan_history, repository_webhook_deliveries TO ruya_app;
REVOKE ALL ON FUNCTION expired_approvals, open_code_changes, repository_integration_org FROM PUBLIC;
GRANT EXECUTE ON FUNCTION expired_approvals, open_code_changes, repository_integration_org TO ruya_app;
