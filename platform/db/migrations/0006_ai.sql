-- RuyaShield P4: evidence-grounded AI analysis (RS-AI-001..006). Blueprint §7.
-- The AI never changes a finding's status, never selects targets and never approves anything. Every analysis
-- records exactly what it was given (input_sha256 + provenance) and which prompt/model/schema/redaction produced it.

-- ---------- per-org budget (RS-AI-006) ----------
ALTER TABLE orgs ADD COLUMN ai_monthly_token_budget int NOT NULL DEFAULT 200000 CHECK (ai_monthly_token_budget >= 0);

-- ---------- eval runs and prompt releases (RS-AI-005, global) ----------
-- Written by the owner role from scripts/ai-eval.mts only. The app role may read them; it can't release a prompt.
CREATE TABLE ai_eval_runs (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  prompt_id       text NOT NULL,
  prompt_version  int NOT NULL,
  template_sha256 text NOT NULL CHECK (template_sha256 ~ '^[0-9a-f]{64}$'),
  provider        text NOT NULL,
  model           text NOT NULL,
  metrics         jsonb NOT NULL,
  thresholds      jsonb NOT NULL,
  passed          boolean NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ai_prompt_releases (
  prompt_id       text NOT NULL,
  prompt_version  int NOT NULL,
  template_sha256 text NOT NULL CHECK (template_sha256 ~ '^[0-9a-f]{64}$'),
  provider        text NOT NULL,
  model           text NOT NULL,
  eval_run_id     uuid NOT NULL REFERENCES ai_eval_runs(id),
  released_at     timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (prompt_id, prompt_version, provider, model)
);
CREATE OR REPLACE FUNCTION ai_release_requires_pass() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM ai_eval_runs e WHERE e.id = NEW.eval_run_id AND e.passed
                   AND e.prompt_id = NEW.prompt_id AND e.prompt_version = NEW.prompt_version
                   AND e.template_sha256 = NEW.template_sha256 AND e.provider = NEW.provider AND e.model = NEW.model) THEN
    RAISE EXCEPTION 'a prompt can only be released against a passing eval run for the same prompt, template and model';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER ai_prompt_releases_gate BEFORE INSERT OR UPDATE ON ai_prompt_releases
  FOR EACH ROW EXECUTE FUNCTION ai_release_requires_pass();

-- ---------- analyses and claims (RS-AI-001..004) ----------
-- status: completed (≥1 evidence-backed claim), inconclusive (nothing could be supported), rejected (output failed
-- schema validation after one repair attempt), unavailable (provider error / timeout / circuit open).
CREATE TABLE ai_analyses (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            uuid NOT NULL,
  finding_id        uuid NOT NULL REFERENCES findings(id),
  use_case          text NOT NULL CHECK (use_case IN ('explain','remediation')),
  prompt_id         text NOT NULL,
  prompt_version    int NOT NULL,
  schema_version    text NOT NULL,
  redaction_version text NOT NULL,
  provider          text NOT NULL,
  model             text NOT NULL,
  input_sha256      text NOT NULL CHECK (input_sha256 ~ '^[0-9a-f]{64}$'),
  -- [{sourceType, id, sha256}] — what the model was shown.
  inputs            jsonb NOT NULL,
  status            text NOT NULL CHECK (status IN ('completed','inconclusive','rejected','unavailable')),
  summary           text,
  uncertainty       text,
  missing_evidence  jsonb NOT NULL DEFAULT '[]',
  dropped_claims    int NOT NULL DEFAULT 0,
  flags             jsonb NOT NULL DEFAULT '[]',
  tokens_in         int NOT NULL DEFAULT 0,
  tokens_out        int NOT NULL DEFAULT 0,
  latency_ms        int NOT NULL DEFAULT 0,
  error             text,
  requested_by      uuid NOT NULL,
  idempotency_key   text NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, idempotency_key)
);
CREATE INDEX ai_analyses_finding ON ai_analyses (finding_id, created_at DESC);

CREATE TABLE ai_claims (
  id                     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                 uuid NOT NULL,
  analysis_id            uuid NOT NULL REFERENCES ai_analyses(id),
  ordinal                int NOT NULL,
  type                   text NOT NULL CHECK (type IN ('observation','inference','recommendation')),
  text                   text NOT NULL,
  evidence_ids           uuid[] NOT NULL CHECK (cardinality(evidence_ids) >= 1),
  confidence_label       text NOT NULL CHECK (confidence_label IN ('confirmed','likely','possible')),
  verification_check_ids text[] NOT NULL DEFAULT '{}',
  steps                  jsonb NOT NULL DEFAULT '[]',
  approval_required      boolean NOT NULL DEFAULT false,
  UNIQUE (analysis_id, ordinal),
  -- inferences are hypotheses: never "confirmed". Recommendations must name a re-test check.
  CHECK (type <> 'inference' OR confidence_label <> 'confirmed'),
  CHECK (type <> 'recommendation' OR cardinality(verification_check_ids) >= 1)
);

-- Analyses and claims are records of what the model said: append-only.
CREATE OR REPLACE FUNCTION ai_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;
CREATE TRIGGER ai_analyses_no_change BEFORE UPDATE OR DELETE ON ai_analyses FOR EACH ROW EXECUTE FUNCTION ai_append_only();
CREATE TRIGGER ai_claims_no_change BEFORE UPDATE OR DELETE ON ai_claims FOR EACH ROW EXECUTE FUNCTION ai_append_only();

-- ---------- row-level security ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['ai_analyses','ai_claims']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id())', t);
  END LOOP;
END $$;

-- ---------- grants ----------
GRANT SELECT, INSERT ON ai_analyses, ai_claims TO ruya_app;
GRANT SELECT ON ai_eval_runs, ai_prompt_releases TO ruya_app;
