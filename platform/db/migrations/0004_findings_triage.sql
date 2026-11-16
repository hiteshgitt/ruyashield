-- RuyaShield P3: findings & triage (RS-FIND-001..005, RS-RISK-001..003, RS-COLLAB-001/002).

-- ---------- lifecycle (RS-FIND-004) ----------
-- P2 statuses map onto the lifecycle: open -> new; resolved (a manual, unverified close) -> triaged,
-- never resolved_verified, because only a verification re-test may set that.
ALTER TABLE findings DROP CONSTRAINT findings_status_check;
UPDATE findings SET status = CASE status WHEN 'open' THEN 'new' WHEN 'resolved' THEN 'triaged' ELSE status END;
ALTER TABLE findings ALTER COLUMN status SET DEFAULT 'new';
ALTER TABLE findings ADD CONSTRAINT findings_status_check CHECK (status IN (
  'new','triaged','confirmed','false_positive','accepted_risk','in_remediation',
  'fix_pending_verification','resolved_verified','reopened','stale'));

ALTER TABLE findings
  ADD COLUMN confidence         text NOT NULL DEFAULT 'confirmed' CHECK (confidence IN ('confirmed','likely','suspected','unknown')),
  ADD COLUMN source_severity    text CHECK (source_severity IN ('info','low','medium','high','critical')),
  ADD COLUMN source_confidence  text CHECK (source_confidence IN ('confirmed','likely','suspected','unknown')),
  ADD COLUMN cvss_vector        text,
  -- Set when an analyst overrides severity/confidence; ingestion then keeps the analyst's values.
  ADD COLUMN severity_reason    text,
  ADD COLUMN severity_set_by    uuid,
  ADD COLUMN owner_id           uuid,
  ADD COLUMN due_at             timestamptz,
  ADD COLUMN latest_evidence_id uuid,
  -- Stable-evidence class recorded when marked false positive; re-detection with a different class re-triages.
  ADD COLUMN fp_evidence_class  text,
  -- Consecutive completed covering checks that did not see the finding (stale candidate rule).
  ADD COLUMN missed_runs        int NOT NULL DEFAULT 0,
  ADD COLUMN status_changed_at  timestamptz NOT NULL DEFAULT now();
UPDATE findings SET source_severity = severity, source_confidence = confidence;

ALTER TABLE assets ADD COLUMN criticality text CHECK (criticality IN ('low','medium','high','critical'));

-- ---------- evidence (RS-FIND-002) ----------
-- Stored in Postgres behind the evidence module. Object storage with SSE-KMS is not implemented.
CREATE TABLE evidence_items (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  sha256        text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  content_type  text NOT NULL,
  size_bytes    int NOT NULL CHECK (size_bytes >= 0),
  truncated     boolean NOT NULL DEFAULT false,
  body          text NOT NULL,
  assessment_id uuid REFERENCES assessments(id),
  check_run_id  uuid REFERENCES check_runs(id),
  captured_at   timestamptz NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION evidence_items_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'evidence_items is append-only';
END $$;
CREATE TRIGGER evidence_items_no_update BEFORE UPDATE OR DELETE ON evidence_items
  FOR EACH ROW EXECUTE FUNCTION evidence_items_immutable();

ALTER TABLE finding_occurrences ADD COLUMN evidence_id uuid REFERENCES evidence_items(id);
ALTER TABLE findings ADD CONSTRAINT findings_latest_evidence_fk FOREIGN KEY (latest_evidence_id) REFERENCES evidence_items(id);

-- ---------- history, risk, comments ----------
CREATE TABLE finding_status_history (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL,
  finding_id  uuid NOT NULL REFERENCES findings(id),
  from_status text,
  to_status   text NOT NULL,
  actor_type  text NOT NULL CHECK (actor_type IN ('user','service')),
  actor_id    text NOT NULL,
  reason      text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION finding_status_history_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'finding_status_history is append-only';
END $$;
CREATE TRIGGER finding_status_history_no_update BEFORE UPDATE OR DELETE ON finding_status_history
  FOR EACH ROW EXECUTE FUNCTION finding_status_history_immutable();

CREATE TABLE risk_acceptances (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                uuid NOT NULL,
  finding_id            uuid NOT NULL REFERENCES findings(id),
  justification         text NOT NULL CHECK (length(justification) >= 20),
  compensating_controls text NOT NULL CHECK (length(compensating_controls) >= 1),
  expires_at            timestamptz NOT NULL,
  accepted_by           uuid NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at <= created_at + interval '365 days'),
  revoked_at            timestamptz,
  revoked_by            uuid,
  expired_at            timestamptz
);
-- At most one live acceptance per finding.
CREATE UNIQUE INDEX risk_acceptances_live ON risk_acceptances (finding_id) WHERE revoked_at IS NULL AND expired_at IS NULL;

CREATE TABLE finding_comments (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL,
  finding_id uuid NOT NULL REFERENCES findings(id),
  author_id  uuid NOT NULL,
  body       text NOT NULL CHECK (length(body) BETWEEN 1 AND 5000),
  mentions   uuid[] NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------- list indexes (RS-FIND-005) ----------
CREATE INDEX findings_org_status ON findings (org_id, status);
CREATE INDEX findings_org_asset ON findings (org_id, asset_id);
CREATE INDEX findings_org_owner ON findings (org_id, owner_id);
CREATE INDEX findings_asset_check ON findings (asset_id, check_key);
CREATE INDEX finding_status_history_finding ON finding_status_history (finding_id, created_at);
CREATE INDEX finding_comments_finding ON finding_comments (finding_id, created_at);
CREATE INDEX finding_occurrences_finding ON finding_occurrences (finding_id, seen_at);

-- ---------- row-level security ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['evidence_items','finding_status_history','risk_acceptances','finding_comments']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id())', t);
  END LOOP;
END $$;

-- ---------- risk expiry (scheduler, cross-tenant; ids only) ----------
CREATE OR REPLACE FUNCTION due_risk_expiries()
RETURNS TABLE (org_id uuid, finding_id uuid, acceptance_id uuid) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, finding_id, id FROM risk_acceptances
  WHERE revoked_at IS NULL AND expired_at IS NULL AND expires_at <= now()
  LIMIT 500
$$;

-- ---------- grants ----------
GRANT SELECT, INSERT ON evidence_items, finding_status_history, finding_comments TO ruya_app;  -- append-only
GRANT SELECT, INSERT, UPDATE ON risk_acceptances TO ruya_app;
REVOKE ALL ON FUNCTION due_risk_expiries FROM PUBLIC;
GRANT EXECUTE ON FUNCTION due_risk_expiries TO ruya_app;
