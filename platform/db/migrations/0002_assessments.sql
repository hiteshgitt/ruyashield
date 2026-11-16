-- RuyaShield P2: core assessment (scope versions, assessments, check runs, findings, usage).
-- Same conventions as 0001: tenant tables carry org_id and RLS keyed on app.org_id; ruya_app
-- gets least-privilege grants; cross-tenant maintenance goes through SECURITY DEFINER helpers.

-- ---------- global catalogue (not tenant data) ----------
-- Every check that can run is listed here with its intrusiveness class (PRD v2 §7):
-- P = passive (public data only), A1 = light active (ordinary requests), A2 = intrusive
-- (needs approval; none are runnable in P2), X = prohibited (never runnable).
CREATE TABLE check_definitions (
  id                     text PRIMARY KEY,           -- '<key>@<version>'
  check_key              text NOT NULL,
  version                int  NOT NULL,
  class                  text NOT NULL CHECK (class IN ('P','A1','A2','X')),
  engine                 text NOT NULL,
  title                  text NOT NULL,
  description            text NOT NULL,
  timeout_ms             int  NOT NULL CHECK (timeout_ms BETWEEN 1000 AND 60000),
  request_budget         int  NOT NULL CHECK (request_budget BETWEEN 0 AND 50),
  verification_supported boolean NOT NULL DEFAULT false,
  enabled                boolean NOT NULL DEFAULT true,
  notes                  text,
  UNIQUE (check_key, version),
  CHECK (class <> 'X' OR enabled = false)
);

INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('tls.cert_expiry@1', 'tls.cert_expiry', 1, 'A1', 'native', 'TLS certificate expiry',
  'Opens one TLS connection to port 443 and reads the presented certificate''s validity dates.', 8000, 1, true, true, NULL),
 ('http.security_headers@1', 'http.security_headers', 1, 'A1', 'native', 'HTTP security headers',
  'Fetches the base path once (GET, following same-host redirects only) and inspects response headers and cookie flags.', 8000, 4, true, true, NULL),
 ('dns.email_posture@1', 'dns.email_posture', 1, 'P', 'native', 'Email DNS posture (SPF / DMARC)',
  'Reads public SPF and DMARC TXT records. Sends no traffic to the asset.', 8000, 0, true, true, NULL),
 ('dns.caa@1', 'dns.caa', 1, 'P', 'native', 'CAA record',
  'Reads public CAA records. Sends no traffic to the asset.', 8000, 0, true, true, NULL),
 ('x.exploit_payloads@1', 'x.exploit_payloads', 1, 'X', 'none', 'Exploit payload delivery',
  'Listed only so the prohibition is explicit and testable. RuyaShield never runs exploit payloads.', 1000, 0, false, false,
  'Prohibited class X: cannot be enabled (table CHECK) or selected (launch validation).');

CREATE TABLE plans (
  id                         text PRIMARY KEY,
  max_assessments_per_month  int NOT NULL CHECK (max_assessments_per_month >= 0),
  max_requests_per_assessment int NOT NULL CHECK (max_requests_per_assessment > 0)
);
INSERT INTO plans VALUES ('pilot', 100, 200);

-- ---------- tenant tables ----------
ALTER TABLE assets ADD COLUMN kill_scanning boolean NOT NULL DEFAULT false;

-- Immutable, versioned scope for an asset (RS-SCAN-001). Rows are never updated.
CREATE TABLE scope_versions (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         uuid NOT NULL REFERENCES orgs(id),
  asset_id       uuid NOT NULL REFERENCES assets(id),
  version        int  NOT NULL,
  hosts          text[] NOT NULL CHECK (cardinality(hosts) BETWEEN 1 AND 10),
  base_paths     text[] NOT NULL CHECK (cardinality(base_paths) BETWEEN 1 AND 10),
  excluded_paths text[] NOT NULL DEFAULT '{}',
  check_ids      text[] NOT NULL CHECK (cardinality(check_ids) >= 1),
  classes        text[] NOT NULL,
  window_start   timestamptz NOT NULL,
  window_end     timestamptz NOT NULL CHECK (window_end > window_start),
  max_requests   int NOT NULL CHECK (max_requests > 0),
  max_duration_s int NOT NULL CHECK (max_duration_s BETWEEN 60 AND 3600),
  sha256         text NOT NULL,
  created_by     uuid NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, asset_id, version)
);

CREATE TABLE assessments (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id              uuid NOT NULL REFERENCES orgs(id),
  asset_id            uuid NOT NULL REFERENCES assets(id),
  scope_version_id    uuid NOT NULL REFERENCES scope_versions(id),
  scope_sha256        text NOT NULL,
  status              text NOT NULL DEFAULT 'queued' CHECK (status IN
                        ('draft','queued','running','cancelling','cancelled','completed',
                         'completed_with_errors','failed','timed_out','rejected')),
  reason              text,
  requested_by        uuid NOT NULL,
  idempotency_key     text NOT NULL,
  attempts            int NOT NULL DEFAULT 0,
  lease_until         timestamptz,
  cancel_requested_at timestamptz,
  cancelled_by        uuid,
  coverage            jsonb,
  engine_version      text,
  queued_at           timestamptz NOT NULL DEFAULT now(),
  started_at          timestamptz,
  finished_at         timestamptz,
  UNIQUE (org_id, idempotency_key)
);
CREATE INDEX assessments_org_idx ON assessments(org_id, queued_at DESC);
CREATE INDEX assessments_active_idx ON assessments(status) WHERE status IN ('queued','running','cancelling');

CREATE TABLE check_runs (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id         uuid NOT NULL,
  assessment_id  uuid NOT NULL REFERENCES assessments(id),
  check_id       text NOT NULL REFERENCES check_definitions(id),
  status         text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','ok','error','timeout','skipped')),
  reason         text,
  requests_used  int NOT NULL DEFAULT 0,
  engine_version text,
  evidence       jsonb,
  started_at     timestamptz,
  finished_at    timestamptz,
  UNIQUE (assessment_id, check_id)
);

CREATE TABLE findings (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid NOT NULL,
  asset_id           uuid NOT NULL REFERENCES assets(id),
  fingerprint        text NOT NULL,
  check_key          text NOT NULL,
  issue_key          text NOT NULL,
  title              text NOT NULL,
  severity           text NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  location           text NOT NULL,
  status             text NOT NULL DEFAULT 'open' CHECK (status IN ('open','resolved','accepted_risk','false_positive')),
  first_seen         timestamptz NOT NULL DEFAULT now(),
  last_seen          timestamptz NOT NULL DEFAULT now(),
  last_assessment_id uuid NOT NULL REFERENCES assessments(id),
  evidence           jsonb NOT NULL DEFAULT '{}',
  remediation        text,
  UNIQUE (org_id, fingerprint)
);

CREATE TABLE finding_occurrences (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL,
  finding_id    uuid NOT NULL REFERENCES findings(id),
  assessment_id uuid NOT NULL REFERENCES assessments(id),
  evidence      jsonb NOT NULL DEFAULT '{}',
  seen_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (finding_id, assessment_id)
);

-- Metering (RS-BILL-001): one row per billable event, idempotent on (kind, source_id).
CREATE TABLE usage_records (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL,
  kind       text NOT NULL,
  source_id  uuid NOT NULL,
  quantity   int NOT NULL DEFAULT 1 CHECK (quantity >= 0),
  period     text NOT NULL CHECK (period ~ '^\d{4}-\d{2}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, kind, source_id)
);

-- History of kill-switch changes (org- or asset-level); the current state lives on orgs/assets.
CREATE TABLE kill_switches (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL,
  asset_id   uuid REFERENCES assets(id),
  which      text NOT NULL CHECK (which IN ('scanning','ai')),
  engaged    boolean NOT NULL,
  reason     text NOT NULL,
  actor_id   uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- ---------- row-level security ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['scope_versions','assessments','check_runs','findings','finding_occurrences',
                           'usage_records','kill_switches']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id())', t);
  END LOOP;
END $$;

-- ---------- maintenance sweep (worker, cross-tenant) ----------
-- Applies the time-based state transitions and reports each one so the worker can audit it:
--  * killed org/asset: queued -> cancelled, running -> cancelling (fail safe)
--  * running with an expired lease (worker died): requeue (max 3 attempts) or timed_out
--  * running past window end: timed_out
--  * cancelling with an expired lease: cancelled
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
        INSERT INTO outbox (org_id, topic, business_key, payload)
          SELECT r.org_id, 'assessment.run', 'assessment:' || r.id || ':' || (r.attempts + 1), o.payload
          FROM outbox o WHERE o.org_id = r.org_id AND o.topic = 'assessment.run'
            AND o.business_key LIKE 'assessment:' || r.id || ':%'
          ORDER BY o.created_at DESC LIMIT 1;
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

-- ---------- grants for runtime role ----------
GRANT SELECT ON check_definitions, plans TO ruya_app;
GRANT SELECT, INSERT ON scope_versions TO ruya_app;          -- no UPDATE/DELETE: scope versions are immutable
GRANT SELECT, INSERT, UPDATE ON assessments, check_runs, findings TO ruya_app;
GRANT SELECT, INSERT ON finding_occurrences, usage_records, kill_switches TO ruya_app;
REVOKE ALL ON FUNCTION sweep_assessments FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sweep_assessments TO ruya_app;
