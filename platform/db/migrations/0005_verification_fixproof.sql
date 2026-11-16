-- RuyaShield P6: verification re-tests and FixProof records (RS-VERIF-001..004, RS-FIXP-001..004, RS-FIXP-006).

-- ---------- verification runs (RS-VERIF-001) ----------
-- One row per request. The worker re-runs only the checks that produced the finding, against the finding's
-- asset, under the same kill-switch and authorization gates as assessments. outcome stays NULL until the run
-- finishes; not_run means no traffic was sent (kill switch, lapsed authorization, unsupported check).
CREATE TABLE verification_runs (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL,
  finding_id      uuid NOT NULL REFERENCES findings(id),
  asset_id        uuid NOT NULL REFERENCES assets(id),
  status          text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','not_run')),
  outcome         text CHECK (outcome IN ('verified','partially_verified','failed','unverified')),
  reason          text,
  -- [{checkId, engineVersion, status: passed|failed|inconclusive|error, reason, evidenceId, evidenceSha256, sameVersionAsDetection, requests}]
  results         jsonb NOT NULL DEFAULT '[]',
  requested_by    uuid NOT NULL,
  idempotency_key text NOT NULL,
  fixproof_id     uuid,
  attempts        int NOT NULL DEFAULT 0,
  created_at      timestamptz NOT NULL DEFAULT now(),
  started_at      timestamptz,
  finished_at     timestamptz,
  UNIQUE (org_id, idempotency_key),
  CHECK ((status = 'completed') = (outcome IS NOT NULL))
);
-- At most one active re-test per finding.
CREATE UNIQUE INDEX verification_runs_active ON verification_runs (finding_id) WHERE status IN ('queued','running');
CREATE INDEX verification_runs_finding ON verification_runs (finding_id, created_at);

-- ---------- FixProof records (RS-FIXP-001..004) ----------
-- Tamper-evident: sha256 = sha256(canonical JSON of content); content carries prev_sha256, chaining the
-- org's records in seq order. Rows are never deleted; the only permitted update marks a record superseded.
CREATE TABLE fixproof_records (
  id                  uuid PRIMARY KEY,
  org_id              uuid NOT NULL,
  seq                 bigint NOT NULL,
  finding_id          uuid NOT NULL REFERENCES findings(id),
  verification_run_id uuid NOT NULL UNIQUE REFERENCES verification_runs(id),
  version             int NOT NULL CHECK (version >= 1),
  status              text NOT NULL CHECK (status IN ('verified','partially_verified','failed','unverified')),
  content             jsonb NOT NULL,
  sha256              text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  prev_sha256         text CHECK (prev_sha256 ~ '^[0-9a-f]{64}$'),
  created_at          timestamptz NOT NULL DEFAULT now(),
  superseded_at       timestamptz,
  superseded_reason   text CHECK (superseded_reason IN ('newer_verification','regression')),
  UNIQUE (org_id, seq),
  UNIQUE (finding_id, version),
  CHECK ((superseded_at IS NULL) = (superseded_reason IS NULL))
);
CREATE UNIQUE INDEX fixproof_records_active ON fixproof_records (finding_id) WHERE superseded_at IS NULL;
ALTER TABLE verification_runs ADD CONSTRAINT verification_runs_fixproof_fk FOREIGN KEY (fixproof_id) REFERENCES fixproof_records(id);

CREATE OR REPLACE FUNCTION fixproof_records_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'fixproof_records is append-only';
  END IF;
  IF OLD.superseded_at IS NOT NULL OR NEW.superseded_at IS NULL
     OR (to_jsonb(NEW) - 'superseded_at' - 'superseded_reason') <> (to_jsonb(OLD) - 'superseded_at' - 'superseded_reason') THEN
    RAISE EXCEPTION 'fixproof_records may only be marked superseded, once';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER fixproof_records_no_change BEFORE UPDATE OR DELETE ON fixproof_records
  FOR EACH ROW EXECUTE FUNCTION fixproof_records_guard();

-- ---------- row-level security ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['verification_runs','fixproof_records']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id())', t);
  END LOOP;
END $$;

-- ---------- stuck-run sweep (worker, cross-tenant; ids only) ----------
CREATE OR REPLACE FUNCTION stuck_verification_runs(before timestamptz)
RETURNS TABLE (id uuid, org_id uuid) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, org_id FROM verification_runs WHERE status = 'running' AND started_at < before LIMIT 200
$$;

-- ---------- grants ----------
GRANT SELECT, INSERT, UPDATE ON verification_runs, fixproof_records TO ruya_app;  -- fixproof updates limited by trigger
REVOKE ALL ON FUNCTION stuck_verification_runs FROM PUBLIC;
GRANT EXECUTE ON FUNCTION stuck_verification_runs TO ruya_app;
