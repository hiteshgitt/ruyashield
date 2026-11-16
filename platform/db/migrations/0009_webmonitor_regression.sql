-- RuyaShield P7: WebMonitor referral handoffs (RS-WMON-001..004, FR-040..042, FR-046) and scheduled regression
-- re-tests (RS-FIXP-006, FR-036). The WebMonitor contract is not agreed (DEP-WM-01 / D-14): everything here is the
-- provisional adapter's own shape, not a WebMonitor API.

-- ---------- referrals (RS-WMON-001) ----------
-- A referral arrives without an org. It belongs to nobody until a signed-in user claims it with the single-use
-- link token, so unclaimed rows are reachable only through the SECURITY DEFINER functions below. Only the minimal
-- context is kept (FR-042): no credentials, page content or end-user data. All of it is untrusted text.
CREATE TABLE webmonitor_referrals (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid REFERENCES orgs(id),
  external_ref    text NOT NULL CHECK (length(external_ref) BETWEEN 1 AND 100),
  nonce           text NOT NULL UNIQUE,
  payload_sha256  text NOT NULL,
  signal_type     text NOT NULL CHECK (length(signal_type) BETWEEN 1 AND 50),
  host            text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
  observed_at     timestamptz NOT NULL,
  summary         text NOT NULL DEFAULT '' CHECK (length(summary) <= 280),
  status          text NOT NULL DEFAULT 'pending_consent'
                  CHECK (status IN ('pending_consent','consented','declined','deleted','expired')),
  token_hash      text NOT NULL UNIQUE,
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz,
  claimed_by      uuid REFERENCES users(id),
  share_status    boolean NOT NULL DEFAULT false,
  assessment_id   uuid,
  received_at     timestamptz NOT NULL DEFAULT now(),
  decided_at      timestamptz,
  CHECK ((org_id IS NULL) = (consumed_at IS NULL))
);
CREATE INDEX webmonitor_referrals_org ON webmonitor_referrals (org_id, received_at);

-- Consent records (FR-041): what was agreed, to which text version, by whom, for which referral. Append-only.
CREATE TABLE consents (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL REFERENCES orgs(id),
  subject       text NOT NULL CHECK (subject IN ('referral_assessment','referral_charges','referral_share_status','referral_declined')),
  text_version  text NOT NULL,
  user_id       uuid NOT NULL REFERENCES users(id),
  referral_id   uuid NOT NULL REFERENCES webmonitor_referrals(id),
  created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX consents_referral ON consents (referral_id);

-- Outbound link-back attempts (RS-WMON-003): status and a link only, never evidence.
CREATE TABLE referral_events (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES orgs(id),
  referral_id uuid NOT NULL REFERENCES webmonitor_referrals(id),
  kind        text NOT NULL CHECK (kind IN ('result_published','result_not_sent')),
  summary     jsonb NOT NULL,
  reason      text,
  created_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE assessments ADD COLUMN referral_id uuid REFERENCES webmonitor_referrals(id);
ALTER TABLE webmonitor_referrals ADD CONSTRAINT webmonitor_referrals_assessment_fk FOREIGN KEY (assessment_id) REFERENCES assessments(id);

-- ---------- scheduled regression re-tests (RS-FIXP-006) ----------
-- Off unless an org admin sets an interval. Scheduled runs have no requesting user.
ALTER TABLE orgs ADD COLUMN regression_interval_days int CHECK (regression_interval_days IS NULL OR regression_interval_days BETWEEN 1 AND 90);
ALTER TABLE verification_runs ADD COLUMN trigger text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual','scheduled_regression'));
ALTER TABLE verification_runs ALTER COLUMN requested_by DROP NOT NULL;
ALTER TABLE verification_runs ADD CONSTRAINT verification_runs_requester CHECK ((trigger = 'manual') = (requested_by IS NOT NULL));

-- ---------- row-level security ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['webmonitor_referrals','consents','referral_events']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id())', t);
  END LOOP;
END $$;

CREATE OR REPLACE FUNCTION consents_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'consents is append-only'; END $$;
CREATE TRIGGER consents_no_change BEFORE UPDATE OR DELETE ON consents FOR EACH ROW EXECUTE FUNCTION consents_append_only();

-- ---------- org-less access (SECURITY DEFINER, narrow) ----------
-- Stores a verified handoff. A repeated nonce never creates a second referral; the caller compares payload hashes.
CREATE OR REPLACE FUNCTION webmonitor_store_referral(
  p_external_ref text, p_nonce text, p_sha text, p_signal text, p_host text, p_observed timestamptz, p_summary text,
  p_token_hash text, p_expires timestamptz)
RETURNS TABLE (id uuid, payload_sha256 text, inserted boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE new_id uuid;
BEGIN
  INSERT INTO webmonitor_referrals (external_ref, nonce, payload_sha256, signal_type, host, observed_at, summary, token_hash, expires_at)
  VALUES (p_external_ref, p_nonce, p_sha, p_signal, p_host, p_observed, p_summary, p_token_hash, p_expires)
  ON CONFLICT (nonce) DO NOTHING RETURNING webmonitor_referrals.id INTO new_id;
  IF new_id IS NOT NULL THEN
    RETURN QUERY SELECT new_id, p_sha, true;
  ELSE
    RETURN QUERY SELECT r.id, r.payload_sha256, false FROM webmonitor_referrals r WHERE r.nonce = p_nonce;
  END IF;
END $$;

-- What the landing page may show for a link token: the minimal context and state, nothing else.
CREATE OR REPLACE FUNCTION webmonitor_referral_by_token(p_token_hash text)
RETURNS TABLE (id uuid, signal_type text, host text, observed_at timestamptz, summary text, status text,
               expires_at timestamptz, consumed boolean, received_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT id, signal_type, host, observed_at, summary, status, expires_at, consumed_at IS NOT NULL, received_at
  FROM webmonitor_referrals WHERE token_hash = p_token_hash
$$;

-- Consumes the token once and binds the referral to the caller's org. Returns NULL if already used or expired.
CREATE OR REPLACE FUNCTION webmonitor_claim_referral(p_token_hash text, p_org uuid, p_user uuid, p_status text, p_now timestamptz)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE rid uuid;
BEGIN
  IF p_status NOT IN ('consented','declined','deleted') THEN RAISE EXCEPTION 'invalid status'; END IF;
  IF NOT EXISTS (SELECT 1 FROM memberships WHERE org_id = p_org AND user_id = p_user) THEN RETURN NULL; END IF;
  UPDATE webmonitor_referrals SET org_id = p_org, claimed_by = p_user, consumed_at = p_now, decided_at = p_now, status = p_status,
         summary = CASE WHEN p_status = 'deleted' THEN '' ELSE summary END
   WHERE token_hash = p_token_hash AND consumed_at IS NULL AND status = 'pending_consent' AND expires_at > p_now
  RETURNING id INTO rid;
  RETURN rid;
END $$;

-- Funnel counts by stage (RS-WMON-004). Counts only: no names, emails, hosts or referral ids leave this function.
CREATE OR REPLACE FUNCTION referral_funnel_counts(p_since timestamptz)
RETURNS TABLE (received bigint, consented bigint, verified bigint, assessed bigint, converted bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT
    count(*),
    count(*) FILTER (WHERE r.status = 'consented'),
    count(*) FILTER (WHERE r.status = 'consented' AND EXISTS (
      SELECT 1 FROM assets a WHERE a.org_id = r.org_id AND a.host = r.host AND a.status = 'verified')),
    count(*) FILTER (WHERE r.assessment_id IS NOT NULL),
    count(*) FILTER (WHERE EXISTS (
      SELECT 1 FROM assessments s WHERE s.id = r.assessment_id AND s.status IN ('completed','completed_with_errors')))
  FROM webmonitor_referrals r WHERE r.received_at >= p_since
$$;

-- Findings due for a regression re-test: verified fixed, org has a schedule, last re-test older than the interval.
CREATE OR REPLACE FUNCTION due_regression_checks(p_now timestamptz)
RETURNS TABLE (org_id uuid, finding_id uuid) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT f.org_id, f.id FROM findings f JOIN orgs o ON o.id = f.org_id
  WHERE o.regression_interval_days IS NOT NULL AND f.status = 'resolved_verified'
    AND NOT EXISTS (SELECT 1 FROM verification_runs v WHERE v.finding_id = f.id AND v.status IN ('queued','running'))
    AND coalesce((SELECT max(v.created_at) FROM verification_runs v WHERE v.finding_id = f.id), '-infinity')
        < p_now - make_interval(days => o.regression_interval_days)
  LIMIT 500
$$;

-- ---------- grants ----------
GRANT SELECT, INSERT, UPDATE ON webmonitor_referrals TO ruya_app;
GRANT SELECT, INSERT ON consents, referral_events TO ruya_app;
DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY['webmonitor_store_referral','webmonitor_referral_by_token','webmonitor_claim_referral','referral_funnel_counts','due_regression_checks']
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %I FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %I TO ruya_app', f);
  END LOOP;
END $$;
