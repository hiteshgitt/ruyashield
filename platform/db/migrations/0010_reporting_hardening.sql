-- P8: reporting & hardening.
-- Dashboard/reports (FR-050/051/052), notifications (FR-054), audit export (FR-056),
-- scoped API tokens (FR-058), retention & org deletion (FR-059, RS-PLAT-005), operator break-glass (RS-PLAT-007).

-- ---------- org lifecycle (FR-059) ----------
-- Deletion is requested, cancellable for 30 days, then the org is closed (deleted_at) and access ends.
-- Physical erasure of a closed org is a manual runbook step (docs/runbooks/org-erasure.md); it is not automated.
ALTER TABLE orgs
  ADD COLUMN legal_hold             boolean NOT NULL DEFAULT false,
  ADD COLUMN deletion_requested_at  timestamptz,
  ADD COLUMN deletion_requested_by  uuid REFERENCES users(id),
  ADD COLUMN deleted_at             timestamptz,
  ADD CONSTRAINT orgs_deleted_after_request CHECK (deleted_at IS NULL OR deletion_requested_at IS NOT NULL);

-- Closed orgs disappear from the org switcher.
CREATE OR REPLACE FUNCTION user_orgs(p_user uuid)
RETURNS TABLE (org_id uuid, name text, slug text, role member_role)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.id, o.name, o.slug, m.role
  FROM memberships m JOIN orgs o ON o.id = m.org_id
  WHERE m.user_id = p_user AND o.deleted_at IS NULL ORDER BY o.name
$$;

-- Orgs whose 30-day cancellation window has passed. Legal hold blocks closure.
CREATE OR REPLACE FUNCTION finalize_org_deletions()
RETURNS TABLE (org_id uuid) LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  UPDATE orgs SET deleted_at = now()
  WHERE deleted_at IS NULL AND NOT legal_hold AND deletion_requested_at IS NOT NULL
    AND deletion_requested_at <= now() - interval '30 days'
  RETURNING id
$$;

-- ---------- notifications (FR-054) ----------
-- In-app notices hold a title and an app-relative link only; evidence never goes into a notification.
CREATE TABLE notifications (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id            uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id           uuid NOT NULL REFERENCES users(id),
  kind              text NOT NULL CHECK (kind ~ '^[a-z_]{2,40}$'),
  title             text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  link              text CHECK (link IS NULL OR link ~ '^/[A-Za-z0-9/_-]{0,200}$'),
  security_critical boolean NOT NULL DEFAULT false,
  source_id         uuid,
  created_at        timestamptz NOT NULL DEFAULT now(),
  read_at           timestamptz,
  UNIQUE (source_id, user_id)
);
CREATE INDEX notifications_user ON notifications (org_id, user_id, created_at DESC);

CREATE TABLE notification_prefs (
  org_id   uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id  uuid NOT NULL REFERENCES users(id),
  kind     text NOT NULL CHECK (kind ~ '^[a-z_]{2,40}$'),
  email    boolean NOT NULL DEFAULT true,
  in_app   boolean NOT NULL DEFAULT true,
  PRIMARY KEY (org_id, user_id, kind)
);

-- ---------- reports (FR-051/052) ----------
-- Generated artifacts are immutable; the stored sha256 lets a recipient check a copy.
CREATE TABLE reports (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  created_by      uuid NOT NULL REFERENCES users(id),
  format          text NOT NULL CHECK (format IN ('csv','pdf')),
  client_group_id uuid,
  params          jsonb NOT NULL DEFAULT '{}',
  sha256          text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes      int NOT NULL CHECK (size_bytes BETWEEN 1 AND 20971520),
  content         bytea NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX reports_org ON reports (org_id, created_at DESC);
CREATE OR REPLACE FUNCTION reports_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND retention_purge_active() THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'reports is append-only';
END $$;

-- ---------- scoped API tokens (FR-058) ----------
-- A token acts as its creating user (membership re-checked per request), narrowed to its scopes.
-- Only the sha256 of the token is stored; the raw value is shown once.
CREATE TABLE api_tokens (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES users(id),
  name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  prefix       text NOT NULL CHECK (prefix ~ '^rs_[A-Za-z0-9_-]{6}$'),
  token_hash   text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  scopes       text[] NOT NULL CHECK (cardinality(scopes) >= 1
                 AND scopes <@ ARRAY['findings:read','assets:read','reports:generate']),
  expires_at   timestamptz NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  revoked_at   timestamptz,
  last_used_at timestamptz,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '366 days')
);
CREATE INDEX api_tokens_org ON api_tokens (org_id, created_at DESC);

-- Bearer lookup happens before the org is known; returns only the row for this exact hash.
CREATE OR REPLACE FUNCTION api_token_lookup(p_hash text)
RETURNS TABLE (id uuid, org_id uuid, user_id uuid, scopes text[], expires_at timestamptz, revoked_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT t.id, t.org_id, t.user_id, t.scopes, t.expires_at, t.revoked_at FROM api_tokens t WHERE t.token_hash = p_hash
$$;

-- ---------- operator break-glass (RS-PLAT-007) ----------
-- Time-boxed (max 4h), reason required, read-only in the policy layer, audited and announced to org admins.
CREATE TABLE break_glass_sessions (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  operator_user_id uuid NOT NULL REFERENCES users(id),
  reason           text NOT NULL CHECK (length(btrim(reason)) BETWEEN 10 AND 500),
  started_at       timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  ended_at         timestamptz,
  CHECK (expires_at > started_at AND expires_at <= started_at + interval '4 hours')
);
CREATE INDEX break_glass_operator ON break_glass_sessions (operator_user_id, expires_at DESC);

-- Operators are not members, so they need the org id from its slug.
CREATE OR REPLACE FUNCTION operator_org_lookup(p_slug text)
RETURNS TABLE (id uuid, name text) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.id, o.name FROM orgs o WHERE o.slug = p_slug AND o.deleted_at IS NULL
$$;

-- ---------- retention (RS-PLAT-005) ----------
-- Append-only tables allow DELETE only inside retention_purge_at(): it sets a transaction-local flag and runs as
-- the table owner. The runtime role can set the flag but is still refused.
CREATE OR REPLACE FUNCTION retention_purge_active() RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT coalesce(current_setting('ruya.retention_purge', true), '') = 'on' AND current_user <> 'ruya_app'
$$;

CREATE OR REPLACE FUNCTION evidence_items_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND retention_purge_active() THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'evidence_items is append-only';
END $$;

CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND retention_purge_active() THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'audit_events is append-only';
END $$;

-- ai_append_only also guards remediation plans/history and approvals; only AI analyses and claims are purgeable.
CREATE OR REPLACE FUNCTION ai_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND TG_TABLE_NAME IN ('ai_analyses','ai_claims') AND retention_purge_active() THEN RETURN OLD; END IF;
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END $$;

CREATE TRIGGER reports_no_change BEFORE UPDATE OR DELETE ON reports FOR EACH ROW EXECUTE FUNCTION reports_immutable();

-- Where the audit chain continues after old events are purged: verification starts from the latest anchor.
CREATE TABLE audit_chain_anchors (
  id           bigserial PRIMARY KEY,
  org_id       uuid NOT NULL,
  seq          bigint NOT NULL,
  hash         text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  purged_count bigint NOT NULL CHECK (purged_count > 0),
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, seq)
);

CREATE OR REPLACE FUNCTION verify_audit_chain()
RETURNS TABLE (checked bigint, first_broken_seq bigint) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_org uuid := app_org_id();
  r audit_events;
  a audit_chain_anchors;
  v_prev text := repeat('0', 64);
  v_expect_seq bigint := 1;
  n bigint := 0;
BEGIN
  IF v_org IS NOT NULL THEN
    SELECT * INTO a FROM audit_chain_anchors WHERE org_id = v_org ORDER BY seq DESC LIMIT 1;
    IF FOUND THEN v_prev := a.hash; v_expect_seq := a.seq + 1; END IF;
  END IF;
  FOR r IN SELECT * FROM audit_events WHERE org_id IS NOT DISTINCT FROM v_org AND seq >= v_expect_seq ORDER BY seq LOOP
    n := n + 1;
    IF r.seq <> v_expect_seq OR r.prev_hash <> v_prev
       OR r.hash <> encode(digest(r.prev_hash || audit_canonical(r), 'sha256'), 'hex') THEN
      checked := n; first_broken_seq := v_expect_seq; RETURN NEXT; RETURN;
    END IF;
    v_prev := r.hash; v_expect_seq := v_expect_seq + 1;
  END LOOP;
  checked := n; first_broken_seq := NULL; RETURN NEXT;
END $$;

-- Retention windows: evidence items, AI analyses, notifications and reports 1 year; evidence on closed findings and
-- audit events 3 years. Orgs on legal hold are skipped entirely. Global (org-less) audit events are kept.
-- Findings rows and their status history are kept (FixProof records point at them); only captured evidence is scrubbed.
-- The newest audit event of each org is always kept so the chain has a head.
-- Owner-only: p_now lets tests simulate time. The runtime role calls retention_purge(), which uses now().
CREATE OR REPLACE FUNCTION retention_purge_at(p_now timestamptz)
RETURNS TABLE (purged_org uuid, n_evidence bigint, n_ai_analyses bigint, n_findings_scrubbed bigint, n_audit_events bigint,
               n_notifications bigint, n_reports bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  o record;
  v_1y timestamptz := p_now - interval '1 year';
  v_3y timestamptz := p_now - interval '3 years';
  v_ev uuid[]; v_ai uuid[];
  v_last audit_events;
  v_n bigint;
BEGIN
  PERFORM set_config('ruya.retention_purge', 'on', true);
  FOR o IN SELECT id FROM orgs WHERE NOT legal_hold ORDER BY id LOOP
    purged_org := o.id; n_evidence := 0; n_ai_analyses := 0; n_findings_scrubbed := 0; n_audit_events := 0; n_notifications := 0; n_reports := 0;

    -- Evidence: keep the latest evidence of findings that are still open.
    SELECT coalesce(array_agg(e.id), '{}') INTO v_ev FROM evidence_items e
    WHERE e.org_id = o.id AND e.captured_at < v_1y
      AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.latest_evidence_id = e.id
                      AND f.status NOT IN ('resolved_verified','false_positive'));
    IF cardinality(v_ev) > 0 THEN
      UPDATE finding_occurrences SET evidence_id = NULL WHERE evidence_id = ANY (v_ev);
      UPDATE findings SET latest_evidence_id = NULL WHERE latest_evidence_id = ANY (v_ev);
      UPDATE sandbox_runs SET logs_evidence_id = NULL WHERE logs_evidence_id = ANY (v_ev);
      DELETE FROM evidence_items WHERE id = ANY (v_ev);
      n_evidence := cardinality(v_ev);
    END IF;

    -- AI analyses not referenced by a (immutable) remediation plan.
    SELECT coalesce(array_agg(a.id), '{}') INTO v_ai FROM ai_analyses a
    WHERE a.org_id = o.id AND a.created_at < v_1y
      AND NOT EXISTS (SELECT 1 FROM remediation_plans p WHERE p.ai_analysis_id = a.id);
    IF cardinality(v_ai) > 0 THEN
      DELETE FROM ai_claims WHERE analysis_id = ANY (v_ai);
      DELETE FROM ai_analyses WHERE id = ANY (v_ai);
      n_ai_analyses := cardinality(v_ai);
    END IF;

    -- Closed findings: scrub captured evidence, keep the row and its history.
    WITH s AS (
      UPDATE findings f SET evidence = '{}'::jsonb, remediation = NULL
      WHERE f.org_id = o.id AND f.status IN ('resolved_verified','false_positive') AND f.status_changed_at < v_3y
        AND (f.evidence <> '{}'::jsonb OR f.remediation IS NOT NULL)
      RETURNING f.id)
    SELECT count(*) INTO n_findings_scrubbed FROM s;
    UPDATE finding_occurrences fo SET evidence = '{}'::jsonb
    FROM findings f WHERE f.id = fo.finding_id AND f.org_id = o.id
      AND f.status IN ('resolved_verified','false_positive') AND f.status_changed_at < v_3y AND fo.evidence <> '{}'::jsonb;

    WITH d AS (DELETE FROM notifications n WHERE n.org_id = o.id AND n.created_at < v_1y RETURNING 1)
    SELECT count(*) INTO n_notifications FROM d;
    WITH d AS (DELETE FROM reports r WHERE r.org_id = o.id AND r.created_at < v_1y RETURNING 1)
    SELECT count(*) INTO n_reports FROM d;

    -- Audit: delete a prefix of the chain and anchor where it now starts.
    PERFORM pg_advisory_xact_lock(hashtextextended('audit:' || o.id::text, 0));
    SELECT * INTO v_last FROM audit_events e
    WHERE e.org_id = o.id AND e.ts < v_3y
      AND e.seq < (SELECT max(x.seq) FROM audit_events x WHERE x.org_id = o.id)
    ORDER BY e.seq DESC LIMIT 1;
    IF FOUND THEN
      DELETE FROM audit_events e WHERE e.org_id = o.id AND e.seq <= v_last.seq;
      GET DIAGNOSTICS v_n = ROW_COUNT;
      INSERT INTO audit_chain_anchors (org_id, seq, hash, purged_count) VALUES (o.id, v_last.seq, v_last.hash, v_n);
      n_audit_events := v_n;
    END IF;

    IF n_evidence + n_ai_analyses + n_findings_scrubbed + n_audit_events + n_notifications + n_reports > 0 THEN RETURN NEXT; END IF;
  END LOOP;
  PERFORM set_config('ruya.retention_purge', 'off', true);
END $$;

CREATE OR REPLACE FUNCTION retention_purge()
RETURNS TABLE (purged_org uuid, n_evidence bigint, n_ai_analyses bigint, n_findings_scrubbed bigint, n_audit_events bigint,
               n_notifications bigint, n_reports bigint)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  SELECT * FROM retention_purge_at(now())
$$;

-- ---------- RLS ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['notifications','notification_prefs','reports','api_tokens','break_glass_sessions','audit_chain_anchors']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id())', t);
  END LOOP;
END $$;

-- ---------- grants ----------
GRANT SELECT, INSERT, UPDATE ON notifications, api_tokens, break_glass_sessions TO ruya_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_prefs TO ruya_app;
GRANT SELECT, INSERT ON reports TO ruya_app;
GRANT SELECT ON audit_chain_anchors TO ruya_app;
DO $$
DECLARE f text;
BEGIN
  FOREACH f IN ARRAY ARRAY['user_orgs','finalize_org_deletions','api_token_lookup','operator_org_lookup','verify_audit_chain','retention_purge']
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %I FROM PUBLIC', f);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %I TO ruya_app', f);
  END LOOP;
END $$;
REVOKE ALL ON FUNCTION retention_purge_at(timestamptz) FROM PUBLIC;
