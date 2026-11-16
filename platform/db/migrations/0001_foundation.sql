-- RuyaShield Phase 1 foundation schema.
-- Applied by the table owner (ruya_owner). The runtime role ruya_app gets only
-- the grants listed at the bottom; every tenant table is protected by RLS on
-- current_setting('app.org_id'), which the app sets with SET LOCAL per transaction.
-- RLS is not FORCEd: the owner role is used only for migrations and the audited
-- SECURITY DEFINER helpers; ruya_app is never the owner, so policies always apply to it.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION app_org_id() RETURNS uuid
  LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.org_id', true), '')::uuid $$;

-- ---------- global identity (not tenant-scoped) ----------
CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text NOT NULL UNIQUE,
  display_name  text NOT NULL,
  idp_issuer    text NOT NULL,
  idp_subject   text NOT NULL,
  disabled_at   timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (idp_issuer, idp_subject)
);

-- Session id stored only as SHA-256 of the cookie token.
CREATE TABLE sessions (
  id_hash       text PRIMARY KEY,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  active_org_id uuid,
  mfa           boolean NOT NULL,
  amr           text[] NOT NULL DEFAULT '{}',
  auth_time     timestamptz NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz,
  ip            text,
  user_agent    text
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

-- One-shot OIDC/dev login state (state + nonce + PKCE verifier), 10 min TTL.
CREATE TABLE login_states (
  state         text PRIMARY KEY,
  nonce         text NOT NULL,
  code_verifier text NOT NULL,
  return_to     text NOT NULL DEFAULT '/',
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE login_attempts (
  id         bigserial PRIMARY KEY,
  key        text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_key_idx ON login_attempts(key, created_at);

-- ---------- tenancy ----------
CREATE TABLE orgs (
  id                 uuid PRIMARY KEY,
  name               text NOT NULL CHECK (length(name) BETWEEN 2 AND 80),
  slug               text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,40}$'),
  plan               text NOT NULL DEFAULT 'pilot',
  region             text NOT NULL DEFAULT 'single-region-dev',
  -- policy defaults (RS-IAM-002)
  approver_must_differ boolean NOT NULL DEFAULT true,
  ai_enabled         boolean NOT NULL DEFAULT false,
  agency_requires_attestation boolean NOT NULL DEFAULT true,
  -- kill switch (FR-057)
  kill_scanning      boolean NOT NULL DEFAULT false,
  kill_ai            boolean NOT NULL DEFAULT false,
  created_by         uuid NOT NULL REFERENCES users(id),
  created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TYPE member_role AS ENUM ('org_admin','security_lead','analyst','developer','approver','viewer');

CREATE TABLE memberships (
  org_id      uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        member_role NOT NULL,
  -- true = member sees only assigned client groups
  restricted  boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);

CREATE TABLE client_groups (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id     uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name),
  UNIQUE (org_id, id)
);

CREATE TABLE member_client_groups (
  org_id          uuid NOT NULL,
  user_id         uuid NOT NULL,
  client_group_id uuid NOT NULL,
  PRIMARY KEY (org_id, user_id, client_group_id),
  FOREIGN KEY (org_id, user_id) REFERENCES memberships(org_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (org_id, client_group_id) REFERENCES client_groups(org_id, id) ON DELETE CASCADE
);

CREATE TABLE invites (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  email           text NOT NULL,
  role            member_role NOT NULL,
  client_group_ids uuid[] NOT NULL DEFAULT '{}',
  token_hash      text NOT NULL UNIQUE,
  invited_by      uuid NOT NULL REFERENCES users(id),
  expires_at      timestamptz NOT NULL,
  accepted_at     timestamptz,
  revoked_at      timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now()
);

-- ---------- assets ----------
CREATE TYPE asset_status AS ENUM ('unverified','verified','lapsed','revoked');

CREATE TABLE assets (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id          uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  client_group_id uuid,
  kind            text NOT NULL DEFAULT 'domain' CHECK (kind IN ('domain')),
  host            text NOT NULL,
  display_name    text NOT NULL,
  environment     text NOT NULL DEFAULT 'production' CHECK (environment IN ('production','staging','development')),
  status          asset_status NOT NULL DEFAULT 'unverified',
  verified_at     timestamptz,
  verified_method text,
  next_reverify_at timestamptz,
  reverify_failures int NOT NULL DEFAULT 0,
  created_by      uuid NOT NULL REFERENCES users(id),
  created_at      timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, host),
  FOREIGN KEY (org_id, client_group_id) REFERENCES client_groups(org_id, id)
);

CREATE TABLE asset_verifications (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  asset_id    uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  method      text NOT NULL CHECK (method IN ('dns_txt','http_file','meta_tag')),
  token       text NOT NULL,
  -- pending: issued, never checked; passed/failed/error are results of a check; expired: token past 14 days
  status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','checking','passed','failed','error','expired')),
  reason      text,
  evidence    jsonb,
  expires_at  timestamptz NOT NULL,
  checked_at  timestamptz,
  created_by  uuid REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX asset_verifications_asset_idx ON asset_verifications(asset_id, created_at DESC);

CREATE TABLE attestations (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  asset_id           uuid NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  party_name         text NOT NULL,
  party_role         text NOT NULL,
  party_email        text NOT NULL,
  relationship       text NOT NULL,
  allowed_classes    text[] NOT NULL CHECK (allowed_classes <@ ARRAY['P','A1']::text[] AND cardinality(allowed_classes) > 0),
  valid_from         date NOT NULL,
  valid_to           date NOT NULL,
  document_name      text,
  document_sha256    text,
  document_path      text,
  recorded_by        uuid NOT NULL REFERENCES users(id),
  revoked_at         timestamptz,
  created_at         timestamptz NOT NULL DEFAULT now(),
  CHECK (valid_to > valid_from AND valid_to <= valid_from + interval '12 months')
);

-- ---------- audit (append-only, hash-chained per org) ----------
CREATE TABLE audit_events (
  id            bigserial PRIMARY KEY,
  org_id        uuid,               -- null for pre-tenant events (e.g. failed login)
  seq           bigint NOT NULL,
  ts            timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_type    text NOT NULL CHECK (actor_type IN ('user','service','anonymous')),
  actor_id      text,
  actor_ip      text,
  action        text NOT NULL,
  target_type   text,
  target_id     text,
  outcome       text NOT NULL CHECK (outcome IN ('success','denied','error')),
  reason        text,
  request_id    text,
  details       jsonb NOT NULL DEFAULT '{}',
  prev_hash     text NOT NULL,
  hash          text NOT NULL,
  UNIQUE (org_id, seq)
);
CREATE UNIQUE INDEX audit_events_global_seq ON audit_events(seq) WHERE org_id IS NULL;

CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END $$;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

-- ---------- outbox & idempotency (ADR-003) ----------
CREATE TABLE outbox (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id       uuid NOT NULL,
  topic        text NOT NULL,
  business_key text NOT NULL,
  payload      jsonb NOT NULL,
  status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','done','dead')),
  attempts     int NOT NULL DEFAULT 0,
  available_at timestamptz NOT NULL DEFAULT now(),
  locked_until timestamptz,
  last_error   text,
  created_at   timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz
);
CREATE INDEX outbox_ready_idx ON outbox(status, available_at);

CREATE TABLE processed_messages (
  consumer     text NOT NULL,
  message_id   uuid NOT NULL,
  org_id       uuid NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (consumer, message_id)
);

-- ---------- row-level security ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['memberships','client_groups','member_client_groups','invites','assets',
                           'asset_verifications','attestations','outbox','processed_messages']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id())', t);
  END LOOP;
END $$;

ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON orgs USING (id = app_org_id()) WITH CHECK (id = app_org_id());

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_read ON audit_events FOR SELECT USING (org_id = app_org_id());
-- No INSERT policy: the app role writes only through append_audit() below.

-- Appends one event, computing seq and hash under a per-org advisory lock so the
-- chain is gapless under concurrency. hash = sha256(prev_hash || canonical(event)).
-- Tamper-evident, not tamper-proof (RS-AUDIT-002).
CREATE OR REPLACE FUNCTION audit_canonical(e audit_events) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT jsonb_build_object(
    'org_id', e.org_id, 'seq', e.seq, 'ts', to_char(e.ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'actor_type', e.actor_type, 'actor_id', e.actor_id, 'actor_ip', e.actor_ip,
    'action', e.action, 'target_type', e.target_type, 'target_id', e.target_id,
    'outcome', e.outcome, 'reason', e.reason, 'request_id', e.request_id, 'details', e.details)::text
$$;

CREATE OR REPLACE FUNCTION append_audit(
  p_actor_type text, p_actor_id text, p_actor_ip text, p_action text,
  p_target_type text, p_target_id text, p_outcome text, p_reason text,
  p_request_id text, p_details jsonb)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_org uuid := app_org_id();
  v_prev audit_events;
  e audit_events;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('audit:' || coalesce(v_org::text, 'global'), 0));
  SELECT * INTO v_prev FROM audit_events
    WHERE org_id IS NOT DISTINCT FROM v_org ORDER BY seq DESC LIMIT 1;
  e.org_id := v_org;
  e.seq := coalesce(v_prev.seq, 0) + 1;
  e.ts := date_trunc('microseconds', clock_timestamp());
  e.actor_type := p_actor_type; e.actor_id := p_actor_id; e.actor_ip := p_actor_ip;
  e.action := p_action; e.target_type := p_target_type; e.target_id := p_target_id;
  e.outcome := p_outcome; e.reason := p_reason; e.request_id := p_request_id;
  e.details := coalesce(p_details, '{}'::jsonb);
  e.prev_hash := coalesce(v_prev.hash, repeat('0', 64));
  e.hash := encode(digest(e.prev_hash || audit_canonical(e), 'sha256'), 'hex');
  INSERT INTO audit_events (org_id, seq, ts, actor_type, actor_id, actor_ip, action, target_type,
                            target_id, outcome, reason, request_id, details, prev_hash, hash)
  VALUES (e.org_id, e.seq, e.ts, e.actor_type, e.actor_id, e.actor_ip, e.action, e.target_type,
          e.target_id, e.outcome, e.reason, e.request_id, e.details, e.prev_hash, e.hash)
  RETURNING id INTO e.id;
  RETURN e.seq;
END $$;

-- Recomputes the chain for the current org; returns the first broken seq or null if intact.
CREATE OR REPLACE FUNCTION verify_audit_chain()
RETURNS TABLE (checked bigint, first_broken_seq bigint) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
  v_org uuid := app_org_id();
  r audit_events;
  v_prev text := repeat('0', 64);
  v_expect_seq bigint := 1;
  n bigint := 0;
BEGIN
  FOR r IN SELECT * FROM audit_events WHERE org_id IS NOT DISTINCT FROM v_org ORDER BY seq LOOP
    n := n + 1;
    IF r.seq <> v_expect_seq OR r.prev_hash <> v_prev
       OR r.hash <> encode(digest(r.prev_hash || audit_canonical(r), 'sha256'), 'hex') THEN
      checked := n; first_broken_seq := v_expect_seq; RETURN NEXT; RETURN;
    END IF;
    v_prev := r.hash; v_expect_seq := v_expect_seq + 1;
  END LOOP;
  checked := n; first_broken_seq := NULL; RETURN NEXT;
END $$;

-- ---------- SECURITY DEFINER helpers for the few cross-tenant lookups ----------
-- Orgs the given user is an active member of (org switcher).
CREATE OR REPLACE FUNCTION user_orgs(p_user uuid)
RETURNS TABLE (org_id uuid, name text, slug text, role member_role)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.id, o.name, o.slug, m.role
  FROM memberships m JOIN orgs o ON o.id = m.org_id
  WHERE m.user_id = p_user ORDER BY o.name
$$;

-- Resolve an invite token to its org without exposing other invites.
CREATE OR REPLACE FUNCTION invite_org(p_token_hash text)
RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id FROM invites WHERE token_hash = p_token_hash
$$;

-- Count orgs a user created (plan limit, RS-IAM-002).
CREATE OR REPLACE FUNCTION user_created_org_count(p_user uuid)
RETURNS int LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT count(*)::int FROM orgs WHERE created_by = p_user
$$;

CREATE OR REPLACE FUNCTION org_slug_taken(p_slug text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM orgs WHERE slug = p_slug)
$$;

-- Outbox claim for the relay worker: locks a batch across tenants.
CREATE OR REPLACE FUNCTION claim_outbox(p_limit int, p_lease_seconds int)
RETURNS SETOF outbox LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$
  UPDATE outbox SET status = 'processing', attempts = attempts + 1,
         locked_until = now() + make_interval(secs => p_lease_seconds)
  WHERE id IN (
    SELECT id FROM outbox
    WHERE (status = 'pending' AND available_at <= now())
       OR (status = 'processing' AND locked_until < now())
    ORDER BY available_at
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  )
  RETURNING *
$$;

-- Assets due for re-verification (scheduler), across tenants; returns ids only.
CREATE OR REPLACE FUNCTION assets_due_reverify()
RETURNS TABLE (org_id uuid, asset_id uuid) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT org_id, id FROM assets
  WHERE status IN ('verified','lapsed') AND next_reverify_at IS NOT NULL AND next_reverify_at <= now()
$$;

-- ---------- grants for runtime role ----------
GRANT USAGE ON SCHEMA public TO ruya_app;
GRANT SELECT, INSERT, UPDATE ON users, sessions TO ruya_app;
GRANT SELECT, INSERT, DELETE ON login_states TO ruya_app;
GRANT SELECT, INSERT, DELETE ON login_attempts TO ruya_app;
GRANT SELECT, INSERT, UPDATE ON orgs TO ruya_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON memberships, client_groups, member_client_groups, invites,
  assets, asset_verifications, attestations TO ruya_app;
GRANT SELECT, INSERT, UPDATE ON outbox TO ruya_app;
GRANT SELECT, INSERT ON processed_messages TO ruya_app;
GRANT SELECT ON audit_events TO ruya_app;   -- no INSERT/UPDATE/DELETE: writes via append_audit() only (RS-AUDIT-001)
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ruya_app;
REVOKE ALL ON FUNCTION append_audit, verify_audit_chain, user_orgs, invite_org, user_created_org_count, org_slug_taken, claim_outbox, assets_due_reverify FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app_org_id, append_audit, verify_audit_chain, user_orgs, invite_org, user_created_org_count, org_slug_taken, claim_outbox, assets_due_reverify TO ruya_app;
