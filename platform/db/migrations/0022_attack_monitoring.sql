-- Attack-origin monitoring: where hostile traffic against a verified asset comes from.
-- Sources: Cloudflare firewall events (pulled with the customer's read-only token) and a log agent that pushes
-- suspicious lines from the customer's own web server. Only suspicious events are stored (visitor IPs are personal
-- data); query strings are stripped before storage; events are purged after 90 days (legal hold orgs excepted).

CREATE TABLE attack_sources (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid NOT NULL REFERENCES orgs(id),
  asset_id           uuid NOT NULL REFERENCES assets(id),
  kind               text NOT NULL CHECK (kind IN ('cloudflare','log_agent')),
  name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
  cf_zone_id         text CHECK (cf_zone_id IS NULL OR cf_zone_id ~ '^[a-f0-9]{32}$'),
  cf_token_enc       text,
  ingest_token_hash  text UNIQUE,
  ingest_prefix      text,
  status             text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','error','disabled')),
  cursor_at          timestamptz,
  next_poll_at       timestamptz,
  last_polled_at     timestamptz,
  last_event_at      timestamptz,
  last_error         text,
  created_by         uuid NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'cloudflare' AND cf_zone_id IS NOT NULL AND cf_token_enc IS NOT NULL AND ingest_token_hash IS NULL)
      OR (kind = 'log_agent' AND ingest_token_hash IS NOT NULL AND cf_zone_id IS NULL AND cf_token_enc IS NULL))
);
CREATE INDEX attack_sources_org ON attack_sources (org_id, asset_id);

CREATE TABLE attack_events (
  id           bigserial PRIMARY KEY,
  org_id       uuid NOT NULL REFERENCES orgs(id),
  asset_id     uuid NOT NULL REFERENCES assets(id),
  source_id    uuid NOT NULL REFERENCES attack_sources(id),
  occurred_at  timestamptz NOT NULL,
  ip           text NOT NULL CHECK (length(ip) <= 45),
  country      text CHECK (country IS NULL OR country ~ '^[A-Z]{2}$'),
  asn          integer,
  as_org       text CHECK (as_org IS NULL OR length(as_org) <= 120),
  action       text NOT NULL CHECK (length(action) <= 40),
  attack_type  text NOT NULL CHECK (length(attack_type) <= 40),
  rule_id      text CHECK (rule_id IS NULL OR length(rule_id) <= 80),
  method       text CHECK (method IS NULL OR length(method) <= 10),
  path         text CHECK (path IS NULL OR length(path) <= 300),
  status_code  integer,
  user_agent   text CHECK (user_agent IS NULL OR length(user_agent) <= 200),
  dedupe_key   text NOT NULL CHECK (length(dedupe_key) <= 128),
  created_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (source_id, dedupe_key)
);
CREATE INDEX attack_events_org_time ON attack_events (org_id, occurred_at DESC);
CREATE INDEX attack_events_asset_time ON attack_events (org_id, asset_id, occurred_at DESC);

DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['attack_sources','attack_events'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id())', t);
END LOOP; END $$;

GRANT SELECT, INSERT, UPDATE ON attack_sources TO ruya_app;
GRANT SELECT, INSERT ON attack_events TO ruya_app;
GRANT USAGE ON SEQUENCE attack_events_id_seq TO ruya_app;

-- The ingest endpoint knows only the token hash, not the org, before it can open an org transaction.
CREATE OR REPLACE FUNCTION attack_source_by_ingest_hash(p_hash text)
RETURNS TABLE (org_id uuid, source_id uuid, asset_id uuid, status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT s.org_id, s.id, s.asset_id, s.status FROM attack_sources s
  WHERE s.kind = 'log_agent' AND s.ingest_token_hash = p_hash
$$;

-- Cloudflare sources due a poll, across orgs. The worker leases each row inside its org transaction.
CREATE OR REPLACE FUNCTION attack_sources_due_poll()
RETURNS TABLE (org_id uuid, source_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT s.org_id, s.id FROM attack_sources s JOIN orgs o ON o.id = s.org_id
  WHERE s.kind = 'cloudflare' AND s.status IN ('pending','active','error')
    AND (s.next_poll_at IS NULL OR s.next_poll_at <= now()) AND o.deleted_at IS NULL
  ORDER BY s.next_poll_at NULLS FIRST LIMIT 50
$$;

-- 90-day retention for visitor IPs (personal data). Legal hold orgs are skipped.
CREATE OR REPLACE FUNCTION attack_events_purge_at(p_now timestamptz)
RETURNS TABLE (purged_org uuid, n_events bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public AS $$
BEGIN
  RETURN QUERY
  WITH d AS (
    DELETE FROM attack_events e USING orgs o
    WHERE o.id = e.org_id AND NOT o.legal_hold AND e.occurred_at < p_now - interval '90 days'
    RETURNING e.org_id)
  SELECT d.org_id, count(*)::bigint FROM d GROUP BY d.org_id;
END $$;

CREATE OR REPLACE FUNCTION attack_events_purge()
RETURNS TABLE (purged_org uuid, n_events bigint)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public AS $$ SELECT * FROM attack_events_purge_at(now()) $$;

REVOKE ALL ON FUNCTION attack_source_by_ingest_hash, attack_sources_due_poll, attack_events_purge_at, attack_events_purge FROM PUBLIC;
GRANT EXECUTE ON FUNCTION attack_source_by_ingest_hash, attack_sources_due_poll, attack_events_purge TO ruya_app;
