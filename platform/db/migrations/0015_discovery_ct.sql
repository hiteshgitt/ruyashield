-- Scanner M5: Certificate Transparency discovery (class P: the target is never contacted).
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('discovery.ct@1', 'discovery.ct', 1, 'P', 'native', 'Certificate Transparency discovery',
  'Looks the domain up in public Certificate Transparency logs (crt.sh, with Cert Spotter as fallback) to list subdomains that have had certificates issued, and compares the issuing CAs with the domain''s CAA records. Never contacts the target. Results are cached for 24 hours. Discovered subdomains are offered as suggested assets; they are not scanned until added and verified.',
  60000, 0, true, true, 'P: third-party CT log APIs and a CAA lookup only.')
ON CONFLICT (id) DO NOTHING;

-- Global cache of CT log answers per domain (public data, not tenant data), so repeat scans do not hit the CT APIs.
CREATE TABLE IF NOT EXISTS ct_cache (
  domain text PRIMARY KEY,
  source text NOT NULL,
  fetched_at timestamptz NOT NULL,
  truncated boolean NOT NULL DEFAULT false,
  entries jsonb NOT NULL
);
GRANT SELECT, INSERT, UPDATE ON ct_cache TO ruya_app;

-- Subdomains found by discovery, waiting for someone to add (and then verify) or dismiss them.
CREATE TABLE IF NOT EXISTS asset_suggestions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
  source_asset_id uuid REFERENCES assets(id) ON DELETE SET NULL,
  host text NOT NULL,
  source text NOT NULL DEFAULT 'ct',
  status text NOT NULL DEFAULT 'suggested' CHECK (status IN ('suggested','added','dismissed')),
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  decided_by uuid,
  decided_at timestamptz,
  UNIQUE (org_id, host)
);
ALTER TABLE asset_suggestions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON asset_suggestions USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id());
GRANT SELECT, INSERT, UPDATE ON asset_suggestions TO ruya_app;
