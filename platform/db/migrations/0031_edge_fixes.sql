-- Safe apply at the edge: security headers set by one RuyaShield-owned Cloudflare Transform Rule per website.
-- The token (Zone Read + Transform Rules Edit on one zone) is sealed, bound to org and row id. Applying needs a
-- fresh MFA sign-in; every apply and undo is audited.
CREATE TABLE edge_connections (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL REFERENCES orgs(id),
  asset_id         uuid NOT NULL REFERENCES assets(id),
  provider         text NOT NULL DEFAULT 'cloudflare' CHECK (provider IN ('cloudflare')),
  zone_id          text NOT NULL CHECK (zone_id ~ '^[a-f0-9]{32}$'),
  zone_name        text NOT NULL,
  token_enc        text NOT NULL,
  status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  applied_fixes    text[],
  applied_at       timestamptz,
  applied_by       uuid,
  last_error       text,
  created_by       uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX edge_connections_one_active ON edge_connections (org_id, asset_id) WHERE status = 'active';
ALTER TABLE edge_connections ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON edge_connections USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id());
GRANT SELECT, INSERT, UPDATE ON edge_connections TO ruya_app;
