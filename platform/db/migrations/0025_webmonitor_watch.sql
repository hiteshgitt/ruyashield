-- Sites a connected WebMonitor account watches for uptime. WebMonitor's posture call already sends the host
-- names of every site it monitors; RuyaShield keeps the latest sighting so its dashboard can show which assets
-- are watched for uptime, and which WebMonitor sites are not in RuyaShield yet. Rows not seen for 30 days are
-- deleted on the next call.
CREATE TABLE webmonitor_watched_hosts (
  org_id        uuid NOT NULL REFERENCES orgs(id),
  host          text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
  token_id      uuid REFERENCES api_tokens(id),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, host)
);
CREATE INDEX webmonitor_watched_hosts_seen ON webmonitor_watched_hosts (org_id, last_seen_at DESC);

ALTER TABLE webmonitor_watched_hosts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON webmonitor_watched_hosts USING (org_id = app_org_id()) WITH CHECK (org_id = app_org_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON webmonitor_watched_hosts TO ruya_app;
