-- WebMonitor package reports: vulnerable npm / Composer packages that a site's WebMonitor integration reported
-- (looked up in OSV.dev by WebMonitor). Sent server to server with the shared, signed handoff secret, and only for
-- WebMonitor customers who connected RuyaShield. Keyed by host, holding no organization data: the
-- webmonitor.packages check reads it only while assessing an asset whose ownership the organization verified.
CREATE TABLE webmonitor_package_reports (
  host         text PRIMARY KEY,
  ecosystem    text NOT NULL CHECK (ecosystem IN ('npm', 'packagist')),
  packages     jsonb NOT NULL,
  observed_at  timestamptz NOT NULL,
  received_at  timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON webmonitor_package_reports TO ruya_app;

INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('webmonitor.packages@1', 'webmonitor.packages', 1, 'P', 'native', 'Vulnerable packages (from WebMonitor)',
  'Reads the latest package report from the site''s WebMonitor integration: installed npm and Composer packages with known vulnerabilities in OSV.dev (GitHub advisories), each with its CVE, severity and the version that fixes it. Sends nothing and makes no request to the site. Sites without a WebMonitor report have nothing to check; a report older than three days is an error rather than a result, so findings are only closed by fresh data.',
  10000, 0, true, true, 'P: no network; reads a stored report.')
ON CONFLICT (id) DO NOTHING;
