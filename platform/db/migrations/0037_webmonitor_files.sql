-- Suspicious-file reports from WebMonitor's read-only scanner (PHP in uploads, backdoors / web shells, injected code,
-- modified WordPress core), sent signed server to server for customers who connected RuyaShield. Keyed by host and
-- used only by the webmonitor.files check while assessing an asset whose ownership the organization verified.
CREATE TABLE webmonitor_file_reports (
  host         text PRIMARY KEY,
  findings     jsonb NOT NULL,
  complete     boolean NOT NULL,          -- from a complete scan pass (the list is the whole truth)
  observed_at  timestamptz NOT NULL,
  received_at  timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON webmonitor_file_reports TO ruya_app;

INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('webmonitor.files@1', 'webmonitor.files', 1, 'P', 'native', 'Suspicious files (from WebMonitor)',
  'Reads the latest report from the site''s WebMonitor file scan, which runs read-only inside the site: PHP files in upload folders, known backdoor and web-shell code, request input reaching eval or shell functions, obfuscated or injected code, and WordPress core files that differ from the official release, each with file and line. Makes no request to the site. Sites without a WebMonitor report have nothing to check; a report older than three days is an error, so findings are only closed by fresh data.',
  10000, 0, true, true, 'P: no network; reads a stored report.')
ON CONFLICT (id) DO NOTHING;
