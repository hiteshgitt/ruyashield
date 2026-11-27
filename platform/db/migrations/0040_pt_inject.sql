-- Automated penetration test, step 3: pt.inject (class A2, detection only). Verified owners with intrusive checks on.
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('pt.inject@1', 'pt.inject', 1, 'A2', 'native', 'Penetration test: SQL injection and path traversal',
  'Detection only. Crawls the site like the reflected-XSS test (same host, GET only, state-changing paths and parameters skipped), then for each parameter (at most 20): adds a single quote and looks for a database error the normal page does not show; for numeric parameters compares "AND 1=1" with "AND 1=2" on a page that is stable across two loads; for file-like parameters asks for /etc/passwd through ../ sequences and checks only for its signature. No time delays, no UNION or data extraction, nothing that writes, file contents never stored, at most five requests a second.',
  300000, 180, true, true, 'A2: crawl plus at most 7 GETs per parameter. Verified owners with intrusive checks enabled only.')
ON CONFLICT (id) DO NOTHING;
