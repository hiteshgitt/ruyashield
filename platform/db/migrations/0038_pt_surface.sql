-- Automated penetration test, step 1: pt.surface (class A1, ordinary GETs, no payloads).
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('pt.surface@1', 'pt.surface', 1, 'A1', 'native', 'Penetration test: attack surface',
  'Looks for what an attacker checks first, with ordinary GET requests only: phpinfo pages, Apache server-status, .DS_Store, wp-config backups, SQL dumps, backup archives, PHP error logs, .htpasswd, Subversion metadata and database admin tools (phpMyAdmin, Adminer). On WordPress sites also an unfinished installation anyone could complete, usernames listed by the REST API or ?author= redirects, XML-RPC, and the login page over plain HTTP. No payloads, no passwords, redirects not followed, at most 4 KB read per response, and no file contents stored. A random path is fetched first so catch-all pages are not reported.',
  90000, 40, true, true, 'A1: about 35 plain GET requests, no payloads, no credential use.')
ON CONFLICT (id) DO NOTHING;
