-- Scanner M8: infrastructure-as-code misconfigurations and public blocklist lookups.
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('code.iac@1', 'code.iac', 1, 'P', 'native', 'Infrastructure as code',
  'Scans Terraform, Kubernetes manifests, Docker Compose files, Dockerfiles and GitHub Actions workflows at the repository''s default branch for risky settings: admin or database ports open to the internet, public buckets and databases, encryption switched off, wildcard IAM, privileged or root containers, mounted Docker sockets, curl-pipe-shell builds, secrets in ENV/ARG and workflow script injection. Runs offline: no code leaves the box. Tests, examples and vendored code are skipped.',
  60000, 0, true, true, 'Repository check. No egress. Line rules; opt out per line with ruya:ignore, tfsec:ignore or checkov:skip.'),
 ('web.blocklist@1', 'web.blocklist', 1, 'P', 'native', 'Malware / phishing blocklists',
  'Looks the host up in Google Safe Browsing and abuse.ch URLhaus (whichever has a key configured on the server). Being listed means browsers warn visitors away or the host has served malware. Only the host name and its home-page URL are sent to those services; nothing is sent to the site itself. Without a configured key the check reports an error, never "not listed".',
  30000, 0, true, true, 'P: third-party lookups only. Egress limited to safebrowsing.googleapis.com and urlhaus-api.abuse.ch. Keys: GOOGLE_SAFE_BROWSING_KEY, URLHAUS_AUTH_KEY.')
ON CONFLICT (id) DO NOTHING;
