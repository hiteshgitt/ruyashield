-- Scanner M2: hard-coded secrets in repository assets (native rules, offline).
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('code.secrets@1', 'code.secrets', 1, 'P', 'native', 'Leaked secrets in code',
  'Scans the files at the repository''s default branch for hard-coded credentials (cloud, payment and API keys, tokens, private keys, and high-entropy values assigned to secret-like names). Runs offline: nothing leaves the box, and found keys are never tried. Only a hash, the first 4 characters and the length of each value are stored.',
  30000, 0, true, true, 'Repository check. No egress. Working tree only; git history is not scanned.');
