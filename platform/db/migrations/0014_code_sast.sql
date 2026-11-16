-- Scanner M4: risky code patterns in repository assets (native line rules, offline).
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('code.sast@1', 'code.sast', 1, 'P', 'native', 'Risky code patterns (SAST)',
  'Scans source files at the repository''s default branch for risky patterns in JavaScript/TypeScript, Python, PHP, Java, Go and Ruby: SQL and shell commands built from input, eval and unsafe deserialization, XSS sinks, disabled TLS verification, the JWT none algorithm, debug mode and weak crypto. Runs offline: no code leaves the box. Most results are marked suspected and need a human look; tests and fixtures are skipped.',
  60000, 0, true, true, 'Repository check. No egress. Line-based rules; no data-flow analysis. Opt out per line with ruya:ignore or nosemgrep.');
