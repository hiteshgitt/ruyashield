-- Scanner M6: TLS configuration (protocol versions, weak ciphers, key size, chain) and exposed-file probes.
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('tls.config@1', 'tls.config', 1, 'A1', 'native', 'TLS configuration',
  'Performs six ordinary TLS handshakes with the server: one default, one pinned to each of TLS 1.0, 1.1, 1.2 and 1.3, and one offering only weak (NULL / anonymous) cipher suites. Reports legacy protocol versions, weak ciphers, RSA keys under 2048 bits, a missing intermediate certificate and missing TLS 1.3. No HTTP request is sent. RC4, 3DES, DES and EXPORT suites cannot be offered by the scanner''s TLS library and are recorded as untestable.',
  60000, 8, true, true, 'A1: six TLS handshakes to port 443, no application data.'),
 ('http.exposure@1', 'http.exposure', 1, 'A1', 'native', 'Exposed files',
  'Requests /.git/HEAD, /.env and a few common folders (/, /uploads/, /images/, /static/, /assets/, /backup/) to detect a downloadable Git repository, a readable environment file or directory listings. Reads at most 512 bytes per response and never stores file contents: only status, content type, byte count and a SHA-256 of the prefix. A random path is fetched first so catch-all pages are not reported. Redirects are not followed.',
  60000, 12, true, true, 'A1: nine plain GET requests, no payloads, no credential use.')
ON CONFLICT (id) DO NOTHING;
