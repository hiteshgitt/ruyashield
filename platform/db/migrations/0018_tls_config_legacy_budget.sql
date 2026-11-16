-- tls.config@1 now also probes RC4, 3DES, DES and EXPORT with the bundled legacy OpenSSL client (bin/openssl-legacy).
-- That is 10 handshakes per run: default, TLS 1.0, 1.1, 1.2, 1.3, weak (NULL / anonymous) and one per legacy family.
UPDATE check_definitions SET
  request_budget = 10,
  description = 'Performs up to ten ordinary TLS handshakes with the server: one default, one pinned to each of TLS 1.0, 1.1, 1.2 and 1.3, one offering only weak (NULL / anonymous) cipher suites, and one each offering only RC4, 3DES, DES or EXPORT suites (via a bundled legacy OpenSSL client over IPv4). Reports legacy protocol versions, weak ciphers, RSA keys under 2048 bits, a missing intermediate certificate and missing TLS 1.3. No HTTP request or application data is sent. A cipher family the client cannot test is reported as untestable, never as refused.',
  notes = 'A1: up to ten TLS handshakes to port 443, no application data.'
WHERE id = 'tls.config@1';
