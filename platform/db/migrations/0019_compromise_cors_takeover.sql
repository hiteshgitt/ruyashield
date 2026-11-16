-- Scanner M7: passive compromise indicators, CORS policy, subdomain takeover.
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('http.compromise@1', 'http.compromise', 1, 'A1', 'native', 'Signs of compromise',
  'Fetches the home page twice (once as RuyaShield, once with a search-engine crawler User-Agent) and looks for common signs of tampering: hidden iframes, scripts from bare IP addresses or throwaway TLDs, obfuscated inline JavaScript, browser crypto-miners, search-engine referrer redirects, and spam keywords that are hidden or shown only to crawlers. Lists every external script host. External scripts are never downloaded and nothing is executed. At most 64 KB per page is read; evidence holds hosts, pattern names and a SHA-256, never page content. Heuristic: no signs is not proof of a clean site.',
  60000, 2, true, true, 'A1: two plain GET requests of the home page, no payloads.'),
 ('http.cors@1', 'http.cors', 1, 'A1', 'native', 'CORS policy',
  'Fetches the home page twice with an Origin header (a random unregistrable .invalid origin, then "null") and reads Access-Control-Allow-Origin and Access-Control-Allow-Credentials. Reports a policy that trusts any origin or the null origin, rated high when credentials are allowed. Reads at most 512 bytes of body. Only the home page is tested.',
  60000, 2, true, true, 'A1: two plain GET requests with an Origin header.'),
 ('dns.takeover@1', 'dns.takeover', 1, 'A1', 'native', 'Subdomain takeover',
  'Follows the host''s own CNAME chain (at most five links). Reports a chain ending in a name that does not exist, and, when the alias points at a hosting service where unclaimed names can be taken (GitHub Pages, Heroku, S3, Azure, Shopify and others), one GET of the home page matched against that service''s "nothing here" page. Reads at most 512 bytes. Never tries to claim anything.',
  60000, 1, true, true, 'P + A1: DNS lookups of the verified host''s CNAME chain and at most one GET.')
ON CONFLICT (id) DO NOTHING;
