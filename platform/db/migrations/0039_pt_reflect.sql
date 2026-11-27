-- Automated penetration test, step 2: pt.reflect (class A2). Runs only on ownership-verified hosts of organizations
-- that turned on intrusive network checks (two-person opt-in); attestation never grants A2.
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('pt.reflect@1', 'pt.reflect', 1, 'A2', 'native', 'Penetration test: reflected XSS and open redirects',
  'Crawls the site (same host, GET only, at most 30 pages, two levels deep) and collects links and GET forms with parameters, skipping anything that could change state (logout, delete, cart, checkout, account, admin, login, nonces and tokens). Each parameter, one at a time, gets a harmless text marker with a made-up tag and no script; a finding needs that tag back unescaped in an HTML page. Redirect-like parameters also get a reserved, unreachable test domain; a finding needs a redirect to it. Redirects are never followed, nothing is posted, no credentials are used, and requests are spaced at most five a second.',
  240000, 90, true, true, 'A2: crawl plus one marker request per parameter (at most 25), and one redirect probe for redirect-like parameters. Verified owners with intrusive checks enabled only.')
ON CONFLICT (id) DO NOTHING;
