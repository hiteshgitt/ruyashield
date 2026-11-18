-- web.technology@1: what a site is built with (platform, framework, PHP, server, CDN, jQuery) from one request to
-- the home page, plus findings for WordPress behind the current release, end-of-life PHP and jQuery < 3.5.
INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('web.technology@1', 'web.technology', 1, 'A1', 'native', 'Technology and versions',
  'Fetches the home page once and reads its headers, cookies, generator tag and script paths to identify the platform (WordPress, Drupal, Joomla, Shopify...), framework (Next.js, Laravel, Django...), PHP version, web server and CDN, and jQuery. Reports WordPress older than the current release (from api.wordpress.org, which receives nothing about the site), PHP versions past end of life, and jQuery older than 3.5 (CVE-2020-11022/11023). Nothing is executed and no other path is requested; at most 256 KB is read. Versions that are not shown publicly cannot be judged.',
  60000, 1, true, true, 'A1: one plain GET of the home page, no payloads.')
ON CONFLICT (id) DO NOTHING;
