-- Scanner M3: exposed network services (TCP connect scan, class A2).
-- A2 is off for every org until two different admins turn it on (scope.enable_a2 is a two-person action).
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS allow_intrusive_network boolean NOT NULL DEFAULT false;
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS intrusive_network_requested_by uuid;
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS intrusive_network_requested_at timestamptz;

INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('net.exposed_services@1', 'net.exposed_services', 1, 'A2', 'native', 'Exposed services / ports',
  'Opens a plain TCP connection to a fixed list of 26 well-known service ports (databases, remote desktop, container and cache admin ports, mail, file sharing) to see which ones accept connections from the internet. Sends nothing; reads at most 256 bytes of a greeting the server sends on its own. At most 5 connections per second, one host at a time, at most once per hour per asset. Requires the organization to opt in to intrusive network checks.',
  60000, 26, true, true, 'A2: connect-only. No payloads, no login attempts, no service fingerprinting beyond the server-sent banner.')
ON CONFLICT (id) DO NOTHING;
