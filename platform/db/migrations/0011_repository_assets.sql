-- Scanner M1: repository assets + dependency CVE scanning (deps.osv).
-- A repository asset is linked 1:1 to a repository integration. It reuses findings, lifecycle,
-- re-tests and reporting unchanged. Ownership is established by the admin connecting the repo
-- (integration.manage), so it skips DNS/HTTP verification; disabling the integration lapses it.

ALTER TABLE repository_integrations ADD CONSTRAINT repository_integrations_org_id_id_key UNIQUE (org_id, id);

ALTER TABLE assets DROP CONSTRAINT assets_kind_check;
ALTER TABLE assets
  ADD CONSTRAINT assets_kind_check CHECK (kind IN ('domain','repository')),
  ADD COLUMN repository_integration_id uuid,
  ADD CONSTRAINT assets_repository_integration_fkey FOREIGN KEY (org_id, repository_integration_id)
      REFERENCES repository_integrations(org_id, id),
  ADD CONSTRAINT assets_repository_link CHECK ((kind = 'repository') = (repository_integration_id IS NOT NULL)),
  -- Repository hosts live in their own namespace so they never collide with a domain or reach the network.
  ADD CONSTRAINT assets_repository_host CHECK ((kind = 'repository') = (host LIKE 'repo:%'));
CREATE UNIQUE INDEX assets_repository_integration_uniq ON assets (repository_integration_id) WHERE repository_integration_id IS NOT NULL;

INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('deps.osv@1', 'deps.osv', 1, 'P', 'native', 'Dependency vulnerabilities (OSV)',
  'Reads lockfiles at the repository''s default branch and looks up each pinned package version in the OSV.dev advisory database. Only ecosystem, package name and version leave the box; no code is sent.',
  30000, 0, true, true, 'Repository check. Egress is limited to api.osv.dev.');
