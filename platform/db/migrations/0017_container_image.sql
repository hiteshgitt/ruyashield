-- container.image@1 (scanner step 3): known vulnerabilities in Dockerfile base images.
-- Image inventory needs more than the original 60 s ceiling (layer downloads); allow up to 5 minutes.
ALTER TABLE check_definitions DROP CONSTRAINT check_definitions_timeout_ms_check;
ALTER TABLE check_definitions ADD CONSTRAINT check_definitions_timeout_ms_check CHECK (timeout_ms BETWEEN 1000 AND 300000);

INSERT INTO check_definitions (id, check_key, version, class, engine, title, description, timeout_ms, request_budget, verification_supported, enabled, notes) VALUES
 ('container.image@1', 'container.image', 1, 'P', 'native', 'Container base image vulnerabilities',
  'Reads the FROM lines of the repository''s Dockerfiles, lists the packages in each base image with syft (read straight from a public registry, anonymously; nothing is executed and no container is started), and looks them up in OSV.dev. Images on private or non-allowlisted registries are reported as not scanned and never contacted.',
  300000, 0, true, true, 'Repository check. Egress: anonymous pulls of public image layers plus OSV lookups ({ecosystem, name, version} only). Fails closed if syft is missing or any pull/lookup fails.')
ON CONFLICT (id) DO NOTHING;
