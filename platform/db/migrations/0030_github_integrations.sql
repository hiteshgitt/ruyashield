-- GitHub repositories for safe apply: RuyaShield opens a pull request on a ruyashield/… branch and never merges.
-- token_enc holds the customer's fine-grained token (AES-GCM sealed, bound to org and integration id).
ALTER TABLE repository_integrations DROP CONSTRAINT IF EXISTS repository_integrations_type_check;
ALTER TABLE repository_integrations ADD CONSTRAINT repository_integrations_type_check CHECK (type IN ('local_git', 'github'));
ALTER TABLE repository_integrations ADD COLUMN IF NOT EXISTS token_enc text;
ALTER TABLE repository_integrations ADD CONSTRAINT repository_integrations_github_token CHECK (type <> 'github' OR token_enc IS NOT NULL);
