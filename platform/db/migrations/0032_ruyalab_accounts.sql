-- One Ruya Lab account (accounts.ruyalab.com): which identity provider a sign-in started with, and the Ruya Lab
-- subject linked to a RuyaShield user. Linking happens only through a verified email; the authenticator code
-- step still follows every Ruya Lab sign-in.
ALTER TABLE login_states ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT 'oidc' CHECK (provider IN ('oidc', 'ruyalab'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS ruyalab_sub text;
CREATE UNIQUE INDEX IF NOT EXISTS users_ruyalab_sub ON users (ruyalab_sub) WHERE ruyalab_sub IS NOT NULL;
