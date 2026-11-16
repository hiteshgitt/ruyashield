-- Newly issued recovery codes waiting to be shown once. Kept sealed (RUYA_SECRETS_KEY) for 15 minutes so the
-- page that displays them is rendered by the server and survives the reload Next.js does after sign-in.
CREATE TABLE mfa_recovery_reveals (
  user_id     uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  codes       text NOT NULL,
  return_to   text NOT NULL DEFAULT '/',
  created_at  timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_recovery_reveals TO ruya_app;
