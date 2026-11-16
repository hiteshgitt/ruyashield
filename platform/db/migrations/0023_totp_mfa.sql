-- Built-in multi-factor authentication (RFC 6238 authenticator codes) on top of Google sign-in.
-- Google's ID token does not say whether 2-step verification was used, so RuyaShield asks for its own code.
-- Every OIDC sign-in ends in a pending login; a session exists only after the code is verified.

-- One authenticator per user. secret is sealed with RUYA_SECRETS_KEY (AES-256-GCM, user id as associated data).
-- enabled_at is null while enrollment is unconfirmed. last_step blocks reusing a code within its 30 s window.
CREATE TABLE user_mfa (
  user_id     uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  secret      text NOT NULL,
  enabled_at  timestamptz,
  last_step   bigint NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now()
);

-- Ten single-use recovery codes, shown once at enrollment; only their SHA-256 is stored.
CREATE TABLE mfa_recovery_codes (
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  text NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, code_hash)
);

-- Between "Google said who you are" and "you entered your code". 10 minute TTL, at most 5 wrong codes.
CREATE TABLE pending_logins (
  token_hash  text PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amr         text[] NOT NULL DEFAULT '{}',
  issuer      text NOT NULL,
  return_to   text NOT NULL DEFAULT '/',
  attempts    integer NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX pending_logins_created_idx ON pending_logins(created_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_mfa, mfa_recovery_codes, pending_logins TO ruya_app;
