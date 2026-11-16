-- 1. "Request Pro" from the plan page: shown to operators in the operator console.
ALTER TABLE orgs ADD COLUMN pro_requested_at timestamptz, ADD COLUMN pro_requested_by uuid;

DROP FUNCTION operator_org_list();
CREATE FUNCTION operator_org_list()
RETURNS TABLE (id uuid, name text, slug text, plan text, created_at timestamptz, members bigint, pro_requested_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT o.id, o.name, o.slug, o.plan, o.created_at,
    (SELECT count(*) FROM memberships m WHERE m.org_id = o.id), o.pro_requested_at
  FROM orgs o WHERE o.deleted_at IS NULL ORDER BY o.pro_requested_at DESC NULLS LAST, o.created_at DESC
$$;
REVOKE ALL ON FUNCTION operator_org_list FROM PUBLIC;
GRANT EXECUTE ON FUNCTION operator_org_list TO ruya_app;

-- 2. Email + password sign-in, alongside Google. Accounts use idp_issuer 'password' and idp_subject = email.
-- An email address must be verified (link sent by email) before the account can sign in; every sign-in then
-- continues to the authenticator-code step, exactly like Google sign-ins.
ALTER TABLE users ADD COLUMN email_verified_at timestamptz;
UPDATE users SET email_verified_at = created_at WHERE idp_issuer <> 'password';

-- scrypt hash with its parameters and salt: "scrypt$N$r$p$saltB64$hashB64".
CREATE TABLE password_credentials (
  user_id     uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  hash        text NOT NULL CHECK (hash LIKE 'scrypt$%'),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

-- One-time links sent by email; only the SHA-256 of the token is stored.
CREATE TABLE email_tokens (
  token_hash  text PRIMARY KEY,
  user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose     text NOT NULL CHECK (purpose IN ('verify', 'reset')),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX email_tokens_user ON email_tokens (user_id, purpose);

GRANT SELECT, INSERT, UPDATE, DELETE ON password_credentials, email_tokens TO ruya_app;
