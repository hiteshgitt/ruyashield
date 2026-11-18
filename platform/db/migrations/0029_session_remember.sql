-- "Keep me signed in on this device": a remembered session stays valid for 7 days without activity and 30 days in
-- total (others: 30 minutes and 12 hours). Sensitive actions still ask for a fresh authenticator code (step-up).
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS remember boolean NOT NULL DEFAULT false;
