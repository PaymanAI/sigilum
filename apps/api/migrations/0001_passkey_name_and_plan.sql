-- Add name column to webauthn_credentials for user-facing passkey names.
ALTER TABLE webauthn_credentials ADD COLUMN name TEXT NOT NULL DEFAULT 'My Passkey';

-- Add plan-related columns to users.
ALTER TABLE users ADD COLUMN paid_until TEXT;
