-- Add blockchain transaction hash fields for audit trail
ALTER TABLE users ADD COLUMN registration_tx_hash TEXT;

-- Index for looking up users by their registration transaction
CREATE INDEX IF NOT EXISTS idx_users_registration_tx ON users(registration_tx_hash);
