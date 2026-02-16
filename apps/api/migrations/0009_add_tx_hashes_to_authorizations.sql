-- Add transaction hash columns for blockchain audit trail
ALTER TABLE authorizations ADD COLUMN approval_tx_hash TEXT;
ALTER TABLE authorizations ADD COLUMN revocation_tx_hash TEXT;

-- Add indexes for looking up authorizations by transaction hash
CREATE INDEX IF NOT EXISTS idx_authorizations_approval_tx ON authorizations(approval_tx_hash);
CREATE INDEX IF NOT EXISTS idx_authorizations_revocation_tx ON authorizations(revocation_tx_hash);
