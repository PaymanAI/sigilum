-- Add submission_tx_hash column to track blockchain claim submissions
ALTER TABLE authorizations ADD COLUMN submission_tx_hash TEXT;

-- Create index for efficient lookups by TX hash
CREATE INDEX IF NOT EXISTS idx_authorizations_submission_tx ON authorizations(submission_tx_hash);
