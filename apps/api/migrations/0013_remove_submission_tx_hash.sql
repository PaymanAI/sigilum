-- Remove submission_tx_hash column and its index from authorizations table
DROP INDEX IF EXISTS idx_authorizations_submission_tx;
ALTER TABLE authorizations DROP COLUMN submission_tx_hash;
