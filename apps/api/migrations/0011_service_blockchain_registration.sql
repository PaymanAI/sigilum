-- Add blockchain registration field to services table
-- registration_tx_hash IS NOT NULL means service is registered on-chain
ALTER TABLE services ADD COLUMN registration_tx_hash TEXT;
