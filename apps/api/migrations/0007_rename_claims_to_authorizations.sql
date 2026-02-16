-- Rename claims table to authorizations.
ALTER TABLE claims RENAME TO authorizations;

-- Recreate indexes with new table name
DROP INDEX IF EXISTS idx_claims_namespace;
DROP INDEX IF EXISTS idx_claims_status;
CREATE INDEX IF NOT EXISTS idx_authorizations_namespace ON authorizations(namespace);
CREATE INDEX IF NOT EXISTS idx_authorizations_status ON authorizations(status);
CREATE INDEX IF NOT EXISTS idx_authorizations_service ON authorizations(namespace, service, status);
