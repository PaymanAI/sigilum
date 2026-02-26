-- Separate requester subject from AI agent identity metadata.
ALTER TABLE authorizations ADD COLUMN subject TEXT;
ALTER TABLE authorizations ADD COLUMN agent_id TEXT;

CREATE INDEX IF NOT EXISTS idx_authorizations_subject ON authorizations(namespace, subject, status);
CREATE INDEX IF NOT EXISTS idx_authorizations_agent_id ON authorizations(namespace, service, agent_id, status);
