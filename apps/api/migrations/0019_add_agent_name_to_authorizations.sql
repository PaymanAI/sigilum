-- Add optional agent display name captured at claim submission time.
ALTER TABLE authorizations ADD COLUMN agent_name TEXT;
