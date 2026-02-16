-- Add optional auth header fields so Sigilum can pass a custom header when calling webhooks.
ALTER TABLE webhooks ADD COLUMN auth_header_name TEXT;
ALTER TABLE webhooks ADD COLUMN auth_header_value TEXT;
