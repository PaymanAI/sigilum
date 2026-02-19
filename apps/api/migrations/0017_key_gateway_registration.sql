-- Track which API key is registered with the gateway.
ALTER TABLE service_api_keys ADD COLUMN gateway_registered_at TEXT;
