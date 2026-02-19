-- Services: registered services that interact with Sigilum via API.
CREATE TABLE IF NOT EXISTS services (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  domain TEXT,
  description TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_services_owner ON services(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_services_slug ON services(slug);

-- Service API keys: hashed keys for authenticating service requests.
CREATE TABLE IF NOT EXISTS service_api_keys (
  id TEXT PRIMARY KEY,
  service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  name TEXT NOT NULL DEFAULT 'Default',
  key_prefix TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_service_api_keys_service ON service_api_keys(service_id);
CREATE INDEX IF NOT EXISTS idx_service_api_keys_hash ON service_api_keys(key_hash);
