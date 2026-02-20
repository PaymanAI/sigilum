-- Scope service slug uniqueness to owner_user_id instead of global slug.
-- This allows each namespace/account to register standard provider slugs
-- (for example "sigilum-secure-linear") without cross-account conflicts.

PRAGMA foreign_keys=OFF;

CREATE TABLE IF NOT EXISTS services_new (
  id TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  domain TEXT,
  description TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT,
  registration_tx_hash TEXT
);

INSERT INTO services_new (
  id,
  owner_user_id,
  name,
  slug,
  domain,
  description,
  created_at,
  updated_at,
  registration_tx_hash
)
SELECT
  id,
  owner_user_id,
  name,
  slug,
  domain,
  description,
  created_at,
  updated_at,
  registration_tx_hash
FROM services;

DROP TABLE services;
ALTER TABLE services_new RENAME TO services;

CREATE UNIQUE INDEX IF NOT EXISTS idx_services_owner_slug ON services(owner_user_id, slug);
CREATE INDEX IF NOT EXISTS idx_services_owner ON services(owner_user_id);
CREATE INDEX IF NOT EXISTS idx_services_slug ON services(slug);

PRAGMA foreign_keys=ON;
