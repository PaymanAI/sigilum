-- Local claims table for development and testing.
-- In production, claims are read from the on-chain indexer (Ponder).
CREATE TABLE IF NOT EXISTS claims (
  claim_id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  service TEXT NOT NULL,
  public_key TEXT NOT NULL,
  agent_ip TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  approved_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_claims_namespace ON claims(namespace);
CREATE INDEX IF NOT EXISTS idx_claims_status ON claims(status);
