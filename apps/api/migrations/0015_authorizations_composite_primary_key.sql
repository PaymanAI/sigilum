-- Enforce one authorization row per (namespace, service, public_key).
-- This prevents duplicate pending rows for the same agent key.

PRAGMA foreign_keys = OFF;

CREATE TABLE IF NOT EXISTS authorizations_new (
  namespace TEXT NOT NULL,
  service TEXT NOT NULL,
  public_key TEXT NOT NULL,
  claim_id TEXT NOT NULL UNIQUE,
  agent_ip TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  approved_at TEXT,
  revoked_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  approval_tx_hash TEXT,
  revocation_tx_hash TEXT,
  PRIMARY KEY (namespace, service, public_key)
);

INSERT INTO authorizations_new (
  namespace,
  service,
  public_key,
  claim_id,
  agent_ip,
  status,
  approved_at,
  revoked_at,
  created_at,
  approval_tx_hash,
  revocation_tx_hash
)
SELECT
  namespace,
  service,
  public_key,
  claim_id,
  agent_ip,
  status,
  approved_at,
  revoked_at,
  created_at,
  approval_tx_hash,
  revocation_tx_hash
FROM (
  SELECT
    namespace,
    service,
    public_key,
    claim_id,
    agent_ip,
    status,
    approved_at,
    revoked_at,
    created_at,
    approval_tx_hash,
    revocation_tx_hash,
    ROW_NUMBER() OVER (
      PARTITION BY namespace, service, public_key
      ORDER BY
        CASE status
          WHEN 'approved' THEN 0
          WHEN 'pending' THEN 1
          WHEN 'revoked' THEN 2
          WHEN 'rejected' THEN 3
          WHEN 'expired' THEN 4
          ELSE 5
        END,
        created_at DESC,
        claim_id DESC
    ) AS rn
  FROM authorizations
)
WHERE rn = 1;

DROP TABLE authorizations;
ALTER TABLE authorizations_new RENAME TO authorizations;

CREATE INDEX IF NOT EXISTS idx_authorizations_namespace ON authorizations(namespace);
CREATE INDEX IF NOT EXISTS idx_authorizations_status ON authorizations(status);
CREATE INDEX IF NOT EXISTS idx_authorizations_service ON authorizations(namespace, service, status);
CREATE INDEX IF NOT EXISTS idx_authorizations_service_status ON authorizations(service, status);
CREATE INDEX IF NOT EXISTS idx_authorizations_approval_tx ON authorizations(approval_tx_hash);
CREATE INDEX IF NOT EXISTS idx_authorizations_revocation_tx ON authorizations(revocation_tx_hash);

PRAGMA foreign_keys = ON;
