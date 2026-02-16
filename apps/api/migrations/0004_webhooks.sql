-- Webhook subscriptions: services register URLs to receive event notifications.
CREATE TABLE IF NOT EXISTS webhooks (
  id TEXT PRIMARY KEY,
  service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  events TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  failure_count INTEGER NOT NULL DEFAULT 0,
  last_triggered_at TEXT,
  last_failure_at TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_webhooks_service ON webhooks(service_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_active ON webhooks(active);
