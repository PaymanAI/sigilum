CREATE TABLE IF NOT EXISTS usage_events (
  event_id TEXT PRIMARY KEY,
  namespace TEXT NOT NULL,
  service TEXT NOT NULL,
  public_key TEXT NOT NULL,
  subject TEXT NOT NULL,
  agent_id TEXT,
  protocol TEXT NOT NULL,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  status_code INTEGER,
  duration_ms INTEGER,
  response_bytes INTEGER,
  request_method TEXT,
  request_path TEXT,
  remote_ip TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_usage_events_namespace_created_at
  ON usage_events(namespace, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_usage_events_namespace_service_created_at
  ON usage_events(namespace, service, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_usage_events_namespace_subject_created_at
  ON usage_events(namespace, subject, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_usage_events_namespace_agent_created_at
  ON usage_events(namespace, agent_id, public_key, created_at DESC);
