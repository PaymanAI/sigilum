---
name: sigilum-plugin
description: "Bootstrap Sigilum identity keys and capture subject hints for OpenClaw agents."
metadata: {"openclaw":{"emoji":"🔐","events":["gateway:startup","command:new","config:reload","gateway:reload","message:received"],"requires":{"env":["SIGILUM_NAMESPACE"]}}}
---

# Sigilum Plugin Hook

This hook prepares OpenClaw agents for Sigilum.

What it does:

1. Resolves Sigilum settings from hook env (and process env fallback).
2. Discovers configured agent IDs from OpenClaw config.
3. Ensures one Ed25519 keypair per agent under a deterministic key root.
4. Injects a gateway-first policy into agent context:
   - check `sigilum-secure-*` connections first for provider access
   - use signed runtime checks via helper (`gateway-admin.sh tools`) for capability checks
   - helper routes to `/mcp/{connection_id}/tools` for MCP connections and `/proxy/{connection_id}/...` for HTTP connections when protocol metadata is available
   - enforce claim-gated access per agent key
   - when approval is required (`401/403`), include helper `APPROVAL_*` fields (namespace/agent/public-key/service) in user-facing instructions
   - apply a negative-answer gate: before saying "no access/integration", run a signed check first
   - include a live provider alias map (`provider -> sigilum-secure-...`) from active gateway connections
   - avoid `/api/admin/*` for capability checks
   - do not request direct provider API keys unless gateway path fails
5. Lists active `sigilum-secure-*` gateway connections and their provider aliases (including `sigilum-secure-linear` when present).
6. Writes a runtime credential discovery report for migration at `<openclaw-home>/.sigilum/legacy-runtime-credentials.json`.
7. Captures per-message sender identity hints at `<openclaw-home>/.sigilum/subject-hints.json` for automatic `sigilum-subject` resolution in the gateway helper.
8. Runs at gateway startup, new sessions/config reload, and `message:received` events.

## Recommended OpenClaw Config

```json
{
  "hooks": {
    "internal": {
      "enabled": true,
      "entries": {
        "sigilum-plugin": {
          "enabled": true,
          "env": {
            "SIGILUM_NAMESPACE": "your-namespace",
            "SIGILUM_GATEWAY_URL": "http://localhost:38100",
            "SIGILUM_GATEWAY_ADMIN_TOKEN": "<optional-admin-token>",
            "SIGILUM_API_URL": "http://localhost:8787",
            "SIGILUM_DASHBOARD_URL": "https://sigilum.id",
            "SIGILUM_KEY_ROOT": "/Users/you/.openclaw/.sigilum/keys",
            "SIGILUM_AUTO_BOOTSTRAP_AGENTS": "true"
          }
        }
      }
    }
  }
}
```

## Environment Variables

- `SIGILUM_NAMESPACE` (required)
- `SIGILUM_GATEWAY_URL` (optional)
- `SIGILUM_GATEWAY_ADMIN_TOKEN` (optional; sent as `Authorization: Bearer ...` for admin inventory calls)
- `SIGILUM_API_URL` (optional)
- `SIGILUM_DASHBOARD_URL` (optional)
- `SIGILUM_KEY_ROOT` (optional)
- `SIGILUM_AUTO_BOOTSTRAP_AGENTS` (`true|false`, optional, default `true`)
- `SIGILUM_LEGACY_RUNTIME_REPORT_PATH` (optional; override runtime discovery report path)
- `SIGILUM_SUBJECT_HINTS_PATH` (optional; override subject hint capture path)

## Output Layout

Per-agent keys are created under:

- `<SIGILUM_KEY_ROOT>/<agent-id>/<fingerprint>.key`
- `<SIGILUM_KEY_ROOT>/<agent-id>/<fingerprint>.pub`

Private keys are stored with mode `0600`.
