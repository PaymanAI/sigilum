---
name: sigilum-plugin
description: "Bootstrap Sigilum identity keys for OpenClaw agents on startup and config reload."
metadata: {"openclaw":{"emoji":"🔐","events":["gateway:startup","command:new","config:reload","gateway:reload"],"requires":{"env":["SIGILUM_NAMESPACE"]}}}
---

# Sigilum Plugin Hook

This hook prepares OpenClaw agents for Sigilum.

What it does:

1. Resolves Sigilum settings from hook env (and process env fallback).
2. Discovers configured agent IDs from OpenClaw config.
3. Ensures one Ed25519 keypair per agent under a deterministic key root.
4. Runs at gateway startup and when new sessions/config reload events happen.

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
            "SIGILUM_API_URL": "http://localhost:8787",
            "SIGILUM_DASHBOARD_URL": "https://sigilum.id/dashboard",
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
- `SIGILUM_API_URL` (optional)
- `SIGILUM_DASHBOARD_URL` (optional)
- `SIGILUM_KEY_ROOT` (optional)
- `SIGILUM_AUTO_BOOTSTRAP_AGENTS` (`true|false`, optional, default `true`)

## Output Layout

Per-agent keys are created under:

- `<SIGILUM_KEY_ROOT>/<agent-id>/<fingerprint>.key`
- `<SIGILUM_KEY_ROOT>/<agent-id>/<fingerprint>.pub`

Private keys are stored with mode `0600`.
