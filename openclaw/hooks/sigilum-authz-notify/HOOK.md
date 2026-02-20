---
name: sigilum-authz-notify
description: "Notify the operator when Sigilum authorization requests are pending approval."
metadata: {"openclaw":{"emoji":"🔏","events":["gateway:startup","command:new"],"requires":{"env":["SIGILUM_NAMESPACE","SIGILUM_OWNER_TOKEN"]}}}
---

# Sigilum Authorization Notifications

This optional hook checks for pending Sigilum authorization requests and sends reminders in-channel.

Security model:

- This hook reads pending authorizations through a namespace-owner endpoint.
- It requires a namespace owner bearer token (`SIGILUM_OWNER_TOKEN`).
- Do not enable this hook unless you intend to keep that token in the OpenClaw runtime.

## Configuration

```json
{
  "hooks": {
    "internal": {
      "enabled": true,
      "entries": {
        "sigilum-authz-notify": {
          "enabled": true,
          "env": {
            "SIGILUM_NAMESPACE": "your-namespace",
            "SIGILUM_API_URL": "https://api.sigilum.id",
            "SIGILUM_OWNER_TOKEN": "<namespace-owner-jwt>",
            "SIGILUM_DASHBOARD_URL": "https://sigilum.id"
          }
        }
      }
    }
  }
}
```

## Environment Variables

- `SIGILUM_NAMESPACE` (required)
- `SIGILUM_OWNER_TOKEN` (required)
- `SIGILUM_API_URL` (optional, default `https://api.sigilum.id`)
- `SIGILUM_DASHBOARD_URL` (optional)
