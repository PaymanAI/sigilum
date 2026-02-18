---
name: sigilum-linear
description: "Register and use Linear as a Sigilum gateway-routed service from OpenClaw. Use this when you want Linear credentials to live in the Sigilum gateway instead of agent process env."
user-invocable: true
metadata: {"openclaw":{"emoji":"📈","requires":{"bins":["bash"],"env":["SIGILUM_NAMESPACE","LINEAR_TOKEN"]},"homepage":"https://linear.app/developers/graphql"}}
---

# Sigilum Linear Skill

This skill configures Linear as a gateway-routed Sigilum service.

## Register Linear in Sigilum

```bash
sigilum service add \
  --service-slug linear \
  --service-name "Linear" \
  --mode gateway \
  --upstream-base-url https://api.linear.app \
  --auth-mode bearer \
  --upstream-secret-env LINEAR_TOKEN
```

## Validate Routing

```bash
sigilum agent-simulator
```

## Notes

- Keep `LINEAR_TOKEN` local while bootstrapping; Sigilum stores it in gateway connection secrets.
- Agents use Sigilum signatures and authorized public keys, not raw Linear tokens.
