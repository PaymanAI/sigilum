---
name: sigilum
description: "Run Sigilum identity/authz workflows from OpenClaw using the Sigilum CLI. Use for stack lifecycle, agent identity bootstrap, service registration, gateway connections, and end-to-end checks."
user-invocable: true
metadata: {"openclaw":{"emoji":"🔏","requires":{"bins":["bash"],"env":["SIGILUM_NAMESPACE"]},"primaryEnv":"SIGILUM_NAMESPACE","homepage":"https://sigilum.id"}}
---

# Sigilum CLI Skill

Use this skill to run Sigilum from OpenClaw without manual dashboard-first setup.

## Command Pattern

Use command-options grammar:

- `sigilum <resource> <verb> [options]`
- `sigilum <resource> <subresource> <verb> [options]`

Examples:

```bash
{baseDir}/bin/sigilum-openclaw.sh up
{baseDir}/bin/sigilum-openclaw.sh e2e-tests
{baseDir}/bin/sigilum-openclaw.sh service add --service-slug demo-service-native --service-name "Demo Service Native" --mode native
{baseDir}/bin/sigilum-openclaw.sh service add --service-slug demo-service-gateway --service-name "Demo Service Gateway" --mode gateway --upstream-base-url http://127.0.0.1:11100
```

## Core Flows

Identity/bootstrap:

```bash
{baseDir}/bin/sigilum-openclaw.sh up
```

This bootstraps local namespace + services in local mode.

Service management:

```bash
{baseDir}/bin/sigilum-openclaw.sh service add --service-slug my-service --service-name "My Service" --mode native
{baseDir}/bin/sigilum-openclaw.sh service add --service-slug linear --service-name "Linear" --mode gateway --upstream-base-url https://api.linear.app --auth-mode bearer --upstream-secret-env LINEAR_TOKEN
```

Validation:

```bash
{baseDir}/bin/sigilum-openclaw.sh agent-simulator
{baseDir}/bin/sigilum-openclaw.sh e2e-tests
```

## Required Environment

- `SIGILUM_NAMESPACE`

Optional:

- `SIGILUM_CLI_PATH`: absolute path to the `sigilum` CLI script
- `SIGILUM_REPO_ROOT`: Sigilum repo root containing `./sigilum`
- `GATEWAY_SIGILUM_NAMESPACE`, `GATEWAY_SIGILUM_HOME`, and related gateway env vars

## Key-Custody Notes

- Sigilum agent signing keys stay local.
- Gateway upstream API credentials stay in the local Sigilum gateway.
- OpenClaw model/channel runtime credentials are separate from Sigilum unless you route them through Sigilum proxy architecture.
