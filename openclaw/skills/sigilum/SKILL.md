---
name: sigilum
description: "Gateway-first provider access via Sigilum. For provider questions, check sigilum-secure-* connections first; do not ask for direct provider API keys until gateway path fails."
user-invocable: true
metadata: {"openclaw":{"emoji":"🔏","requires":{"bins":["bash","openssl","od","awk"],"env":["SIGILUM_NAMESPACE"]},"primaryEnv":"SIGILUM_NAMESPACE","homepage":"https://sigilum.id"}}
---

# Sigilum Gateway Skill

Use this skill for provider access through Sigilum gateway (Linear, Typefully, and other `sigilum-secure-*` connections).

## Gateway-First Policy

- Sigilum gateway is the default integration path.
- For “can you access <provider>?” always check gateway runtime access first.
- Do not ask for a direct provider API key unless:
  - `sigilum-secure-<provider>` is missing, or
  - signed runtime check fails for non-auth reasons.
- If `sigilum-secure-linear` is active and test passes, answer that Linear is accessible via Sigilum gateway.
- Access checks must be signed and claim-gated per agent key.
- Do not use `/api/admin/*` as a capability check path.

## Commands

Resolve URL + helper path:

```bash
GATEWAY_URL="${SIGILUM_GATEWAY_URL:-http://localhost:38100}"
HELPER="${SIGILUM_GATEWAY_HELPER_BIN:-/workspace/skills/sigilum/bin/gateway-admin.sh}"
if [[ ! -x "${HELPER}" && -x "${HOME}/.openclaw/workspace/skills/sigilum/bin/gateway-admin.sh" ]]; then
  HELPER="${HOME}/.openclaw/workspace/skills/sigilum/bin/gateway-admin.sh"
fi
```

Signed tools-list check (per-agent auth):

```bash
CONNECTION_ID="sigilum-secure-<provider>"
"${HELPER}" tools "${CONNECTION_ID}" "${GATEWAY_URL}"
```

When auth is required (`401/403 AUTH_FORBIDDEN`), the helper auto-attempts claim submission to Sigilum API and prints:

- `CLAIM_HTTP_STATUS=<status>` when claim submit was attempted
- `CLAIM_ERROR=<message>` when claim submit could not be attempted (missing API URL/key, unsupported URL, etc.)

Signed tool call:

```bash
CONNECTION_ID="<connection-id>"
TOOL_NAME="<tool-name>"
ARGS_JSON='{"query":"..."}'
"${HELPER}" call "${CONNECTION_ID}" "${TOOL_NAME}" "${ARGS_JSON}" "${GATEWAY_URL}"
```

## Provider Question Flow

When user asks: “can you access linear?”

1. Derive connection id: `sigilum-secure-linear`.
2. Run signed tools check: `"${HELPER}" tools "sigilum-secure-linear" "${GATEWAY_URL}"`.
3. Interpret `HTTP_STATUS`:
4. `200`: yes, accessible via Sigilum gateway for this agent key.
5. `401` or `403`: agent authorization required; ask user to approve claim for this agent key.
6. If `CLAIM_HTTP_STATUS` is present and indicates pending/already pending/already approved, report that claim registration was submitted (or already exists).
7. `404`: connection missing; ask user to configure/install the provider connection.
8. Other non-2xx: gateway/upstream issue; surface exact error and next action.

## Runtime CLI (optional)

```bash
RUNTIME_BIN="${SIGILUM_RUNTIME_BIN:-${SIGILUM_RUNTIME_ROOT:-${OPENCLAW_HOME:-$HOME/.openclaw}/workspace/.sigilum/runtime}/sigilum}"
"${RUNTIME_BIN}" --help
```

## Required Environment

- `SIGILUM_NAMESPACE`

Optional:

- `SIGILUM_RUNTIME_ROOT`: runtime root containing `sigilum` launcher (default from `sigilum openclaw install`, usually `<OPENCLAW_HOME>/workspace/.sigilum/runtime`)
- `SIGILUM_RUNTIME_BIN`: explicit launcher path (preferred when available)
- `SIGILUM_GATEWAY_URL`: gateway base URL (optional; defaults to `http://localhost:38100`)
- `SIGILUM_GATEWAY_HELPER_BIN`: optional absolute path to `gateway-admin.sh`
- `SIGILUM_KEY_ROOT`: optional agent key root (default `~/.openclaw/.sigilum/keys`)
- `SIGILUM_AGENT_ID`: optional agent id selector for per-agent key lookup (`main`/`default` fallback)
- `SIGILUM_SUBJECT`: optional subject override for signed runtime requests

## Key-Custody Notes

- Sigilum agent signing keys stay local.
- Gateway upstream API credentials stay in the local Sigilum gateway.
- OpenClaw model/channel runtime credentials are separate from Sigilum unless you route them through Sigilum proxy architecture.
