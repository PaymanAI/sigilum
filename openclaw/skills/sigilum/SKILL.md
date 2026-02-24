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
- Negative-answer gate: before saying "no integration", "no access", or asking for direct provider credentials, you must run a signed `tools` check for the provider connection.
- Do not ask for a direct provider API key unless:
  - `sigilum-secure-<provider>` is missing, or
  - signed runtime check fails for non-auth reasons.
- If `sigilum-secure-linear` is active and test passes, answer that Linear is accessible via Sigilum gateway.
- Access checks must be signed and claim-gated per agent key.
- Do not use `/api/admin/*` as a capability check path.
- Use the hook-injected provider alias map (for example `linear -> sigilum-secure-linear`) as the source of truth for provider-to-connection routing.

## Commands

Resolve URL + helper path:

```bash
GATEWAY_URL="${SIGILUM_GATEWAY_URL:-http://localhost:38100}"
HELPER="${SIGILUM_GATEWAY_HELPER_BIN:-/workspace/skills/sigilum/bin/gateway-admin.sh}"
if [[ ! -x "${HELPER}" && -x "${HOME}/.openclaw/workspace/skills/sigilum/bin/gateway-admin.sh" ]]; then
  HELPER="${HOME}/.openclaw/workspace/skills/sigilum/bin/gateway-admin.sh"
fi
if [[ -z "${SIGILUM_AGENT_ID:-}" ]]; then
  export SIGILUM_AGENT_ID="${OPENCLAW_AGENT_ID:-${OPENCLAW_AGENT:-}}"
fi
```

Signed tools-list check (per-agent auth):

```bash
CONNECTION_ID="sigilum-secure-<provider>"
"${HELPER}" tools "${CONNECTION_ID}" "${GATEWAY_URL}"
```

Signed proxy call for HTTP-protocol connections:

```bash
CONNECTION_ID="sigilum-secure-<provider>"
METHOD="POST"
UPSTREAM_PATH="/graphql"
BODY_JSON='{"query":"query { viewer { id name } }"}'
"${HELPER}" proxy "${CONNECTION_ID}" "${METHOD}" "${UPSTREAM_PATH}" "${BODY_JSON}" "${GATEWAY_URL}"
```

Important parsing rule:

- Do **not** truncate helper output to first lines.
- Always read the full output and parse `HTTP_STATUS` + `APPROVAL_*` fields.
- If `APPROVAL_REQUIRED=true`, treat it as authorization-required-now (including revoked/expired prior approvals), ask user to approve/re-approve, then retry.

When auth is required (`401/403 AUTH_FORBIDDEN`), the helper prints:

- `APPROVAL_REQUIRED=true`
- `APPROVAL_NAMESPACE=<namespace>`
- `APPROVAL_AGENT_ID=<agent_id>`
- `APPROVAL_SUBJECT=<subject>`
- `APPROVAL_PUBLIC_KEY=<ed25519:...>`
- `APPROVAL_SERVICE=<connection_id>`
- `APPROVAL_MESSAGE=<operator guidance>`

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
2. Run signed capability check: `"${HELPER}" tools "sigilum-secure-linear" "${GATEWAY_URL}"`.
   - The helper auto-detects connection protocol when admin metadata is readable.
   - `protocol=mcp`: checks `/mcp/{connection_id}/tools`.
   - `protocol=http`: checks `/proxy/{connection_id}/` (or `SIGILUM_PROXY_TOOLS_PATH`).
3. Interpret `HTTP_STATUS`:
   - `200`: yes, accessible via Sigilum gateway for this agent key.
   - `401` or `403`: agent authorization required.
   - If `APPROVAL_REQUIRED=true`, include `APPROVAL_NAMESPACE`, `APPROVAL_AGENT_ID`, and `APPROVAL_PUBLIC_KEY` in your user-facing approval instructions.
   - Never infer "gateway restart bug" from `401/403` alone; use `APPROVAL_*` and claim details as the source of truth.
   - `404`: connection missing; ask user to configure/install the provider connection.
   - Other non-2xx: gateway/upstream issue; surface exact error and next action.

If user asks "what skills/integrations do you have?" and mentions any provider:

1. Consult the hook-injected alias map for that provider name.
2. Run signed `tools` check for the mapped connection id.
3. Only then answer availability.

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
- `SIGILUM_AGENT_ID`: preferred explicit selector for signed runtime requests
- `OPENCLAW_AGENT_ID`: runtime fallback selector (when `SIGILUM_AGENT_ID` is unset)
- `OPENCLAW_AGENT`: runtime fallback selector (when `SIGILUM_AGENT_ID` and `OPENCLAW_AGENT_ID` are unset)
- `SIGILUM_SUBJECT`: optional subject override for signed runtime requests
- `SIGILUM_GATEWAY_ADMIN_TOKEN`: optional bearer token for helper protocol auto-detect (`/api/admin/connections/{id}`)
- `SIGILUM_CONNECTION_PROTOCOL`: optional manual override for helper protocol routing (`mcp|http`)
- `SIGILUM_PROXY_TOOLS_PATH`: optional path used by `tools` when connection protocol is `http` (default `/`)

## Key-Custody Notes

- Sigilum agent signing keys stay local.
- Gateway upstream API credentials stay in the local Sigilum gateway.
- OpenClaw model/channel runtime credentials are separate from Sigilum unless you route them through Sigilum proxy architecture.
