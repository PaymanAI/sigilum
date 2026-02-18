# Sigilum Gateway

Sigilum Gateway is a local reverse-proxy service that enforces Sigilum signed-auth and approved-claim checks before forwarding requests to third-party APIs with connector-managed credentials.

This folder contains:

- `service/` - Go gateway runtime
- `envoy/` - optional Envoy local ingress config
- `docker-compose.yml` - local compose setup for Envoy + gateway

## Service Internals

Gateway service code is organized under `apps/gateway/service`:

- `cmd/sigilum-gateway` - service entrypoint
- `cmd/sigilum-gateway-cli` - local CLI for connection management
- `config` - environment loading and validation
- `internal/connectors` - connector models, auth-header injection, reverse proxy
- `internal/mcp` - MCP JSON-RPC client, discovery, and tool policy filtering
- `internal/claims` - approved-claims authorization lookup client
- `internal/catalog` - local service catalog schema + persistence

## What Gateway Does

- Verifies incoming Sigilum RFC 9421 request signatures:
  - `signature-input`
  - `signature`
  - `sigilum-namespace`
  - `sigilum-subject`
  - `sigilum-agent-key`
  - `sigilum-agent-cert`
- Enforces nonce replay checks in gateway process memory.
- Confirms authorization by querying Sigilum API approved claims feed (`/v1/namespaces/claims`) with service API key auth.
- Routes requests to configured upstream connectors (`/proxy/{connection_id}/...` and `/slack/...` alias).
- Injects connector auth headers (Bearer or custom header-key mode) and strips Sigilum signing headers before upstream forwarding.
- Supports MCP connections (`protocol: "mcp"`) with streamable HTTP transport.
- Discovers MCP tools (`/api/admin/connections/{id}/discover`) and stores discovery metadata locally.
- Exposes filtered MCP tools at runtime:
  - `GET /mcp/{connection_id}/tools`
  - `POST /mcp/{connection_id}/tools/{tool}/call`
- Applies tool filtering policies by `sigilum-subject` via connection-level and subject-level allow/deny rules.
- Provides admin APIs for local connector configuration and credential rotation metadata.

Service catalog templates now support both HTTP and MCP provider definitions:

- `protocol`: `http` (default) or `mcp`
- MCP template fields: `mcp_transport`, `mcp_endpoint`, `mcp_tool_allowlist`, `mcp_tool_denylist`, `mcp_max_tools_exposed`, `mcp_subject_tool_policies`
- Credential fields can include `env_var` hints for dashboard UX (display-only hint; secrets still stored in gateway)
- Shared credential variables can be defined once and reused across multiple connections via secret references like `{{var:OPENAI_API_KEY}}`.
- Shared variable metadata includes `created_by_subject` for audit traceability.

## `sigilum-subject` Semantics

- `sigilum-subject` is a required signed identity header on protected runtime requests.
- Treat it as the stable requester identifier inside a namespace (human user id, employee id, or app-level principal).
- Gateway uses `sigilum-subject` for:
  - MCP subject-level tool filtering (`mcp_subject_tool_policies`)
  - shared credential variable audit attribution (`created_by_subject`) when writing variables

## Protocol Behavior (`http` vs `mcp`)

- `protocol: "http"`
  - request path: `/proxy/{connection_id}/...`
  - requires upstream auth secret configuration (`auth_secret_key` + secret material)
- `protocol: "mcp"`
  - runtime paths: `/mcp/{connection_id}/tools` and `/mcp/{connection_id}/tools/{tool}/call`
  - optional auth secret configuration (only required when MCP upstream requires credentials)
  - supports discovery (`POST /api/admin/connections/{id}/discover`) and per-subject tool policy filtering
- Shared credential variable references (`{{var:KEY}}`) are resolved for both HTTP and MCP connections.

## Request Flow (Proxy)

1. Client sends signed request to gateway proxy endpoint.
2. Gateway verifies signature and signed component set.
3. Gateway checks nonce replay (in-memory).
4. Gateway validates approved claim for `<namespace, public_key, service>`.
5. Gateway resolves connector config + secret from local encrypted store.
6. Gateway forwards request to target upstream with connector auth injection.

If any auth step fails, gateway returns a structured error without forwarding upstream.

## Admin/API Surface

- Health:
  - `GET /health`
- Proxy:
  - `/{proxy routes}`
    - `/<proxy>/proxy/{connection_id}/...`
    - `/<proxy>/slack/...`
- MCP Runtime:
  - `GET /mcp/{connection_id}/tools`
  - `POST /mcp/{connection_id}/tools/{tool}/call`
- Admin:
  - `GET /api/admin/connections`
  - `POST /api/admin/connections`
  - `GET /api/admin/connections/{id}`
  - `PATCH /api/admin/connections/{id}`
  - `DELETE /api/admin/connections/{id}`
  - `POST /api/admin/connections/{id}/rotate`
  - `POST /api/admin/connections/{id}/test`
  - `POST /api/admin/connections/{id}/discover`
  - `GET /api/admin/credential-variables`
  - `POST /api/admin/credential-variables`
  - `DELETE /api/admin/credential-variables/{key}`
  - `GET /api/admin/service-catalog`
  - `PUT /api/admin/service-catalog`

`POST /api/admin/credential-variables` accepts optional `created_by_subject` and also honors the `sigilum-subject` header (header takes precedence).

## Shared Variables and `env_var`

- `credential_fields[].env_var` in service catalog templates is a dashboard hint key, not automatic host environment lookup by gateway.
- Dashboard setup uses this key to:
  - detect existing shared credential variables
  - let users reuse an existing value without re-entry
  - store connection secrets as references (`{{var:KEY}}`) instead of duplicating raw values per connection
- If you manage gateway directly, define shared variables via admin API and reference them in connection secrets:

```bash
# Upsert shared variable with explicit subject attribution
curl -sS -X POST http://127.0.0.1:38100/api/admin/credential-variables \
  -H 'Content-Type: application/json' \
  -H 'sigilum-subject: user_123' \
  -d '{"key":"OPENAI_API_KEY","value":"sk-live-..."}'
```

```json
{
  "secrets": {
    "api_key": "{{var:OPENAI_API_KEY}}"
  }
}
```

## Does Setup Change?

- Existing HTTP setup still works unchanged (`auth_secret_key` + direct secret value).
- New optional step for reusable credentials:
  1. Create shared credential variable once.
  2. Reference it from one or more connections with `{{var:KEY}}`.
- For MCP providers, choose `protocol: "mcp"` and run discovery after saving connection config.

Connection secrets are stored encrypted in local BadgerDB at `GATEWAY_DATA_DIR/badger`.

Rotation policy controls:

- `GATEWAY_ROTATION_ENFORCEMENT=off|warn|block`
- `GATEWAY_ROTATION_GRACE_DAYS=<n>`

In `block` mode, overdue connections are rejected with `ROTATION_REQUIRED`.

## CLI (Local Service Management)

The gateway also provides a local CLI for managing stored service connections directly:

- `go run ./apps/gateway/service/cmd/sigilum-gateway-cli list`
- `go run ./apps/gateway/service/cmd/sigilum-gateway-cli get --id slack-proxy`
- `go run ./apps/gateway/service/cmd/sigilum-gateway-cli add --name Slack --base-url https://slack.com/api --auth-mode bearer --auth-prefix "Bearer " --auth-secret-key bot_token --secret bot_token=<token>`
- `go run ./apps/gateway/service/cmd/sigilum-gateway-cli add --name LinearMCP --protocol mcp --base-url https://mcp.linear.app --mcp-endpoint /mcp --auth-secret-key api_key --secret api_key=<token> --mcp-allow linear.searchIssues --mcp-deny linear.createIssue`
- `go run ./apps/gateway/service/cmd/sigilum-gateway-cli update --id slack-proxy --status active`
- `go run ./apps/gateway/service/cmd/sigilum-gateway-cli rotate --id slack-proxy --secret bot_token=<new_token>`
- `go run ./apps/gateway/service/cmd/sigilum-gateway-cli test --id slack-proxy --method GET --path /auth.test`
- `go run ./apps/gateway/service/cmd/sigilum-gateway-cli delete --id slack-proxy`

CLI reads:

- `GATEWAY_DATA_DIR` (default `/var/lib/sigilum-gateway`)
- `GATEWAY_MASTER_KEY` (required; can be passed via `--master-key`)

## Envoy (Optional Local Ingress)

The local Envoy scaffold in `apps/gateway/envoy/envoy.yaml` provides:

- listener on `:38000`
- routes for `/health`, `/api/admin/*`, `/proxy/*`, `/slack*`
- upstream cluster target `sigilum-gateway:38100`
- admin interface on `:38200`
- websocket upgrade enabled

This is a local bootstrap config, not a production ingress baseline.

## Local-Only Assumptions

This gateway is currently designed for local, single-instance operation.

- Nonce replay protection is process-local and in-memory (not shared across instances, resets on restart).
- Connector secret storage is local BadgerDB on filesystem.
- No distributed lock/state model is implemented.
- No HA/multi-node consistency guarantees are provided.
- Configuration and admin routes are intended for trusted local environments.

## Managed/Enterprise Dashboard Integration Pattern

For managed and enterprise deployments, treat gateway as the local/private data plane and API/dashboard as control plane.

Do not rely on direct browser calls from hosted dashboard UI to `http://localhost:<gateway-port>`.
That pattern is fragile (mixed-content, CORS, local network boundaries, and device mismatch).

Recommended pattern:

1. Pair local gateway with control plane; local CLI/agent establishes gateway identity and registration metadata.
2. Keep an outbound gateway session to control plane; gateway initiates and maintains a persistent outbound channel (for example WebSocket).
3. Dashboard sends admin intents to control plane for list/add/update/remove/test connection actions.
4. Control plane relays commands to connected gateway; no inbound exposure of local gateway admin API is required.
5. Keep secrets local-only; dashboard encrypts secret payloads to gateway public key, control plane relays ciphertext only, gateway decrypts and stores locally.
6. Keep secret reads one-way; value retrieval from dashboard should be disallowed (rotate/set only).

This model supports:

- `managed`: hosted API/dashboard + customer-run local gateway
- `enterprise`: private/on-prem API/dashboard + private gateway
- `oss-local`: local API + local gateway (dashboard optional/not required)

Current v1 command:

- `sigilum gateway pair --session-id <id> --pair-code <code> --namespace <namespace>`

This runs a local websocket bridge process that relays dashboard gateway-admin intents
through Sigilum API pairing endpoints to your local gateway admin API (`:38100` by default).

Future commands (planned):

- `sigilum gateway connect`
- `sigilum gateway status`
- `sigilum gateway disconnect`

## Non-Goals (Current)

- Multi-instance production replay guarantees.
- Cross-node shared nonce/state coordination.
- Production-grade admin authn/authz boundary.
- Global control-plane orchestration for connector secrets.

## Configuration Highlights

See `apps/gateway/.env.example` for local defaults and examples.

Key variables:

- `SIGILUM_REGISTRY_URL` - Sigilum API base URL.
- `SIGILUM_SERVICE_API_KEY` (+ optional per-connection overrides) - used for approved-claims feed lookup.
- `GATEWAY_SIGILUM_NAMESPACE` and optional `GATEWAY_SIGILUM_HOME` - local signer identity used for signed API calls.
- `GATEWAY_MASTER_KEY` - local encryption key for connector secret store.
- `GATEWAY_DATA_DIR` - local persistent data directory.
- `GATEWAY_ALLOWED_ORIGINS` - explicit browser origin allowlist for admin API CORS.
- `GATEWAY_TRUSTED_PROXY_CIDRS` - trusted proxy hop CIDRs/IPs allowed to supply `X-Forwarded-*`.
- Default local port block:
  - Envoy ingress: `38000`
  - Gateway service: `38100`
  - Envoy admin: `38200`

The `/slack/...` alias is fixed to connector id `slack-proxy` (no environment override).

If a hosted dashboard at `https://sigilum.id` is used to guide setup for a local gateway, keep proxy trust narrow: include only local ingress/tunnel CIDRs you control in `GATEWAY_TRUSTED_PROXY_CIDRS`.
`GATEWAY_ALLOWED_ORIGINS` is primarily for trusted same-origin/local admin surfaces, not as a primary managed-dashboard integration mechanism.

## Running Locally

From repo root:

- Gateway service only:
  - `go run ./apps/gateway/service/cmd/sigilum-gateway`
- Compose with Envoy:
  - `docker compose -f apps/gateway/docker-compose.yml up --build`

If using compose, ensure your `.env` in `apps/gateway/` is configured first.
