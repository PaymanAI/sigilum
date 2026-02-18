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
- `internal/claims` - approved-claims authorization lookup client
- `internal/catalog` - local service catalog schema + persistence

## What Gateway Does

- Verifies incoming Sigilum RFC 9421 request signatures:
  - `signature-input`
  - `signature`
  - `sigilum-namespace`
  - `sigilum-agent-key`
  - `sigilum-agent-cert`
- Enforces nonce replay checks in gateway process memory.
- Confirms authorization by querying Sigilum API approved claims feed (`/v1/namespaces/claims`) with service API key auth.
- Routes requests to configured upstream connectors (`/proxy/{connection_id}/...` and `/slack/...` alias).
- Injects connector auth headers (Bearer or custom header-key mode) and strips Sigilum signing headers before upstream forwarding.
- Provides admin APIs for local connector configuration and credential rotation metadata.

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
- Admin:
  - `GET /api/admin/connections`
  - `POST /api/admin/connections`
  - `GET /api/admin/connections/{id}`
  - `PATCH /api/admin/connections/{id}`
  - `DELETE /api/admin/connections/{id}`
  - `POST /api/admin/connections/{id}/rotate`
  - `POST /api/admin/connections/{id}/test`
  - `GET /api/admin/service-catalog`
  - `PUT /api/admin/service-catalog`

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

Planned CLI-facing control commands:

- `sigilum gateway pair`
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
