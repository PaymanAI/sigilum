# Sigilum API (`@sigilum/api`)

Sigilum API is the backend for namespace-based agent authorization.

It provides:
- Namespace identity (`did:sigilum:<namespace>`)
- Authenticated service registration and API key management
- Authorization request lifecycle (`submit -> approve/reject -> revoke`)
- Verification endpoints for SDK/runtime checks
- Dashboard auth (WebAuthn + JWT)
- Durable webhook delivery
- Optional blockchain audit-log writes

OpenAPI: `apps/api/openapi.json`

## Related Docs

- API guide: `apps/api/README.md`
- Environment variables and bindings: `apps/api/ENV_VARS.md`

## Runtime and Adapters

- API framework: Hono
- Adapter architecture:
  - Interfaces: `src/adapters/interfaces.ts`
  - Default provider: `cloudflare` (`src/adapters/cloudflare/*`)
- Current default bindings:
  - D1: `DB`
  - Durable Object nonce store: `NONCE_STORE_DO`
  - Queues: `BLOCKCHAIN_QUEUE`, `WEBHOOK_QUEUE`

The API is adapter-based; Cloudflare is the current implementation, not a hard platform requirement.

## Main Flow

1. Namespace owner signs up and authenticates (`/v1/auth/*`).
2. Owner registers service and generates API key (`/v1/services/*`).
3. Service submits authorization requests (`POST /v1/claims`) with signed headers + nonce replay protection.
4. Namespace owner approves/rejects/revokes authorization (`/v1/claims/{claimId}/*`).
5. Service checks authorization via:
   - `GET /v1/verify` (point lookup)
   - `GET /v1/namespaces/claims` (approved-claims cache feed)
6. Service webhooks receive durable `request.*` lifecycle events.

## API Surface

All protected endpoints (`/v1/*` and `/.well-known/*`) require valid Sigilum signed headers.

### Health
- `GET /health`

### Auth (dashboard)
- `GET /v1/auth/signup/options`
- `POST /v1/auth/signup`
- `GET /v1/auth/login/options`
- `POST /v1/auth/login`
- `GET /v1/auth/me`
- `POST /v1/auth/logout`
- `GET /v1/auth/passkeys/options`
- `POST /v1/auth/passkeys`
- `GET /v1/auth/passkeys`
- `PATCH /v1/auth/passkeys/{id}`
- `DELETE /v1/auth/passkeys/{id}`
- `PATCH /v1/auth/settings`
- `DELETE /v1/auth/account`

### Namespaces, DID, verification
- `GET /v1/namespaces/{namespace}`
- `GET /v1/namespaces/{namespace}/claims` (namespace-owner auth)
- `GET /v1/namespaces/claims` (service API key)
- `GET /.well-known/did/{did}`
- `GET /v1/verify`

### Authorizations
- `POST /v1/claims` (service API key)
- `GET /v1/claims/{claimId}` (namespace-owner auth)
- `POST /v1/claims/{claimId}/approve`
- `POST /v1/claims/{claimId}/reject`
- `POST /v1/claims/{claimId}/revoke`

### Services
- `GET /v1/services`
- `POST /v1/services`
- `GET /v1/services/{serviceId}`
- `PATCH /v1/services/{serviceId}`
- `DELETE /v1/services/{serviceId}`
- `GET /v1/services/{serviceId}/keys`
- `POST /v1/services/{serviceId}/keys`
- `DELETE /v1/services/{serviceId}/keys/{keyId}`
- `GET /v1/services/{serviceId}/webhooks`
- `POST /v1/services/{serviceId}/webhooks`
- `DELETE /v1/services/{serviceId}/webhooks/{webhookId}`

## Local Development

Prerequisites:
- Node.js >= 20
- pnpm
- Wrangler CLI

Install from repo root:

```bash
pnpm install
```

Configure env (from `apps/api`):

```bash
cp .dev.vars.example .dev.vars
```

Environment reference:
- `apps/api/ENV_VARS.md`

Apply local D1 migrations:

```bash
pnpm exec wrangler d1 migrations apply sigilum-api --local
```

Run:

```bash
pnpm --filter @sigilum/api dev
```

## Build and Test

From repo root:

```bash
pnpm --filter @sigilum/api typecheck
pnpm --filter @sigilum/api test
pnpm --filter @sigilum/api build
pnpm --filter @sigilum/api deploy
```

## Blockchain Modes

`BLOCKCHAIN_MODE`:
- `disabled`: skip blockchain writes
- `sync`: execute inline
- `memory`: in-memory async queue (testing)
- `queue`: durable queue-backed writes

If required blockchain config is missing (`SIGILUM_REGISTRY_ADDRESS`, `RELAYER_PRIVATE_KEY`), blockchain submissions are skipped and logged.

## Webhook Delivery

- Webhooks are configured via service endpoints (`/v1/services/{serviceId}/webhooks*`).
- Delivery is durable via `WEBHOOK_QUEUE`.
- Retries use exponential backoff within `WEBHOOK_RETRY_WINDOW_HOURS`.
- Terminal-failure email alert requires:
  - `WEBHOOK_ALERT_EMAIL_FROM`
  - `RESEND_API_KEY`
  - namespace owner email resolution from `users.email`
