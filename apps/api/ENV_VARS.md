# API Env Vars and Bindings

This file documents environment variables and bindings used by the current default adapter implementation in `apps/api/src` (`ADAPTER_PROVIDER=cloudflare`).
The API is adapter-based; non-Cloudflare adapters can define different binding/config requirements.

## How Configuration Is Loaded

- Local development:
  - `.dev.vars` is loaded by `wrangler dev`
- Worker defaults:
  - `[vars]` in `apps/api/wrangler.toml`
- Secrets:
  - `wrangler secret put <NAME>`

## Required Cloudflare Bindings (Default Adapter)

These are **Cloudflare Worker bindings**, not `.dev.vars` key/value environment variables.
For the Cloudflare adapter, they must be configured in `apps/api/wrangler.toml` (and provisioned in Cloudflare) using:
- `[[d1_databases]]` for `DB`
- `[[queues.producers]]` / `[[queues.consumers]]` for queue bindings
- `[[durable_objects.bindings]]` for `NONCE_STORE_DO`

| Name | Type | Required | Notes |
| --- | --- | --- | --- |
| `DB` | D1 database | Yes | Primary system of record. |
| `NONCE_STORE_DO` | Durable Object namespace | Yes (for claims submit path) | Nonce replay protection; missing binding causes claim submit to fail (`503`). |
| `WEBHOOK_QUEUE` | Queue producer | Required for durable webhook delivery | Missing binding prevents enqueueing deliveries. |
| `BLOCKCHAIN_QUEUE` | Queue producer | Required only for `BLOCKCHAIN_MODE=queue` | Optional in `sync`, `memory`, `disabled` modes. |

## Variables

### Core / Platform

| Variable | Required | Default | Used by | Description |
| --- | --- | --- | --- | --- |
| `ENVIRONMENT` | Recommended | none in code | auth/blockchain logs and mode behavior | Typically `development`, `staging`, `production`, `test`. |
| `ADAPTER_PROVIDER` | No | `cloudflare` | `adapters/index.ts` | Current adapter provider switch. Only `cloudflare` is implemented. |
| `ALLOWED_ORIGINS` | No | `http://localhost:3000` (CORS middleware) | CORS + WebAuthn fallback | Comma-separated allowed origins for CORS. Also fallback source for WebAuthn allowed origins. |

### Auth / WebAuthn / JWT

| Variable | Required | Default | Used by | Description |
| --- | --- | --- | --- | --- |
| `JWT_SECRET` | Yes for auth | none | auth routes, services auth, webhook secret fallback | JWT signing/verification key. Also used as fallback for webhook secret encryption if `WEBHOOK_SECRET_ENCRYPTION_KEY` is absent. |
| `JWT_EXPIRY` | No | `7d` | `utils/config.ts` | JWT expiration for dashboard session tokens. |
| `WEBAUTHN_ALLOWED_ORIGINS` | Recommended | fallback to `ALLOWED_ORIGINS`, then `http://localhost:5000` | `utils/webauthn-config.ts` | Trusted WebAuthn origins for expected origin verification. |
| `WEBAUTHN_RP_ID` | No | derived from first trusted origin hostname | `utils/webauthn-config.ts` | WebAuthn relying-party ID. Must be compatible with trusted origins. |

### Blockchain

| Variable | Required | Default | Used by | Description |
| --- | --- | --- | --- | --- |
| `BLOCKCHAIN_MODE` | No | `disabled` | `utils/blockchain-queue.ts` | `queue`, `sync`, `memory`, or `disabled`. |
| `BLOCKCHAIN_NETWORK` | Recommended | behavior defaults to mainnet branch when not `testnet` | `utils/blockchain.ts` | `testnet` or `mainnet`; determines chain defaults. |
| `BLOCKCHAIN_RPC_URL` | No | `https://sepolia.base.org` for testnet, `https://mainnet.base.org` for mainnet | `utils/blockchain.ts` | Override RPC endpoint. |
| `SIGILUM_REGISTRY_ADDRESS` | Required for blockchain writes | none | blockchain utils + auth route checks | Contract address. Missing value causes blockchain jobs to be skipped/retried depending on mode/path. |
| `RELAYER_PRIVATE_KEY` | Required for blockchain writes | none | blockchain utils | Relayer key for on-chain transactions. |

### Webhooks / Delivery / SSRF

| Variable | Required | Default | Used by | Description |
| --- | --- | --- | --- | --- |
| `WEBHOOK_SECRET_ENCRYPTION_KEY` | No (but encryption key needed) | fallback to `JWT_SECRET` | `utils/webhook-secrets.ts` | Preferred key for encrypting stored webhook secrets. |
| `WEBHOOK_RETRY_WINDOW_HOURS` | No | `24` | `utils/config.ts`, webhook queue consumer | Retry window for durable webhook delivery attempts. |
| `WEBHOOK_FAILURE_THRESHOLD` | No | `10` | `utils/config.ts` | Currently parsed in config; not actively enforced in queue logic. |
| `WEBHOOK_ALERT_EMAIL_FROM` | Optional for failure alerts | none | webhook queue consumer | Sender address for terminal-failure alerts. |
| `RESEND_API_KEY` | Optional for failure alerts | none | webhook queue consumer | API key for alert-email transport via Resend. |
| `WEBHOOK_ALLOW_PRIVATE_TARGETS` | No | `false` | `utils/validation.ts` | `true` allows private/internal webhook targets; `false` blocks non-public IP targets. |
| `WEBHOOK_DNS_RESOLVER_URL` | No | `https://cloudflare-dns.com/dns-query` | `utils/validation.ts` | DNS-over-HTTPS resolver used for SSRF-safe hostname resolution. |

### Limits / Policy / Expiry

| Variable | Required | Default | Used by | Description |
| --- | --- | --- | --- | --- |
| `MAX_PENDING_AUTHORIZATIONS` | No | `20` | claims logic | Max pending requests per namespace before auto-reject. |
| `MAX_API_KEYS_PER_SERVICE` | No | `5` | services keys route | Max active API keys per service. |
| `MAX_WEBHOOKS_PER_SERVICE` | No | `5` | webhook create routes | Max active webhooks per service. |
| `PENDING_AUTHORIZATION_EXPIRY_HOURS` | No | `24` | scheduled handler | Auto-expire window for pending authorizations. |
| `CHALLENGE_EXPIRY_HOURS` | No | `1` | scheduled handler | Cleanup window for stale WebAuthn challenges. |

## Mode-Specific Minimum Sets

### Local fast iteration (no chain writes)

- `BLOCKCHAIN_MODE=disabled`
- `JWT_SECRET`
- `DB`, `NONCE_STORE_DO`, `WEBHOOK_QUEUE`
- `ALLOWED_ORIGINS`, `WEBAUTHN_ALLOWED_ORIGINS`, `WEBAUTHN_RP_ID`

### Staging testnet sync (no blockchain queue needed)

- `BLOCKCHAIN_MODE=sync`
- `BLOCKCHAIN_NETWORK=testnet`
- `SIGILUM_REGISTRY_ADDRESS`
- `RELAYER_PRIVATE_KEY`
- plus core vars above

### Production durable queue mode

- `BLOCKCHAIN_MODE=queue`
- `BLOCKCHAIN_NETWORK=mainnet` (or testnet if intentionally staging)
- `SIGILUM_REGISTRY_ADDRESS`
- `RELAYER_PRIVATE_KEY`
- `BLOCKCHAIN_QUEUE`, `WEBHOOK_QUEUE`, `DB`, `NONCE_STORE_DO`
- strongly recommended: `WEBHOOK_ALERT_EMAIL_FROM`, `RESEND_API_KEY`

## Notes on Sample Files

- Sample files exist at:
  - `apps/api/.dev.vars.example`
  - `apps/api/.dev.vars.local-sample.md`
  - `apps/api/.dev.vars.prod-sample.md`
  - `apps/api/.dev.vars.testnet-sample.md`
- Some local files may contain extra keys not consumed by the current API code (for example `DEBUG_LOGGING`, `STRIPE_*`). Treat this document as the code-usage source of truth.
