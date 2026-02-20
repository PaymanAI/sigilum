# Sigilum SDKs

All language SDKs live under this folder.

## Layout

- `sdk-ts/` - TypeScript/Node SDK package (`@sigilum/sdk`)
- `sdk-python/` - Python SDK package (`sigilum`)
- `sdk-go/` - Go SDK module (`sigilum.local/sdk-go`)
- `sdk-java/` - Java SDK placeholder (not yet supported)
- `test-vectors/` - language-agnostic shared test vectors

## Compatibility Matrix

| SDK | Runtime | Package/Module | Install | Import | Status |
| --- | --- | --- | --- | --- | --- |
| TypeScript | Node.js >= 20 | `@sigilum/sdk` | `pnpm add @sigilum/sdk` | `import * as sigilum from "@sigilum/sdk"` | Supported |
| Python | Python >= 3.11 | `sigilum` | `pip install sigilum` | `import sigilum` | Supported |
| Go | Go 1.23 | `sigilum.local/sdk-go` | `go get sigilum.local/sdk-go/sigilum` | `import "sigilum.local/sdk-go/sigilum"` | Supported |
| Java | JDK 21 | `id.sigilum:sdk-java` | N/A (implementation not shipped) | N/A | Not yet supported |

## Common Contract

Supported SDKs implement the same signed-header profile for API requests:

- RFC 9421-style `Signature-Input` and `Signature`
- Ed25519 signatures
- Required Sigilum headers:
  - `sigilum-namespace`
  - `sigilum-subject`
  - `sigilum-agent-key`
  - `sigilum-agent-cert`
- Optional body integrity via `content-digest`
- SDK CLIs provide stable machine-readable output for identity bootstrap/list commands (`sigilum init --json`, `sigilum list --json` in supported SDKs)
- Signature verification failures expose stable machine codes + human-readable reasons across supported SDKs (example code: `SIG_CONTENT_DIGEST_MISMATCH`)
- SDKs expose portable retry helpers for idempotent calls (`retryWithBackoff` / `retry_with_backoff` / `RetryWithBackoff`) plus shared retryable status guidance (`429/502/503/504`)

`sigilum-subject` is not decorative: treat it as a stable requester principal id inside a namespace. Gateway can apply subject-aware policy using this value (for example MCP tool filtering).
When `subject` is omitted at signing time, supported SDKs default `sigilum-subject` to the signer namespace.

Shared conformance vectors are stored in:

- `sdks/test-vectors/http-signatures-rfc9421.json`
- `sdks/test-vectors/identity-record-v1.json`
- Coverage includes fragment stripping, method/body component profile checks, replay/timestamp strictness, and tamper failures (method/header/body).
- Identity compatibility fixture coverage ensures TS/Go/Python loaders remain compatible with persisted v1 identity records (including unknown forward-compatible fields).

Cross-SDK onboarding quickstarts:

- `sdks/sdk-ts/README.md`
- `sdks/sdk-python/README.md`
- `sdks/sdk-go/README.md`

## API Enforcement

The API now enforces signed headers on all protected endpoints (`/v1/*` and `/.well-known/*`), so unsigned requests are rejected.

Signed headers are identity/authenticity proof. Some endpoints also require endpoint-specific auth (for example service API key bearer auth on `POST /v1/claims`).

## Testing

Run tests per SDK package:

- TypeScript:
  - `pnpm --dir sdks/sdk-ts test`
  - `pnpm --dir sdks/sdk-ts test:conformance`
- Python:
  - `python -m pytest sdks/sdk-python/tests`
- Go:
  - `go test ./...` (from `sdks/sdk-go`)

Java SDK is currently a placeholder package and does not ship executable source/tests yet.

Shared signing conformance vectors used by SDK tests:

- `sdks/test-vectors/http-signatures-rfc9421.json`
