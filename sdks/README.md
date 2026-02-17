# Sigilum SDKs

All language SDKs live under this folder.

## Layout

- `sdk-ts/` - TypeScript/Node SDK package (`@sigilum/sdk`)
- `sdk-python/` - Python SDK package (`sigilum`)
- `sdk-go/` - Go SDK module (`sigilum.local/sdk-go`)
- `sdk-java/` - Java SDK (Maven)
- `test-vectors/` - language-agnostic shared test vectors

## Compatibility Matrix

| SDK | Runtime | Package/Module | Install | Import |
| --- | --- | --- | --- | --- |
| TypeScript | Node.js >= 20 | `@sigilum/sdk` | `pnpm add @sigilum/sdk` | `import * as sigilum from "@sigilum/sdk"` |
| Python | Python >= 3.11 | `sigilum` | `pip install sigilum` | `import sigilum` |
| Go | Go 1.23 | `sigilum.local/sdk-go` | `go get sigilum.local/sdk-go/sigilum` | `import "sigilum.local/sdk-go/sigilum"` |
| Java | JDK 21 | `id.sigilum:sdk-java` | Add Maven dependency | `import id.sigilum.sdk.Sigilum` |

## Common Contract

All SDKs implement the same signed-header profile for API requests:

- RFC 9421-style `Signature-Input` and `Signature`
- Ed25519 signatures
- Required Sigilum headers:
  - `sigilum-namespace`
  - `sigilum-agent-key`
  - `sigilum-agent-cert`
- Optional body integrity via `content-digest`

Shared conformance vectors are stored in:

- `sdks/test-vectors/http-signatures-rfc9421.json`

## API Enforcement

The API now enforces signed headers on all protected endpoints (`/v1/*` and `/.well-known/*`), so unsigned requests are rejected.

Signed headers are identity/authenticity proof. Some endpoints also require endpoint-specific auth (for example service API key bearer auth on `POST /v1/claims`).
