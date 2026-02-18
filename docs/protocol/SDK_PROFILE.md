# Sigilum SDK Profile v1

This profile defines the cross-language minimum contract for Sigilum SDKs (TypeScript, Python, Go, Java).

## Goal

A single local-first model for both sides:

- Agent side: initialize identity locally, sign outgoing requests.
- Service side: verify request signature + namespace identity proof.

## Required capabilities

1. Local identity lifecycle
- `initIdentity(namespace)` creates (or loads) local identity.
- `loadIdentity(namespace?)` loads existing identity.
- `listNamespaces()` returns known local owner namespaces.

2. One-line certification entrypoint
- SDKs should provide a top-level certification entrypoint (for example `certify(...)`) that binds identity and signing helpers.

3. HTTP request signing (RFC 9421 profile)
- Signatures use Ed25519.
- Signed request includes:
  - `signature-input`
  - `signature`
  - `sigilum-namespace`
  - `sigilum-subject`
  - `sigilum-agent-key`
  - `sigilum-agent-cert`
  - `content-digest` (when body is present)

4. Service verification primitive
- `verifyHttpSignature(...)` validates:
  - signature headers are present and parseable
  - agent certificate is valid
  - namespace/key/keyid consistency
  - content digest (if body exists)
  - Ed25519 signature correctness

## Identity record format

Stored under:

- `~/.sigilum/identities/<namespace>/identity.json`

Required fields:

- `version`
- `namespace`
- `did`
- `keyId`
- `publicKey`
- `privateKey`
- `certificate`
- `createdAt`
- `updatedAt`

## Certificate payload canonical form

Certificate proof signs UTF-8 text:

1. `sigilum-certificate-v1`
2. `namespace:<namespace>`
3. `did:<did>`
4. `key-id:<keyId>`
5. `public-key:<publicKey>`
6. `issued-at:<issuedAt>`
7. `expires-at:<expiresAt-or-empty>`

## Security posture

- Identity creation/signing is local; no hosted dependency required at agent runtime.
- Verification is deterministic and offline-capable for signature/certificate checks.
- Namespace authorization policy can be layered on top by services.
