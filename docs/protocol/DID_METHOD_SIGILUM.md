# did:sigilum Method Specification (v0.1.0)

Status: Draft  
Method name: `sigilum`  
Primary network: Base L2 (or compatible EVM deployment)  
Reference contract: `contracts/src/SigilumRegistry.sol`

## 1. Abstract

`did:sigilum` is a DID method for verifiable AI-agent identity under a human-owned namespace.  
The method binds:

- a namespace owner
- one or more approved Ed25519 agent public keys
- one or more service authorizations

to produce a DID Document that relying services can verify.

## 2. Method-Specific Identifier

### 2.1 Syntax

Base DID form:

```text
did:sigilum:<namespace>
```

- `<namespace>` MUST be 3-64 chars.
- Allowed characters: `a-z`, `A-Z`, `0-9`, `-`.
- Namespace MUST begin and end with an alphanumeric character.

Optional DID URL fragment (for key/service references):

```text
did:sigilum:<namespace>#<fragment>
```

Example:

```text
did:sigilum:prashanth-openai#agent123
```

## 3. DID Document Model

Resolver output uses W3C DID Core JSON-LD context:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:sigilum:prashanth-openai",
  "verificationMethod": [
    {
      "id": "did:sigilum:prashanth-openai#key-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:sigilum:prashanth-openai",
      "publicKeyMultibase": "z6Mkf5rG..."
    }
  ],
  "authentication": [
    "did:sigilum:prashanth-openai#key-1"
  ],
  "assertionMethod": [
    "did:sigilum:prashanth-openai#key-1"
  ],
  "service": [
    {
      "id": "did:sigilum:prashanth-openai#agent-runtime-openai",
      "type": "AgentEndpoint",
      "serviceEndpoint": "https://api.sigilum.id/v1/verify?namespace=prashanth-openai&service=openai"
    }
  ]
}
```

## 4. Method Operations (CRUD)

`did:sigilum` operations are backed by `SigilumRegistry` state transitions and mirrored API state.

### 4.1 Create

Create namespace DID:

- Contract: `registerNamespace(name)`
- Result: `did:sigilum:<name>` becomes resolvable.

Create authorized verification material:

- Contract (two-step):
  - `submitClaim(namespace, publicKey, service, agentIP)`
  - `approveClaim(claimId)`
- Contract (single-step API mode):
  - `approveClaimDirect(namespace, publicKey, service, agentIP)`

### 4.2 Read (Resolve)

Resolve DID document:

- `GET /.well-known/did/{did}`
- `GET /1.0/identifiers/{did}` (DID Resolution result envelope)

Resolver behavior:

- Reads namespace owner state.
- Reads approved claims (`status = approved`).
- Converts Ed25519 keys to `publicKeyMultibase`.
- Emits DID Document + DID metadata.

### 4.3 Update

Update DID control/authorization state:

- Transfer control: `transferNamespace(name, newOwner)`
- Add/replace approved key-service bindings:
  - `approveClaim(...)` or `approveClaimDirect(...)`
- Remove authorization:
  - `revokeClaim(claimId)` or `revokeClaimDirect(namespace, publicKey, service)`

These updates change resolver output (keys/services/authentication relationships).

### 4.4 Deactivate

Method-level deactivation is represented by removal of namespace-owner control-plane record plus revocation of active approvals.

Resolver semantics:

- If historical authorization data exists but active namespace-owner record is absent:
  - `didDocumentMetadata.deactivated = true`
  - DID remains identifiable, but active methods are empty.

## 5. DID Resolution API

### 5.1 DID Document endpoint

`GET /.well-known/did/{did}`

- Content type: `application/did+ld+json`
- Returns DID Document only.

### 5.2 DID Resolution endpoint

`GET /1.0/identifiers/{did}`

- Content type: `application/ld+json;profile="https://w3id.org/did-resolution"`
- Returns:
  - `@context`: `https://w3id.org/did-resolution/v1`
  - `didDocument`
  - `didDocumentMetadata`
  - `didResolutionMetadata`

Error mapping:

- `invalidDid` -> HTTP `400`
- `notFound` -> HTTP `404`
- `internalError` -> HTTP `500`

## 6. Contract Interface Mapping

Core methods in `SigilumRegistry`:

- `registerNamespace`
- `transferNamespace`
- `submitClaim`
- `approveClaim`
- `rejectClaim`
- `revokeClaim`
- `approveClaimDirect`
- `revokeClaimDirect`
- `isAuthorized`

These are the canonical state transitions for DID creation and key/service authorization updates.

## 7. Security Considerations

- Namespace ownership controls approval and revocation rights.
- Approved key lookups are deterministic (`namespace + publicKey + service`).
- Resolver output should be consumed with cache TTL and replay-safe request signing at runtime.
- Private keys are never published in DID Documents.

## 8. Privacy Considerations

- DID Documents expose only public verification material and service authorization bindings.
- Sensitive secrets remain in gateway-local encrypted storage and are not part of DID resolution output.

## 9. Conformance Notes

This method conforms to DID Core document shape and exposes a DID Resolution endpoint envelope.  
Method updates are reflected through Sigilum registry lifecycle operations and resolver output.
