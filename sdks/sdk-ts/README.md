# @sigilum/sdk (TypeScript SDK)

TypeScript/Node SDK for local-first agent identity and signed Sigilum API requests.

## Runtime

- Node.js >= 20

## Install

```bash
pnpm add @sigilum/sdk
```

## 1. Create identity once

```bash
sigilum init <human_namespace>
```

Examples:

```bash
sigilum init johndee
```

Machine-readable CLI output for automation:

```bash
sigilum init johndee --json
sigilum list --json
```

## 2. Certify any agent in one line

```ts
import * as sigilum from "@sigilum/sdk";

const agent = sigilum.certify(createAgent(...));
```

This does not wrap your agent class. It attaches identity and signed request helpers.

## 3. Hello Signed Request

```ts
import * as sigilum from "@sigilum/sdk";

const namespace = "alice";
const agent = sigilum.certify({});

const response = await agent.sigilum.fetch(`/v1/namespaces/${namespace}`, {
  method: "GET",
});

console.log("status", response.status);
console.log(await response.text());
```

Expected outcome:

- request includes Sigilum signed headers
- API returns namespace metadata when auth/approval is satisfied

## Minimal runnable example

```ts
import * as sigilum from "@sigilum/sdk";

const agent = sigilum.certify({});

const response = await agent.sigilum.fetch(`/v1/namespaces/${agent.sigilum.namespace}`, {
  method: "GET",
});

const data = await response.json();
console.log(data);
```

## Sending signed requests

```ts
const agent = sigilum.certify(createAgent(...));

await agent.sigilum.fetch(`/v1/namespaces/${agent.sigilum.namespace}`, {
  method: "GET",
});

// Override subject for a single request (for example, the end user ID)
await agent.sigilum.request("/claims", {
  method: "POST",
  subject: "customer-12345",
});
```

All protected API endpoints require signed headers. This SDK signs requests with Ed25519 using RFC 9421-style `Signature-Input` and `Signature`, including:

- `sigilum-namespace`
- `sigilum-subject`
- `sigilum-agent-key`
- `sigilum-agent-cert`

Use a stable `sigilum-subject` principal id (not a random per-request value); gateway policy can use it for subject-level controls.
`subject` means "who triggered this action" (the authenticated human or system identity). The platform/integration layer is responsible for setting this value accurately.
If `subject` is omitted, SDK signing defaults it to the signer namespace for backward compatibility.

## Subject + DID model

- Identity hierarchy: `namespace -> service -> agent -> subject`
- DID format: `did:sigilum:{namespace}:{service}#{agent}#{subject}`
- Example: `did:sigilum:mfs:narmi#davis-agent#customer-12345`

`verifyHttpSignature(...)` returns deterministic failure metadata for automation:

- `code` (stable machine code such as `SIG_CONTENT_DIGEST_MISMATCH`)
- `reason` (human-readable detail)

Retry helper for idempotent operations:

- `retryWithBackoff(...)`
- `shouldRetryHttpStatus(...)` for `429/502/503/504`
- set `idempotent: true` only for safe/idempotent requests (for example `GET`, `HEAD`, retry-safe `PUT`)

## Auth note

Signed headers prove agent identity. Some endpoints also require additional auth:

- Example: `POST /v1/claims` requires `Authorization: Bearer <service_api_key>`
