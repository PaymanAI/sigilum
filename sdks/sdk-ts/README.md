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
```

All protected API endpoints require signed headers. This SDK signs requests with Ed25519 using RFC 9421-style `Signature-Input` and `Signature`, including:

- `sigilum-namespace`
- `sigilum-subject`
- `sigilum-agent-key`
- `sigilum-agent-cert`

Use a stable `sigilum-subject` principal id (not a random per-request value); gateway policy can use it for subject-level controls.

## Auth note

Signed headers prove agent identity. Some endpoints also require additional auth:

- Example: `POST /v1/claims` requires `Authorization: Bearer <service_api_key>`
