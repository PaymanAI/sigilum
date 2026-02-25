# sigilum (Python SDK)

Local-first identity for AI agents.

## Runtime

- Python >= 3.11

## Install

```bash
pip install sigilum
```

## 1) Init identity once

```bash
sigilum init <human_namespace>
```

Machine-readable CLI output for automation:

```bash
sigilum init <human_namespace> --json
sigilum list --json
```

## 2) Certify any agent in one line

```python
import sigilum

agent = MyAgent(...)
sigilum.certify(agent)
```

## 3) Hello Signed Request

```python
import sigilum

namespace = "alice"

class Agent:
    pass

agent = Agent()
sigilum.certify(agent, namespace=namespace)

response = agent.sigilum.fetch(
    url=f"/v1/namespaces/{namespace}",
    method="GET",
)

print("status", response.status)
print(response.read().decode("utf-8"))
```

Expected outcome:

- request includes Sigilum signed headers
- API returns namespace metadata when auth/approval is satisfied

## Minimal runnable example

```python
import sigilum

class Agent:
    pass

agent = Agent()
sigilum.certify(agent, namespace="alice")

response = agent.sigilum.fetch(
    url=f"/v1/namespaces/{agent.sigilum.namespace}",
    method="GET",
)
print(response.status)
print(response.read().decode("utf-8"))
```

## Signed request

```python
agent.sigilum.fetch(
    url=f"/v1/namespaces/{agent.sigilum.namespace}",
    method="GET",
)

# Override subject for a single request (for example, the end user ID)
agent.sigilum.request(
    "/claims",
    method="POST",
    subject="customer-12345",
)
```

All protected API endpoints require signed headers. This SDK signs requests with Ed25519 using RFC 9421-style `Signature-Input` and `Signature`, including `sigilum-namespace`, `sigilum-subject`, `sigilum-agent-key`, and `sigilum-agent-cert`.
Use a stable `sigilum-subject` principal id; gateway policy can use it for subject-level controls.
`subject` means "who triggered this action" (the authenticated human or system identity). The platform/integration layer is responsible for setting this value accurately.
If `subject` is omitted, SDK signing defaults it to the signer namespace for backward compatibility.

## Subject + DID model

- Identity hierarchy: `namespace -> service -> agent -> subject`
- DID format: `did:sigilum:{namespace}:{service}#{agent}#{subject}`
- Example: `did:sigilum:mfs:narmi#davis-agent#customer-12345`

`verify_http_signature(...)` returns deterministic failure metadata for automation:

- `code` (stable machine code such as `SIG_CONTENT_DIGEST_MISMATCH`)
- `reason` (human-readable detail)

Retry helper for idempotent operations:

- `retry_with_backoff(...)`
- `should_retry_http_status(...)` for `429/502/503/504`
- set `idempotent=True` only for safe/idempotent requests (for example `GET`, `HEAD`, retry-safe `PUT`)

## Auth note

Signed headers prove agent identity. Some endpoints also require additional auth:

- Example: `POST /v1/claims` requires `Authorization: Bearer <service_api_key>`
