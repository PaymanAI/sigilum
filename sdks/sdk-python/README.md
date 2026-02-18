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

## 2) Certify any agent in one line

```python
import sigilum

agent = MyAgent(...)
sigilum.certify(agent)
```

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
```

All protected API endpoints require signed headers. This SDK signs requests with Ed25519 using RFC 9421-style `Signature-Input` and `Signature`, including `sigilum-namespace`, `sigilum-subject`, `sigilum-agent-key`, and `sigilum-agent-cert`.
Use a stable `sigilum-subject` principal id; gateway policy can use it for subject-level controls.

## Auth note

Signed headers prove agent identity. Some endpoints also require additional auth:

- Example: `POST /v1/claims` requires `Authorization: Bearer <service_api_key>`
