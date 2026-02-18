# Sigilum Go SDK

Local-first identity for AI agents and services.

## Runtime

- Go 1.23

## SDK surface

- `InitIdentity` / `LoadIdentity` / `ListNamespaces`
- `SignHTTPRequest` for agent-side RFC 9421 signing
- `VerifyHTTPSignature` for service-side verification
- `Certify` bindings for namespace-scoped API requests

## Quick start

```go
package main

import (
	"context"
	"log"

	"sigilum.local/sdk-go/sigilum"
)

func main() {
result, _ := sigilum.InitIdentity(sigilum.InitIdentityOptions{Namespace: "alice"})
_ = result

bindings, _ := sigilum.Certify(sigilum.CertifyOptions{Namespace: "alice"})
resp, err := bindings.Do(context.Background(), sigilum.SignRequestInput{
	URL:    "/v1/namespaces/" + bindings.Namespace,
	Method: "GET",
})
if err != nil {
	log.Fatal(err)
}
defer resp.Body.Close()
}
```

All protected API endpoints require signed headers. Requests are signed with Ed25519 using RFC 9421-style `Signature-Input` and `Signature`, and can be validated server-side with `VerifyHTTPSignature`.
Signed identity headers include `sigilum-namespace`, `sigilum-subject`, `sigilum-agent-key`, and `sigilum-agent-cert`.

## Auth note

Signed headers prove agent identity. Some endpoints also require additional auth:

- Example: `POST /v1/claims` requires `Authorization: Bearer <service_api_key>`
