# Sigilum Java SDK

Local-first identity for AI agents and services.

## Runtime

- JDK 21

## SDK surface

- `Sigilum.initIdentity` / `Sigilum.loadIdentity` / `Sigilum.listNamespaces`
- `Sigilum.signHttpRequest` for agent-side RFC 9421 signing
- `Sigilum.verifyHttpSignature` for service-side verification
- `Sigilum.certify` namespace-scoped request bindings

## Quick start

```java
import id.sigilum.sdk.Sigilum;
import java.util.Map;

public class Main {
  public static void main(String[] args) {
Sigilum.InitIdentityOptions init = new Sigilum.InitIdentityOptions();
init.namespace = "alice";
Sigilum.initIdentity(init);

Sigilum.CertifyOptions certify = new Sigilum.CertifyOptions();
certify.namespace = "alice";
Sigilum.SigilumBindings bindings = Sigilum.certify(certify);

bindings.fetch(
  "/v1/namespaces/" + bindings.namespace,
  "GET",
  Map.of(),
  null
);
  }
}
```

All protected API endpoints require signed headers. The SDK signs requests with Ed25519 using RFC 9421-style `Signature-Input` and `Signature`, including `sigilum-namespace`, `sigilum-subject`, `sigilum-agent-key`, and `sigilum-agent-cert`.

## Auth note

Signed headers prove agent identity. Some endpoints also require additional auth:

- Example: `POST /v1/claims` requires `Authorization: Bearer <service_api_key>`
