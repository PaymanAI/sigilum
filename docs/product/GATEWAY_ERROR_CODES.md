# Gateway Error Codes

This reference maps gateway `code` values to operator actions.

## Auth Errors

| Code | Meaning | Operator Action |
| --- | --- | --- |
| `AUTH_HEADERS_INVALID` | Signed headers are malformed or duplicated. | Re-sign the request with one value per Sigilum header and retry. |
| `AUTH_SIGNATURE_INVALID` | Signature verification failed. | Verify identity key pair, request body integrity, and signing inputs. |
| `AUTH_SIGNED_COMPONENTS_INVALID` | Signed component set is missing required entries. | Include the required Sigilum component profile and re-sign. |
| `AUTH_IDENTITY_INVALID` | Required identity headers are missing/invalid. | Send valid `sigilum-namespace`, `sigilum-subject`, `sigilum-agent-key`, and `sigilum-agent-cert`. |
| `AUTH_NONCE_INVALID` | Signature nonce is missing or malformed. | Include a unique nonce in `Signature-Input`. |
| `AUTH_REPLAY_DETECTED` | Nonce was already seen within replay window. | Generate a fresh nonce and retry once. |
| `AUTH_CLAIMS_UNAVAILABLE` | Gateway claims cache is unavailable. | Check gateway/API connectivity and service API key configuration. |
| `AUTH_CLAIMS_LOOKUP_FAILED` | Claims lookup failed. | Verify Sigilum API health, credentials, and namespace configuration. |
| `AUTH_CLAIM_REQUIRED` | Caller is not approved for the target service. | Complete approval flow, then retry the same request. |
| `AUTH_CLAIM_SUBMIT_RATE_LIMITED` | Auto-claim registration burst limit was exceeded. | Wait one minute, then retry once or complete approval manually. |
| `AUTH_FORBIDDEN` | Generic auth-denied fallback. | Inspect request signature + approval posture and retry after remediation. |

## Admin Errors

| Code | Meaning | Operator Action |
| --- | --- | --- |
| `ADMIN_TOKEN_NOT_CONFIGURED` | Token-only admin mode is enabled without token config. | Set `GATEWAY_ADMIN_TOKEN` and restart gateway. |
| `ADMIN_TOKEN_REQUIRED` | Admin token is required for this request. | Provide `X-Sigilum-Admin-Token` or `Authorization: Bearer ...`. |
| `ADMIN_LOOPBACK_REQUIRED` | Admin request is restricted to loopback clients. | Call from loopback host or switch admin access mode explicitly. |
| `ADMIN_TOKEN_OR_LOOPBACK_REQUIRED` | Admin request requires loopback or a valid admin token. | Use loopback access or attach a valid admin token. |

## Runtime And MCP Errors

| Code | Meaning | Operator Action |
| --- | --- | --- |
| `UPSTREAM_ERROR` | HTTP proxy upstream request failed. | Verify upstream service health, network reachability, and connector secrets. |
| `ROTATION_REQUIRED` | Connector secret rotation policy blocks access. | Rotate connector secret and retry. |
| `INVALID_REFRESH_MODE` | `refresh` query value is invalid. | Use `refresh=auto` or `refresh=force`. |
| `MCP_DISCOVERY_FAILED` | MCP discovery refresh failed. | Verify MCP endpoint/auth and rerun discovery. |
| `MCP_TOOL_FORBIDDEN` | Tool is blocked by effective tool policy. | Use explain endpoint and adjust policy/allowlist as needed. |
| `MCP_TOOL_RATE_LIMITED` | MCP tool call burst limit was exceeded for this connection/namespace. | Wait one minute, then retry with backoff. |
| `MCP_CIRCUIT_OPEN` | MCP upstream circuit breaker is open after repeated failures. | Wait for cooldown and investigate upstream stability before retrying. |
| `MCP_TOOL_CALL_FAILED` | MCP tool execution failed upstream. | Check provider health, tool arguments, and upstream credentials. |

## Health And Readiness Errors

| Code | Meaning | Operator Action |
| --- | --- | --- |
| `NOT_READY` | Gateway dependencies are not initialized/ready. | Wait for initialization or repair connector store/API dependencies. |

## Generic And Operator Errors

| Code | Meaning | Operator Action |
| --- | --- | --- |
| `METHOD_NOT_ALLOWED` | Endpoint does not support this HTTP method. | Use the documented method for that route. |
| `NOT_FOUND` | Route/resource does not exist. | Verify route path and resource identifiers. |
| `REQUEST_BODY_TOO_LARGE` | Request body exceeds configured size limit. | Reduce payload size or increase `GATEWAY_MAX_REQUEST_BODY_BYTES`. |

## Triage Checklist

1. Capture `request_id`, `timestamp`, and `code` from the error envelope.
2. Check gateway decision logs and metrics around that `request_id`.
3. Apply the mapped action above.
4. Retry once with the same route/method after remediation.
