# Sigilum World-Class TODO

Reference: `world_class_review.md`

## In Progress Queue

- [x] `SDK-001` Enforce identical strict signature verification profile across TS/Go/Python SDKs.
- [x] `GW-016` Normalize gateway method-not-allowed and route failures to stable JSON errors.
- [x] `GW-018` Harden gateway CORS contract for admin and signed request headers.
- [x] `SCR-001` Harden gateway pairing bridge shutdown/retry/relay-safety behavior.
- [x] `GW-012` Use unique MCP JSON-RPC request IDs for traceability/interoperability.

## Next Queue

- [x] `GW-001` Define and implement one explicit admin trust model.
- [x] `GW-003` Add deterministic auth failure code taxonomy and docs mapping.
- [x] `GW-017` Add `request_id`, `timestamp`, and `docs_url` to gateway error responses.
- [x] `GW-011` Refactor MCP session and retry behavior into clear state machine.
- [x] `GW-010` Add timeouts per route class (proxy vs admin vs discovery vs tool call).
- [x] `GW-020` Add structured gateway decision logs with redaction guarantees.
- [x] `GW-021` Add gateway metrics for auth, policy, MCP, and upstream latency/errors.
- [x] `GW-023` Add redaction guarantees for logs and tests that enforce them.
- [x] `GW-022` Add health/readiness/liveness split endpoints.
- [x] `GW-019` Publish gateway API schema (OpenAPI) for admin/runtime endpoints.
- [x] `GW-013` Add MCP discovery caching policy (TTL + stale-if-error + forced refresh API).
- [x] `GW-014` Add MCP tool policy explainability endpoint (`why allowed/denied`).
- [x] `SDK-002` Expand shared RFC9421 conformance vectors and run in all SDKs.
- [x] `SDK-006` Restore Java SDK source implementation or mark unsupported in matrix.
- [x] `SDK-011` Improve CLI UX for `init/list` with `--json` and stable output for automation.
- [x] `SDK-012` Add copy-paste “hello signed request” quickstarts that are identical across languages.
- [x] `SCR-005` Add checksum/signature verification to release install path.
- [x] `SCR-006` Extract shared script library to remove duplicated shell logic.
- [x] `SCR-009` Add shellcheck + script CI checks.
- [x] `SCR-010` Make `sigilum doctor` emit machine-readable JSON and human-friendly summary.
- [x] `SCR-011` Add `sigilum doctor --fix` for safe automated remediations.
- [x] `SCR-012` Add clearer success output contracts for onboarding and pairing flows.
- [x] `PRD-001` Build one canonical onboarding checklist per deployment mode.
- [x] `PRD-003` Add “explain failure” docs pages mapped from gateway error codes.
- [x] `PRD-007` Publish product-wide error/success message style guide.
