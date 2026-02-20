# Sigilum World-Class Product Review (Gateway + SDKs + Scripts)

Date: 2026-02-20
Scope: `apps/gateway/service/**`, `sdks/**`, `scripts/**`, `sigilum`

## North-Star Quality Bar

A world-class Sigilum should feel like this in every interaction:

- Security-first by default with explicit trust boundaries and least privilege.
- Deterministic behavior under failure (clear contracts, no ambiguous errors).
- Cross-language SDK parity (same behavior, same edge cases, same errors).
- Operational maturity (observability, graceful shutdown, replay and resiliency semantics).
- Onboarding that takes a new developer from zero to first verified request in under 10 minutes.
- Product voice that is precise, calm, and actionable in both success and failure states.

## Highest-Impact Gaps I Would Address First

## P0

1. Gateway admin hardening model is not yet “reference implementation” quality.
- Admin checks are loopback/token focused, but the docs and positioning imply stronger signed/caller-identity semantics.
- Need one explicit and testable model: signed admin caller identity + policy, or fully locked local control plane with explicit boundary docs.

2. SDK verification profiles are too permissive and can drift from gateway signature expectations.
- SDK verifiers currently do not enforce the full signed component profile consistently across languages.
- This creates interop and security ambiguity.

3. Pairing bridge trust surface is larger than necessary.
- Gateway bridge relays broad admin paths/headers without a strict contract and without strong command-shape validation.

## P1

4. Error model consistency is fragmented.
- Some routes return JSON with codes, others fall back to plain `http.Error` text.
- A security product needs stable, typed error contracts.

5. Gateway observability is below production reference-grade.
- Request IDs exist, but no consistent structured event taxonomy for auth reject reasons, upstream failure classes, policy decisions, and latency buckets.

6. Scripts are capable but brittle at scale.
- Multiple scripts duplicate logic (port handling, secret handling, API probing, argument parsing).
- Several flows rely on implicit defaults and shell-specific behavior.

## Detailed Backlog

## 1) Gateway Engineering and Architecture (Model MCP Gateway)

### Security and Policy

- `GW-001` Define and enforce one admin trust model end-to-end.
- `GW-002` Add signed admin identity verification middleware (or explicitly lock to loopback + token and document as local-only profile).
- `GW-003` Normalize authz decisions into explicit machine codes:
  - `AUTH_SIGNATURE_INVALID`
  - `AUTH_REPLAY_DETECTED`
  - `AUTH_CLAIM_REQUIRED`
  - `AUTH_POLICY_DENIED`
  - `ADMIN_ACCESS_FORBIDDEN`
- `GW-004` Enforce full signature component profile in gateway verifier boundary with deterministic error codes.
- `GW-005` Add per-connection and per-namespace rate limiting controls for claim registration and MCP call bursts.

### Resilience and Runtime

- `GW-006` Introduce graceful shutdown drain metrics and in-flight request accounting.
- `GW-007` Add upstream circuit-breaker behavior for repeated MCP/provider failures.
- `GW-008` Add bounded retries with jitter and classify retryable vs non-retryable errors.
- `GW-009` Add optional persistent nonce store mode (Badger-backed) for restart-safe replay protection.
- `GW-010` Add timeouts per route class (proxy vs admin vs discovery vs tool call).

### MCP Reference Implementation Quality

- `GW-011` Harden MCP transport contract:
  - Strict request/response schemas
  - Session lifecycle state machine
  - Explicit reconnect strategy
- `GW-012` Unique JSON-RPC request IDs and correlation with logs.
- `GW-013` MCP discovery caching policy (TTL + stale-if-error + forced refresh API).
- `GW-014` Tool policy explainability endpoint (`why allowed/denied`).
- `GW-015` Add MCP conformance harness against multiple providers with fixtures.

### API and DX Contract

- `GW-016` Convert all route errors to a shared JSON envelope.
- `GW-017` Add `request_id`, `timestamp`, and `docs_url` fields to every error response.
- `GW-018` Ensure CORS config supports required headers consistently (`X-Sigilum-Admin-Token`, request-id, signed headers where relevant).
- `GW-019` Publish gateway API schema (OpenAPI or equivalent) for admin/runtime endpoints.

### Observability

- `GW-020` Structured logs for every decision point (auth, claim, policy, upstream, rotation).
- `GW-021` Prometheus-style metrics for:
  - auth reject reasons
  - upstream latency/error classes
  - MCP discovery/tool call success rates
  - replay detections
- `GW-022` Add health/readiness/liveness split endpoints.
- `GW-023` Add redaction guarantees for logs and tests that enforce them.

## 2) SDK Engineering and Developer Experience

### Parity and Correctness

- `SDK-001` Enforce identical signature verification profile in TS/Go/Python (and Java when restored).
- `SDK-002` Expand shared conformance vectors beyond 2 cases:
  - duplicate headers
  - missing signed components
  - malformed `Signature-Input`
  - stale signature windows
  - nonce replay
- `SDK-003` Guarantee same default `sigilum-subject` semantics across SDKs.
- `SDK-004` Align error messages and error codes across all SDK languages.

### Package Quality

- `SDK-005` Remove committed build artifacts / local caches from SDK folders.
- `SDK-006` Restore Java SDK source or explicitly mark unsupported in matrix until complete.
- `SDK-007` Add semantic versioning and release automation per SDK.
- `SDK-008` Add backwards-compatibility tests for identity file formats.

### Developer Ergonomics

- `SDK-009` Add first-class typed clients/wrappers for common Sigilum endpoints.
- `SDK-010` Add portable retry helper with idempotency guidance.
- `SDK-011` Improve CLI UX for `init/list` with `--json` and stable output for automation.
- `SDK-012` Add copy-paste “hello signed request” quickstarts that are identical across languages.

## 3) Scripts, CLI, and Automation

### Reliability and Safety

- `SCR-001` Add strict shell contract tests for high-value scripts (`sigilum`, `run-local-api-gateway.sh`, `sigilum-auth.sh`, pairing bridge).
- `SCR-002` Standardize argument parsing and validation patterns across scripts.
- `SCR-003` Add timeout guards for all network subprocess calls.
- `SCR-004` Improve failure messages to always include:
  - what failed
  - where
  - likely causes
  - next command to run
- `SCR-005` Add checksum/signature verification in release install flow (`install-curl.sh`).

### Maintainability

- `SCR-006` Extract shared helpers into one reusable script library with test coverage.
- `SCR-007` Remove duplicated connection test logic between gateway runtime and gateway CLI.
- `SCR-008` Reduce inline Node heredocs in shell scripts; move to versioned JS modules.
- `SCR-009` Add `shellcheck` and formatting/linting in CI for all scripts.

### Operator Experience

- `SCR-010` Make `sigilum doctor` emit machine-readable JSON and human-friendly summary.
- `SCR-011` Add `sigilum doctor --fix` for safe automated remediations.
- `SCR-012` Add clearer success output contracts for onboarding and pairing flows.

## 4) Product Features and Onboarding

### Onboarding Flow

- `PRD-001` One canonical onboarding path per mode (`managed`, `enterprise`, `oss-local`) with explicit checklists.
- `PRD-002` First-run wizard should verify:
  - identity exists
  - API reachable
  - gateway reachable
  - one service connected
  - one signed request succeeds
- `PRD-003` Add “explain failure” docs pages mapped from gateway error codes.

### Approval and Security UX

- `PRD-004` Approval state should be explicit and queryable:
  - pending
  - approved
  - revoked
  - expired
- `PRD-005` Provide deterministic re-approval flow from any auth-forbidden response.
- `PRD-006` Add audit timeline events for claim submit/approve/revoke/access deny.

### Design and Messaging

- `PRD-007` Define error/success style guide for all surfaces (gateway, SDKs, scripts).
- `PRD-008` Every error should provide an operator action.
- `PRD-009` Every success should confirm scope and next meaningful step.

## 5) Acceptance Criteria for “World-Class Gateway”

The gateway should be considered model-quality when all are true:

- `AC-001` Security boundary is explicit, documented, and enforced by tests.
- `AC-002` All auth failures are deterministic with typed error codes and docs mapping.
- `AC-003` MCP behavior is spec-conformant with robust session/retry/discovery semantics.
- `AC-004` Replay guarantees are well-defined for both local and restart scenarios.
- `AC-005` Performance and reliability SLOs are measurable via metrics and logs.
- `AC-006` Admin/runtime APIs are schema-documented and backwards-compatible.
- `AC-007` Onboarding from clean machine to first successful signed call is <=10 minutes.

## Execution Plan

### Wave 1 (Immediate)

- `GW-016`, `GW-018`, `GW-012`, `SDK-001`, `SCR-001`

### Wave 2

- `GW-001`, `GW-002`, `GW-003`, `GW-020`, `GW-021`, `SDK-002`

### Wave 3

- `GW-009`, `GW-011`, `GW-013`, `GW-014`, `SCR-006`, `SCR-008`

### Wave 4

- `SDK-009`, `SDK-010`, `PRD-001`, `PRD-002`, `PRD-004`

## Start Now

The first implementation tasks I’m starting immediately:

1. `SDK-001` strict cross-language signature profile enforcement.
2. `GW-016` consistent JSON error envelope for method/route failures.
3. `GW-018` CORS and admin-header interoperability hardening.
4. `SCR-001` pairing bridge shutdown and relay-safety hardening.

