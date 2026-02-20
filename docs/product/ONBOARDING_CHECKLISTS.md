# Sigilum Onboarding Checklists

Canonical onboarding checklists by deployment mode.

## Shared Preconditions

- Namespace chosen and reserved naming convention documented.
- Security owner identified (human accountable operator).
- Runtime owner identified (who runs gateway and rotates credentials).
- One explicit decision recorded for deployment mode: `oss-local`, `managed`, or `enterprise`.

## OSS Local Mode Checklist

- [ ] Install prerequisites: Node, pnpm, Go, curl.
- [ ] Clone repo and run `pnpm install`.
- [ ] Start stack with `./sigilum up`.
- [ ] Confirm `GET /health` for API and gateway is healthy.
- [ ] Initialize namespace identity in local workspace.
- [ ] Add at least one service (`sigilum service add ...`) with secret configured.
- [ ] Run `./sigilum e2e-tests` and confirm signed/unsigned behavior.
- [ ] Run `./sigilum doctor` and resolve all `FAIL` checks.
- [ ] Document local data paths and backup/cleanup policy.

Exit Criteria:
- Signed approved requests succeed.
- Unsigned requests fail closed.
- Team can reproduce setup from zero in <30 minutes.

## Managed Mode Checklist

- [ ] Install local gateway runtime and pair to hosted control plane.
- [ ] Reserve namespace and bind accountability proof to operator.
- [ ] Configure gateway admin access mode (`loopback|token|hybrid`) explicitly.
- [ ] Verify gateway-to-control-plane connectivity and reconnection behavior.
- [ ] Configure provider connection and run discovery (`/discover`) at least once.
- [ ] Confirm claim/approval flow from dashboard to gateway enforcement.
- [ ] Validate credential handling: secrets remain local to gateway.
- [ ] Validate one revoke flow (approved -> revoked -> access denied).
- [ ] Capture runbook links for operations and incident response.

Exit Criteria:
- Pairing, approval, revoke, and retry flows are all validated end-to-end.
- No plaintext provider secrets leave gateway storage.
- Admin and runtime routes enforce configured trust model.

## Enterprise Mode Checklist

- [ ] Deploy private control plane in target network boundary.
- [ ] Deploy gateway in customer/private environment with outbound-only control-plane connectivity.
- [ ] Configure enterprise identity and namespace governance policy.
- [ ] Configure audit log sink and retention requirements.
- [ ] Validate admin token/loopback access policy and CORS restrictions.
- [ ] Validate `/metrics` scrape and log forwarding with redaction guarantees.
- [ ] Execute DR test: restart gateway and verify replay protection/session recovery behavior.
- [ ] Execute break-glass procedure and verify traceability.
- [ ] Complete security sign-off with evidence bundle.

Exit Criteria:
- Security and compliance owners approve policy, telemetry, and incident controls.
- Production SLO/SLA monitors are connected to gateway health/metrics.
- Runbooks include upgrade, rotate, revoke, and rollback procedures.
