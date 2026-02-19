# Detailed Gateway/OpenClaw Review

Scope reviewed:
- Go gateway service (`apps/gateway/service/**`) with focus on MCP, authorization registration, request verification, and request forwarding.
- OpenClaw installer, hooks, skills, and gateway admin helper (`openclaw/**`).
- CLI/admin/support scripts (`scripts/**`, `sigilum`).

Legend:
- Priority: `P0` critical, `P1` high, `P2` medium, `P3` low.
- Status: `open`, `in-progress`, `done`.

| ID | Priority | Tags | Status | Files | Issue |
|---|---|---|---|---|---|
| R-001 | P0 | security, bug, scripts | done | `openclaw/install-openclaw-sigilum.sh`, `scripts/sigilum-auth.sh`, `scripts/sigilum-doctor.sh` | Config parsing used `Function(...)` fallback on local config text. Replaced with strict JSON/JSON5 parsing and explicit parse errors (no eval fallback). |
| R-002 | P0 | security, reliability, ux, scripts | done | `openclaw/skills/sigilum/bin/gateway-admin.sh`, `openclaw/skills/sigilum/SKILL.md` | Added curl-first transport with HTTPS support (HTTP `/dev/tcp` fallback only), clearer runtime transport errors, and explicit approval-required output fields (`APPROVAL_*`) for namespace/agent/key/service context. |
| R-003 | P1 | security, performance, bug, gateway | done | `apps/gateway/service/cmd/sigilum-gateway/runtime.go`, `apps/gateway/service/config/config.go`, `apps/gateway/service/cmd/sigilum-gateway/runtime_helpers.go` | Added bounded request-body reads with configurable `GATEWAY_MAX_REQUEST_BODY_BYTES` and `413 REQUEST_BODY_TOO_LARGE` responses. |
| R-004 | P1 | security, architecture, gateway | done | `apps/gateway/service/cmd/sigilum-gateway/runtime_helpers.go`, `apps/gateway/service/cmd/sigilum-gateway/authorization.go` | Added duplicate-header rejection for critical Sigilum/signature headers before signature verification. |
| R-005 | P1 | performance, bug, mcp, gateway | done | `apps/gateway/service/internal/mcp/client.go`, `apps/gateway/service/internal/mcp/client_test.go` | MCP session cache now isolates by connection/auth context (not endpoint-only), preventing cross-connection session collisions. |
| R-006 | P1 | architecture, design, readability, gateway | done | `apps/gateway/service/cmd/sigilum-gateway/authorization.go`, `apps/gateway/service/cmd/sigilum-gateway/runtime.go` | Extracted authorization flow into modular helper functions (`verifySignedRequest`, identity resolution, nonce replay enforcement, claim authorization). |
| R-007 | P2 | security, permissions, install | done | `openclaw/install-openclaw-sigilum.sh` | Added explicit permission normalization for runtime and skill installs; owner-only defaults with explicit executable bits for shell entrypoints. |
| R-008 | P2 | documentation, ux, developer-experience | done | `docs/cli/GATEWAY_OPENCLAW_VALIDATION.md`, `openclaw/README.md`, `apps/gateway/README.md`, `docs/cli/README.md` | Added a deterministic first-time step-by-step validation runbook with expected results and troubleshooting, and linked it from gateway/openclaw docs. |
| R-009 | P2 | documentation, design, skills | done | `openclaw/skills/sigilum/SKILL.md`, `openclaw/hooks/sigilum-plugin/handler.ts`, `openclaw/hooks/sigilum-plugin/HOOK.md` | Clarified approval-denied guidance to require explicit `APPROVAL_*` fields in user-facing instructions. |

## Execution Log

- [x] Create this checklist.
- [x] R-001 fixed: removed eval-style config parsing fallback in installer/auth/doctor scripts.
- [x] R-002 fixed: improved gateway-admin transport + explicit approval context outputs and skill guidance.
- [x] R-003 fixed: bounded request body reads + explicit 413 handling.
- [x] R-004 fixed: duplicate critical signed-header rejection before verification.
- [x] R-005 fixed: MCP session isolation per connection/auth context.
- [x] R-006 fixed: split gateway authorization into smaller modular helpers.
- [x] R-007 fixed: explicit runtime/skill permission normalization during install.
- [x] R-008 fixed: added first-time deterministic validation runbook and linked docs.
- [x] R-009 fixed: clarified approval-required instructions in skill/hook guidance.
- [x] Complete items in priority order.
- [x] After each completed item: update status here, run relevant tests, stage, and commit.
