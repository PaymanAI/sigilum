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
| R-002 | P0 | security, reliability, ux, scripts | open | `openclaw/skills/sigilum/bin/gateway-admin.sh`, `openclaw/skills/sigilum/SKILL.md` | Gateway helper depends on bash `/dev/tcp`, only supports HTTP, and provides weak operator guidance on approval-required failures. Add robust transport path and explicit approval metadata output (namespace, agent id, key, service, required action). |
| R-003 | P1 | security, performance, bug, gateway | open | `apps/gateway/service/cmd/sigilum-gateway/runtime.go` | Proxy/MCP runtime reads request bodies without hard limit, creating memory pressure/DoS risk. Add configurable max request-body limits and `413` handling. |
| R-004 | P1 | security, architecture, gateway | open | `apps/gateway/service/cmd/sigilum-gateway/runtime.go`, `apps/gateway/service/cmd/sigilum-gateway/runtime_helpers.go` | Signature verification path accepts ambiguous duplicate signed headers (first-value wins). Reject duplicate critical Sigilum/signature headers before verification. |
| R-005 | P1 | performance, bug, mcp, gateway | open | `apps/gateway/service/internal/mcp/client.go`, `apps/gateway/service/internal/mcp/client_test.go` | MCP session cache keyed only by endpoint; different connections sharing endpoint can collide sessions and trigger stale/invalid session behavior. Isolate session keys per connection/auth context. |
| R-006 | P1 | architecture, design, readability, gateway | open | `apps/gateway/service/cmd/sigilum-gateway/runtime.go` | Authorization flow is monolithic and difficult to reason about. Split into small explicit helper functions and clarify control flow with focused comments. |
| R-007 | P2 | security, permissions, install | open | `openclaw/install-openclaw-sigilum.sh` | Runtime install sets broad recursive permissions but does not explicitly enforce executable bits for runtime command scripts after copy. Harden permission normalization for scripts/binaries. |
| R-008 | P2 | documentation, ux, developer-experience | open | `openclaw/README.md`, `apps/gateway/README.md` | End-to-end first-time validation steps are spread across files and ambiguous. Add a single deterministic step-by-step validation path with expected outcomes and failure diagnostics. |
| R-009 | P2 | documentation, design, skills | open | `openclaw/skills/sigilum/SKILL.md`, `openclaw/hooks/sigilum-plugin/handler.ts` | Skill/hook guidance is partially redundant and not explicit enough for approval-denied workflows. Make instructions unambiguous, minimal, and deterministic. |

## Execution Log

- [ ] Create this checklist.
- [x] R-001 fixed: removed eval-style config parsing fallback in installer/auth/doctor scripts.
- [ ] Complete items in priority order.
- [ ] After each completed item: update status here, run relevant tests, stage, and commit.
