# Detailed Review Pass 3 (Gateway + OpenClaw + Scripts)

Scope:
- Go gateway (`apps/gateway/service/**`) with focus on MCP, authorization verification, request forwarding, and admin surfaces.
- OpenClaw integration (`openclaw/**`) including installer, skills, hooks, and gateway admin helper.
- CLI/admin/support scripts (`scripts/**`, `sigilum`).

Pass 1 validation summary:
- `detailed_review.md` items R-001 through R-009 were re-checked and are present in code.
- No unresolved Pass 1 item required a `detailed_review_pass2.md` follow-up.

Legend:
- Priority: `P0` critical, `P1` high, `P2` medium, `P3` low.
- Status: `open`, `in-progress`, `done`.

| ID | Priority | Tags | Status | Files | Issue |
|---|---|---|---|---|---|
| P3-001 | P0 | security, bug, gateway, architecture | done | `apps/gateway/service/cmd/sigilum-gateway/main.go`, `apps/gateway/service/cmd/sigilum-gateway/authorization.go`, `apps/gateway/service/cmd/sigilum-gateway/main_test.go` | Added centralized admin access enforcement across all `/api/admin/*` handlers. With signed-admin-check mode enabled, non-loopback admin requests are denied consistently. |
| P3-002 | P1 | security, bug, install, scripts | done | `openclaw/install-openclaw-sigilum.sh`, `scripts/sigilum-auth.sh` | Owner JWT is now only written into hook env when `sigilum-authz-notify` is enabled, and installer output no longer prints raw JWT values. |
| P3-003 | P1 | performance, bug, mcp, gateway | done | `apps/gateway/service/cmd/sigilum-gateway/runtime.go`, `apps/gateway/service/cmd/sigilum-gateway/runtime_helpers.go`, `apps/gateway/service/cmd/sigilum-gateway/main_test.go` | Added guarded MCP auto-discovery (`shouldAutoDiscoverMCPTools`) so empty-tool responses do not trigger rediscovery on every request after initial discovery. |
| P3-004 | P1 | security, permissions, install, scripts | done | `openclaw/install-openclaw-sigilum.sh`, `scripts/sigilum-auth.sh` | Added hook permission normalization during install and enforced best-effort `0600` permissions for `openclaw.json` writes in installer/auth update paths. |
| P3-005 | P2 | design, architecture, gateway, readability | done | `apps/gateway/service/cmd/sigilum-gateway/main.go`, `apps/gateway/service/cmd/sigilum-gateway/authorization.go` | Extracted admin-gate enforcement into `enforceAdminRequestAccess` and reused it for every admin route to remove duplicated/inconsistent checks. |

## Execution Log

- [x] Re-read and validate `detailed_review.md` pass-1 fixes.
- [x] Complete scoped review (gateway MCP/auth/forwarding + OpenClaw skills/hooks/install + scripts).
- [x] Fix P3-001, update this file, test, stage, commit.
- [x] Fix P3-002, update this file, test, stage, commit.
- [x] Fix P3-003, update this file, test, stage, commit.
- [x] Fix P3-004, update this file, test, stage, commit.
- [x] Fix P3-005, update this file, test, stage, commit.
