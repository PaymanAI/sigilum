# Sigilum Script Inventory (Consolidated)

This is the canonical script surface for this repository after consolidation.

Design rule:
- `sigilum` is the single command router.
- No wrapper-of-wrapper dispatch.
- Each script below has one explicit responsibility.

## User-facing entrypoints

| Script | Invoked as | Purpose |
|---|---|---|
| `sigilum` | `sigilum ...` | Top-level CLI router. Handles global env flags and dispatches to the right script/module. |
| `scripts/install-curl.sh` | `curl ... | bash` | Release install path from GitHub Releases tarballs. |
| `scripts/install-sigilum.sh` | `sigilum install` | Source-checkout install path (symlink + shell PATH wiring). |

## Core CLI command scripts

| Script | Invoked as | Purpose |
|---|---|---|
| `scripts/sigilum-auth.sh` | `sigilum auth ...` | Namespace-owner JWT login/refresh/show (managed and oss-local flows). |
| `scripts/sigilum-openclaw.sh` | `sigilum openclaw ...` | OpenClaw command surface (`install`, `uninstall`, `status`). |
| `scripts/sigilum-doctor.sh` | `sigilum doctor` | Local diagnostics: tools, runtime status, OpenClaw posture, health checks, and machine-readable output via `--json`. |
| `scripts/sigilum-down.sh` | `sigilum down` | Stops local listeners on known Sigilum development ports. |
| `scripts/run-local-api-gateway.sh` | `sigilum up` | Starts local API + gateway stack and bootstraps local defaults. |
| `scripts/run-demo-e2e.sh` | `sigilum e2e-tests` | Full local e2e bring-up, seeding, simulator validation. |
| `scripts/test-agent-simulator.mjs` | `sigilum agent-simulator` | Auth behavior simulator against running API/gateway/services. |
| `scripts/gateway-pair-bridge.mjs` | `sigilum gateway pair ...` | Managed dashboard pairing bridge (session/pair-code relay). |

## Service management scripts

| Script | Invoked as | Purpose |
|---|---|---|
| `scripts/shell-common.sh` | sourced by install/ops scripts | Shared shell helpers (color/log output, rc file detection, idempotent rc updates). |
| `scripts/sigilum-service-common.sh` | sourced by service scripts | Shared helpers (D1, gateway admin/CLI, secret handling, formatting). |
| `scripts/sigilum-service-add.sh` | `sigilum service add ...` | Register native/gateway services and persist service API keys/secrets. |
| `scripts/sigilum-service-list.sh` | `sigilum service list ...` | List services with native vs gateway mode inference. |
| `scripts/sigilum-service-secret.sh` | `sigilum service secret set ...` | Rotate/set upstream secret for an existing gateway connection. |

## Build/guard scripts

| Script | Invoked as | Purpose |
|---|---|---|
| `scripts/build-release.sh` | manual release build | Creates release tarball plus `.sha256` checksum (and optional `.sha256.sig` signature). |
| `scripts/check-config-guards.sh` | `pnpm config:guards` | Prevents prod/staging templates from enabling unsafe local seed endpoint. |

## Removed redundant wrappers

The following wrappers were removed as redundant dispatch layers:
- `scripts/sigilum-gateway.sh`
- `scripts/sigilum-service.sh`

Their behavior now routes directly inside `sigilum` to:
- `scripts/gateway-pair-bridge.mjs`
- `scripts/sigilum-service-add.sh`
- `scripts/sigilum-service-list.sh`
- `scripts/sigilum-service-secret.sh`
