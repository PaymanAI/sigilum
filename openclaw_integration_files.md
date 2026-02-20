# OpenClaw Integration Files and Environment Variables

This is the canonical OpenClaw integration reference for this repository.

Scope:
- Sigilum CLI entrypoints used for OpenClaw integration
- OpenClaw installer/uninstaller and config mutators
- OpenClaw hook + skill runtime contracts
- Local `oss-local` bridge variables used during install/auth bootstrap

## Integration File Map

## CLI and install entrypoints

| File | Purpose | Modify when |
|---|---|---|
| `sigilum` | Top-level CLI router for `openclaw`, `auth`, `gateway`, `up/down`, and shared env flags. | CLI command wiring/global flags change. |
| `scripts/sigilum-openclaw.sh` | OpenClaw command surface (`install`, `uninstall`, `status`). | OpenClaw UX/command contract changes. |
| `openclaw/install-openclaw-sigilum.sh` | Installs hooks/skill/runtime, updates `openclaw.json`, prints onboarding flow. | Install flow, defaults, runtime bundle, or onboarding changes. |
| `openclaw/uninstall-openclaw-sigilum.sh` | Removes Sigilum artifacts and cleans OpenClaw config/defaults. | Uninstall scope/safety rules change. |
| `scripts/sigilum-auth.sh` | Owner-token login/refresh/show used by OpenClaw install and manual auth flows. | JWT/bootstrap behavior changes. |

## OpenClaw config mutation

| File | Purpose | Modify when |
|---|---|---|
| `openclaw/lib/update-openclaw-config.mjs` | Source of truth for writing Sigilum env + hook/skill entries into `openclaw.json`. | Any persisted env contract/schema changes. |
| `openclaw/lib/remove-openclaw-sigilum-config.mjs` | Removes Sigilum hook/skill/env entries from `openclaw.json`. | Uninstall config cleanup changes. |
| `openclaw/lib/detect-workspace.mjs` | Detects OpenClaw workspace path. | OpenClaw workspace schema changes. |
| `openclaw/lib/detect-runtime-root.mjs` | Computes runtime-root default destination. | Runtime placement policy changes. |
| `openclaw/lib/detect-sigilum-paths.mjs` | Detects workspace/key/runtime/sigilum-home paths for uninstall cleanup. | Path detection policy changes. |

## Runtime contracts

| File | Purpose | Modify when |
|---|---|---|
| `openclaw/hooks/sigilum-plugin/config.ts` | Resolves plugin env contract and defaults. | Plugin env names/defaults change. |
| `openclaw/hooks/sigilum-plugin/handler.ts` | Bootstraps agent keys and injects gateway-first policy. | Plugin runtime behavior changes. |
| `openclaw/hooks/sigilum-authz-notify/handler.ts` | Optional pending-authorization notifications for namespace owner. | Notify logic/API route contract changes. |
| `openclaw/skills/sigilum/bin/gateway-admin.sh` | Signed gateway helper for MCP tool discovery/calls. | Signing/runtime gateway behavior changes. |
| `openclaw/skills/sigilum/bin/sigilum-openclaw.sh` | Runtime resolver for selecting the `sigilum` launcher binary. | Runtime resolution order changes. |

## Consolidation Notes

- CLI dispatch is centralized in `sigilum`.
- Redundant wrappers were removed:
  - `scripts/sigilum-gateway.sh`
  - `scripts/sigilum-service.sh`

## Environment Variables (Complete Catalog)

Legend:
- Scope:
  - `installer input`: read by install/uninstall scripts
  - `persisted`: written to `openclaw.json` or `~/.sigilum/config.env`
  - `runtime`: read by hooks/skills at runtime
  - `local bridge`: used when installer starts/uses local OSS stack

## 1) CLI global passthrough (`sigilum`)

| Variable | Scope | Purpose |
|---|---|---|
| `SIGILUM_CONFIG_HOME` | installer input | Directory used for persisted Sigilum defaults (`~/.sigilum` by default). |
| `SIGILUM_CONFIG_FILE` | installer input | Explicit defaults file path (`$SIGILUM_CONFIG_HOME/config.env`). |
| `OPENCLAW_HOME` | installer input | OpenClaw home root used for config detection. |
| `OPENCLAW_CONFIG_PATH` | installer input | Explicit OpenClaw config path override. |
| `SIGILUM_NAMESPACE` | installer input/runtime | Namespace selection for auth/install/runtime helper flows. |
| `GATEWAY_SIGILUM_NAMESPACE` | installer input/runtime | Gateway namespace override; also set from `--namespace`. |
| `GATEWAY_SIGILUM_HOME` | installer input/runtime | Sigilum home directory for local gateway identity/artifacts. |
| `GATEWAY_ADMIN_URL` | local bridge/runtime | Gateway admin API endpoint override. |
| `GATEWAY_DATA_DIR` | local bridge/runtime | Gateway local data dir override for CLI fallback. |
| `GATEWAY_MASTER_KEY` | local bridge/runtime | Gateway encryption/master key for local CLI fallback. |
| `API_PORT` | local bridge | Local API port override. |
| `GATEWAY_PORT` | local bridge | Local gateway port override (also mapped to `GATEWAY_ADDR`). |
| `NATIVE_PORT` | local bridge | Local demo native service port override. |
| `UPSTREAM_PORT` | local bridge | Local demo upstream service port override. |
| `GATEWAY_ADDR` | local bridge | Gateway bind address (derived from `--gateway-port` if provided). |

## 2) Installer and uninstaller inputs

| Variable | Scope | Default | Purpose |
|---|---|---|---|
| `OPENCLAW_HOME` | installer input | `$HOME/.openclaw` | OpenClaw root for hooks/skills/config install. |
| `SIGILUM_MODE` | installer input | `managed` | Install mode: `managed` or `oss-local`. |
| `SIGILUM_SOURCE_HOME` | installer input/local bridge | unset | Source checkout root required for full `oss-local` API workflows. |
| `SIGILUM_NAMESPACE` | installer input | `$USER` | Namespace for hook/skill identity and onboarding. |
| `SIGILUM_GATEWAY_URL` | installer input/persisted | `http://localhost:38100` | Gateway base URL written to config env. |
| `SIGILUM_API_URL` | installer input/persisted | `https://api.sigilum.id` | API base URL written to config env. |
| `SIGILUM_RUNTIME_ROOT` | installer input/persisted | auto-detected | Runtime bundle destination path. |
| `SIGILUM_OWNER_TOKEN` | installer input/persisted | unset | Namespace-owner JWT for `sigilum-authz-notify` hook. |
| `SIGILUM_DASHBOARD_URL` | installer input/persisted | `https://sigilum.id` | Dashboard URL for onboarding/notifications. |
| `SIGILUM_AUTO_OWNER_TOKEN` | installer input | `true` in `oss-local` when token missing | Whether installer should auto-issue local owner token. |
| `SIGILUM_OWNER_EMAIL` | installer input | `<namespace>@local.sigilum` | Email used for local owner bootstrap. |
| `SIGILUM_AUTO_START` | installer input/local bridge | `true` | Whether install should auto-start local stack if loopback endpoints are down. |
| `SIGILUM_CONFIG_HOME` | installer input | `$HOME/.sigilum` | Directory for installer-managed defaults file. |
| `SIGILUM_CONFIG_FILE` | installer input | `$SIGILUM_CONFIG_HOME/config.env` | Installer-managed defaults file path. |
| `SIGILUM_HOME` | installer input | unset | Candidate source for key-sync into runtime home. |
| `GATEWAY_SIGILUM_HOME` | installer input | unset | Additional candidate source for key-sync into runtime home. |
| `NO_COLOR` | installer input | unset | Disables colored output for install/uninstall scripts. |

## 3) Installer-managed defaults file (`~/.sigilum/config.env`)

Written by `openclaw/install-openclaw-sigilum.sh`, removed by uninstall only when managed marker is present.

| Variable | Scope | Purpose |
|---|---|---|
| `SIGILUM_OPENCLAW_MANAGED` | persisted | Marker that defaults file was created by OpenClaw installer. |
| `SIGILUM_NAMESPACE` | persisted | Default namespace for future CLI sessions. |
| `GATEWAY_SIGILUM_NAMESPACE` | persisted | Default gateway namespace for local stack commands. |
| `SIGILUM_API_URL` | persisted | Default API URL for CLI flows. |
| `SIGILUM_GATEWAY_URL` | persisted | Default gateway URL for CLI flows. |

## 4) `openclaw.json` global env vars (`config.env.vars`)

Written by `openclaw/lib/update-openclaw-config.mjs`.

| Variable | Scope | Purpose |
|---|---|---|
| `SIGILUM_GATEWAY_URL` | persisted/runtime | Global gateway URL for runtime processes. |
| `SIGILUM_AGENT_ID` | persisted/runtime | Default agent ID used by skill helper signing. |
| `SIGILUM_RUNTIME_ROOT` | persisted/runtime | Runtime root path. |
| `SIGILUM_RUNTIME_BIN` | persisted/runtime | Absolute launcher path (`<runtime_root>/sigilum`). |
| `SIGILUM_GATEWAY_HELPER_BIN` | persisted/runtime | Gateway helper path used by skill flows. |
| `SIGILUM_HOME` | persisted/runtime | Runtime home path used for artifact lookup (optional). |

Removed during uninstall:
- `SIGILUM_GATEWAY_URL`
- `SIGILUM_AGENT_ID`
- `SIGILUM_RUNTIME_ROOT`
- `SIGILUM_RUNTIME_BIN`
- `SIGILUM_GATEWAY_HELPER_BIN`
- `SIGILUM_HOME`

## 5) Hook env vars (`hooks.internal.entries`)

### `sigilum-plugin` hook env

| Variable | Scope | Purpose |
|---|---|---|
| `SIGILUM_MODE` | persisted/runtime | Signals managed vs oss-local mode. |
| `SIGILUM_NAMESPACE` | persisted/runtime | Namespace for key bootstrap and policy context. |
| `SIGILUM_GATEWAY_URL` | persisted/runtime | Gateway URL used for connection inventory/policy messaging. |
| `SIGILUM_API_URL` | persisted/runtime | API URL used in startup messaging context. |
| `SIGILUM_DASHBOARD_URL` | persisted/runtime | Dashboard/passkey links shown in startup output. |
| `SIGILUM_KEY_ROOT` | persisted/runtime | Filesystem root for per-agent keypairs. |
| `SIGILUM_AUTO_BOOTSTRAP_AGENTS` | persisted/runtime | Enables auto key bootstrap for configured agents. |
| `SIGILUM_GATEWAY_ADMIN_TOKEN` | runtime override | Optional bearer token for gateway admin inventory calls. |

### `sigilum-authz-notify` hook env

| Variable | Scope | Purpose |
|---|---|---|
| `SIGILUM_MODE` | persisted/runtime | Mode indicator for hook context. |
| `SIGILUM_NAMESPACE` | persisted/runtime | Namespace used to query pending claims. |
| `SIGILUM_API_URL` | persisted/runtime | API URL for pending claims endpoint. |
| `SIGILUM_DASHBOARD_URL` | persisted/runtime | Dashboard URL shown in notifications. |
| `SIGILUM_OWNER_TOKEN` | persisted/runtime | Owner JWT (only set when hook is enabled + token provided). |

## 6) Skill env vars (`skills.entries.sigilum.env`)

| Variable | Scope | Purpose |
|---|---|---|
| `SIGILUM_MODE` | persisted/runtime | Mode indicator for skill behavior. |
| `SIGILUM_NAMESPACE` | persisted/runtime | Namespace claim for signed gateway requests. |
| `SIGILUM_AGENT_ID` | persisted/runtime | Default signing agent id. |
| `SIGILUM_GATEWAY_URL` | persisted/runtime | Gateway base URL for helper calls. |
| `SIGILUM_API_URL` | persisted/runtime | API URL context for skill workflows. |
| `SIGILUM_KEY_ROOT` | persisted/runtime | Keypair directory for signed requests. |
| `SIGILUM_RUNTIME_ROOT` | persisted/runtime | Runtime root path. |
| `SIGILUM_RUNTIME_BIN` | persisted/runtime | Runtime launcher path. |
| `SIGILUM_GATEWAY_HELPER_BIN` | persisted/runtime | Signed helper binary path. |
| `SIGILUM_HOME` | persisted/runtime | Optional runtime home path. |

## 7) Runtime-only skill/helper variables

Read by `openclaw/skills/sigilum/bin/gateway-admin.sh` and `openclaw/skills/sigilum/bin/sigilum-openclaw.sh`.

| Variable | Scope | Purpose |
|---|---|---|
| `SIGILUM_GATEWAY_URL` | runtime | Gateway URL for signed `tools/call` requests. |
| `SIGILUM_NAMESPACE` | runtime | Required namespace claim in signatures. |
| `SIGILUM_KEY_ROOT` | runtime | Keypair lookup root. |
| `SIGILUM_AGENT_ID` | runtime | Preferred agent identity for signing. |
| `OPENCLAW_AGENT_ID` | runtime | Fallback agent identity candidate. |
| `OPENCLAW_AGENT` | runtime | Additional fallback agent identity candidate. |
| `SIGILUM_SUBJECT` | runtime | Optional explicit subject claim override. |
| `SIGILUM_HTTP_TIMEOUT_SECONDS` | runtime | Timeout for helper HTTP requests. |
| `SIGILUM_ALLOW_INSECURE_ADMIN` | runtime | Enables legacy insecure `list/test/discover` admin helpers. |
| `SIGILUM_RUNTIME_BIN` | runtime | First-priority launcher path in runtime resolver. |
| `SIGILUM_RUNTIME_ROOT` | runtime | Runtime root fallback in launcher resolver. |
| `SIGILUM_CLI_PATH` | runtime | Legacy explicit CLI path fallback. |
| `SIGILUM_REPO_ROOT` | runtime | Legacy source-root fallback (`<repo>/sigilum`). |
| `OPENCLAW_HOME` | runtime | Used to derive workspace runtime fallback path. |

## 8) Local `oss-local` bridge variables (installer/auth interaction)

Used when install auto-issues local owner tokens or auto-starts local loopback API/gateway.

| Variable | Scope | Purpose |
|---|---|---|
| `JWT_SECRET` | local bridge | Secret used by `scripts/sigilum-auth.sh` for local JWT issuance. |
| `SIGILUM_OWNER_TOKEN_TTL_SECONDS` | local bridge | TTL override for local owner token issuance. |
| `SIGILUM_OWNER_TOKEN` | local bridge | Explicit owner token input override. |
| `SIGILUM_OWNER_EMAIL` | local bridge | Owner email used when creating local namespace owner. |
| `API_HOST` | local bridge | Host binding for local API startup. |
| `API_PORT` | local bridge | Port binding for local API startup. |
| `SIGILUM_REGISTRY_URL` | local bridge | Local API URL alias used by startup scripts. |
| `SIGILUM_API_URL` | local bridge | Local API URL used in startup and auth flows. |
| `SIGILUM_NAMESPACE` | local bridge | Namespace for local auth/bootstrap. |
| `GATEWAY_SIGILUM_NAMESPACE` | local bridge | Namespace for local gateway identity bootstrap. |
| `GATEWAY_ADDR` | local bridge | Gateway bind address for local startup. |

## Persistence Flow

```text
sigilum openclaw install
  -> openclaw/install-openclaw-sigilum.sh
    -> openclaw/lib/update-openclaw-config.mjs
      -> ~/.openclaw/openclaw.json
         - config.env.vars (global env)
         - hooks.internal.entries["sigilum-plugin"].env
         - hooks.internal.entries["sigilum-authz-notify"].env
         - skills.entries.sigilum.env
    -> ~/.sigilum/config.env (installer-managed CLI defaults)
```

Runtime precedence:
- `process.env` overrides values from `openclaw.json`.

## Change Rules

1. Treat `openclaw/lib/update-openclaw-config.mjs` as the single source of truth for persisted env schema.
2. If a variable is renamed/removed, update:
   - installer/uninstaller scripts
   - hook/skill runtime readers
   - this document
3. Keep hook and skill entry names stable (`sigilum-plugin`, `sigilum-authz-notify`, `sigilum`) unless migration logic is updated in the same change.
4. For security-sensitive vars (`SIGILUM_OWNER_TOKEN`, `JWT_SECRET`, signing vars), update docs and tests/runbooks in the same PR.
