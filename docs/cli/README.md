# Sigilum CLI

Local developer CLI for running the Sigilum local stack, registering services, and running end-to-end tests.

## Install

From repository root:

```bash
./sigilum install
```

Optional alias setup:

```bash
./sigilum install --with-alias
```

After install, reload your shell:

```bash
source ~/.zshrc
```

Install command options:

- `--bin-dir <path>`: symlink destination (default `~/.local/bin`)
- `--rc-file <path>`: shell rc file to update (auto-detected by default)
- `--with-alias`: add `alias sigilum="<repo>/sigilum"` in rc file

## Help

Top-level help:

```bash
sigilum --help
```

Service help:

```bash
sigilum service help
```

Install help:

```bash
sigilum install --help
```

OpenClaw integration help:

```bash
sigilum openclaw help
```

Auth helper help:

```bash
sigilum auth --help
```

Doctor help:

```bash
sigilum doctor --help
```

## Global Options

Global options are accepted before the command:

```bash
sigilum [global-options] <command> [args]
```

- `--namespace <value>`: sets `GATEWAY_SIGILUM_NAMESPACE`
- `--sigilum-home <path>`: sets `GATEWAY_SIGILUM_HOME`
- `--gateway-admin-url <url>`: sets `GATEWAY_ADMIN_URL`
- `--gateway-data-dir <path>`: sets `GATEWAY_DATA_DIR`
- `--gateway-master-key <value>`: sets `GATEWAY_MASTER_KEY`
- `--api-port <port>`: sets `API_PORT`
- `--gateway-port <port>`: sets `GATEWAY_PORT`
- `--native-port <port>`: sets `NATIVE_PORT`
- `--upstream-port <port>`: sets `UPSTREAM_PORT`
- if neither `GATEWAY_SIGILUM_NAMESPACE` nor `SIGILUM_NAMESPACE` is set, `sigilum` loads a default namespace from `~/.sigilum/config.env` (`SIGILUM_NAMESPACE` or `GATEWAY_SIGILUM_NAMESPACE`) before `sigilum up`

## Commands

### `sigilum up`

Starts local API + gateway by running:

- `scripts/run-local-api-gateway.sh`

Behavior notes:

- by default, gateway binaries are built/reused from `./.local/bin` to reduce memory usage on small machines
- set `GATEWAY_BUILD_BINARIES=false` to force `go run` mode
- on low-memory Docker sandboxes (for example 4 GB), prefer keeping binary mode enabled and avoid running gateway compile tasks in parallel with Wrangler startup
- if `apps/api/wrangler.toml` is missing, the script auto-creates it from `apps/api/wrangler.toml.example`

Example:

```bash
sigilum up
```

### `sigilum down`

Stops local listeners on known Sigilum dev ports:

- API (`8787`)
- Gateway (`38100`)
- Demo native (`11000`)
- Demo upstream (`11100`)
- Envoy ingress/admin (`38000` / `38200`)

Example:

```bash
sigilum down
```

### `sigilum doctor`

Runs local diagnostics:

- required tools (`node`, `pnpm`, `go`, `curl`)
- optional Java/Maven presence for SDK tests
- wrangler config/template checks
- local identity/key-file checks
- API/gateway health checks
- OpenClaw config permissions and authz-notify token posture checks

Example:

```bash
sigilum doctor
```

### `sigilum gateway pair ...`

Starts the local websocket bridge used by dashboard pairing mode.

Use this when dashboard pairing shows a session id + pair code:

```bash
sigilum gateway pair --session-id <id> --pair-code <code> --namespace <namespace>
```

Optional flags:

- `--api-url <url>`: Sigilum API base URL (default from `SIGILUM_API_URL` / `SIGILUM_REGISTRY_URL` or `http://127.0.0.1:8787`)
- `--gateway-admin-url <url>`: local gateway admin endpoint (default `http://127.0.0.1:38100`)
- `--reconnect-ms <ms>`: websocket reconnect delay (default `2000`)
- `--connect-timeout-ms <ms>`: preflight/connect timeout (default `5000`)

Important:

- `--api-url` must point to the Sigilum API service, not the dashboard app.
  - Managed default: `https://api.sigilum.id`
  - Local OSS API default: `http://127.0.0.1:8787`
- Local gateway admin must be running on `--gateway-admin-url` (default `http://127.0.0.1:38100`), otherwise pairing relay cannot execute dashboard commands.

### `sigilum openclaw install ...`

Installs Sigilum OpenClaw hooks + skills into `~/.openclaw`, mirrors skill files into `<agent-workspace>/skills` when workspace is configured, bundles a lean runtime (`sigilum` launcher + scripts) under `<agent-workspace>/.sigilum/runtime` by default (fallback: `~/.openclaw/skills/sigilum/runtime`), and patches `openclaw.json`.

Lean-runtime note:
- Sandbox runtime is optimized for gateway/provider checks.
- Full local stack lifecycle/service bootstrap commands are host workflows.

Basic usage:

```bash
sigilum openclaw install
```

Interactive install prompts for:
- namespace
- OpenClaw home directory (`.openclaw`)
- Sigilum API URL (default `https://api.sigilum.id`)

Common options:

- `--openclaw-home <path>`
- `--config <path>`
- `--mode <managed|oss-local>` (default `managed`)
- `--source-home <path>` (required for `oss-local` when running from global/lean install)
- `--namespace <value>`
- `--gateway-url <url>`
- `--api-url <url>`
- `--interactive` or `--non-interactive`
- `--auto-start-sigilum <true|false>` (default `true` for local default ports)
- `--key-root <path>`
- `--runtime-root <path>`
- `--enable-authz-notify <true|false>` (default `false`)
- `--owner-token <token>` (required if authz notify enabled)
- `--auto-owner-token <true|false>` (default: `true` in `oss-local` if `--owner-token` not provided)
- `--owner-email <email>` (default: `<namespace>@local.sigilum`)
- `--restart`

MCP-first note:
- The legacy `sigilum-linear` skill is removed from this installer path.
- Use gateway/dashboard MCP provider connections for Linear and other MCP servers.

`oss-local` note:

- run install with `--api-url http://127.0.0.1:8787` when targeting a local API stack.
- if using globally-installed Sigilum CLI, also pass `--source-home /path/to/sigilum` so local API files are resolved from your checkout.
- installer auto-registers local namespace owner (if missing), issues local JWT, writes it to `<openclaw-home>/.sigilum/owner-token-<namespace>.jwt`, and prints it.
- installer prints dashboard URL and passkey setup URL (`/bootstrap/passkey?namespace=<namespace>`), so seeded namespaces can attach a passkey without deleting/re-signup.
- passkey setup page accepts namespace-owner JWT and registers a passkey, then you can sign in normally at `/login`.
- installer writes CLI defaults to `~/.sigilum/config.env` so future `sigilum up` launches reuse the installed namespace by default.

`managed` note:

- post-install output points to `https://sigilum.id` to sign in and reserve your namespace.
- after namespace registration, run `sigilum auth login --mode managed --namespace <namespace> --owner-token-stdin`.
- `sigilum-authz-notify` remains disabled by default to avoid loading namespace-owner token into OpenClaw runtime unless explicitly enabled.

### `sigilum openclaw uninstall`

Removes Sigilum OpenClaw footprint:
- hooks (`sigilum-plugin`, `sigilum-authz-notify`)
- skill (`sigilum`) in OpenClaw home and workspace mirror
- workspace `.sigilum` runtime folder and key/token directories
- Sigilum env/entries from `openclaw.json` (with config backup)
- installer-managed `~/.sigilum/config.env` defaults file (only when marked as `SIGILUM_OPENCLAW_MANAGED=true`)

Usage:

```bash
sigilum openclaw uninstall
```

Common options:

- `--openclaw-home <path>`
- `--config <path>`
- `--workspace <path>`
- `--key-root <path>`
- `--runtime-root <path>`
- `--sigilum-home <path>`

Status:

```bash
sigilum openclaw status
```

Status output also includes configured namespace, dashboard URL, passkey setup URL, runtime root, and runtime existence.

Validation runbook:

- `docs/cli/GATEWAY_OPENCLAW_VALIDATION.md`

### `sigilum auth ...`

Bootstrap and manage namespace-owner JWT tokens used by `sigilum-authz-notify`.

Local login/issue:

```bash
sigilum auth login --mode oss-local --namespace johndee
```

Refresh local token:

```bash
sigilum auth refresh --mode oss-local --namespace johndee
```

Managed mode (token from browser/passkey flow):

```bash
sigilum auth login --mode managed --namespace johndee --owner-token-stdin
```

Show stored token:

```bash
sigilum auth show --namespace johndee
```

Alias:

- `sigilum login` is equivalent to `sigilum auth login`.

### `sigilum service add ...`

Registers a service in local API DB, creates/stores service API key, and (for gateway mode) creates/updates gateway connection + upstream secret.

Basic usage:

```bash
sigilum service add --service-slug <slug> [options]
```

General options:

- `--service-slug <slug>` (required)
- `--service-name <name>` (default: slug)
- `--description <text>`
- `--domain <domain>` (default: `localhost`)
- `--namespace <namespace>` (default: `johndee`, or `GATEWAY_SIGILUM_NAMESPACE`)
- `--email <email>` (default: `<namespace>@local.sigilum`)
- `--mode <native|gateway>` (default: `native`)

Gateway mode options:

- `--upstream-base-url <url>` (required in gateway mode)
- `--auth-mode <mode>`: `bearer`, `header_key`, or `query_param` (default: `bearer`)
- `--upstream-header <name>`: upstream auth header name
- `--auth-prefix <value>`: auth header prefix (for example `Bearer `)
- `--upstream-secret-key <key>`: key name used in gateway secrets map
- `--upstream-secret <value>`: provide token/secret directly
- `--upstream-secret-env <name>`: read token/secret from env var
- `--upstream-secret-file <path>`: read token/secret from file
- `--reveal-secrets`: print raw key/secret values (default output masks secrets)
- `--gateway-admin-url <url>`: gateway admin endpoint (default `http://127.0.0.1:38100`)
- `--gateway-data-dir <path>`: fallback local gateway data dir if admin API is not reachable
- `--gateway-master-key <value>`: fallback gateway master key for CLI mode

Notes:

- Use only one secret source: `--upstream-secret` or `--upstream-secret-env` or `--upstream-secret-file`.
- If none is provided, a random secret is generated and saved.
- Service API keys are persisted in `.sigilum-workspace/service-api-key-<service-slug>`.
- Gateway upstream secrets are persisted in `.sigilum-workspace/gateway-connection-secret-<service-slug>`.
- Raw secret values are hidden by default in CLI output.

Protocol and credential source notes:

- `sigilum service add --mode gateway` provisions HTTP-style gateway connections.
- For MCP connections, use either:
  - dashboard provider setup (`protocol: mcp` templates), or
  - gateway CLI directly: `go run ./apps/gateway/service/cmd/sigilum-gateway-cli add --protocol mcp ...`
- Service-catalog templates may include `mcp_base_url` and `mcp_endpoint` defaults so dashboard protocol toggles can prefill the MCP target (for example Linear: `https://mcp.linear.app` + `/mcp`).
- `--upstream-secret-env` reads a shell environment variable once at command runtime, then stores the resolved value in gateway.
- This is different from service-catalog `credential_fields[].env_var`, which is a dashboard hint for reusable shared credential variables.
- Reusable shared credential variables are currently managed through dashboard or gateway admin API (`/api/admin/credential-variables`), then referenced as `{{KEY}}` in connection secrets.

Examples:

Native service:

```bash
sigilum service add \
  --service-slug my-native-service \
  --service-name "My Native Service" \
  --mode native
```

Gateway service (Linear bearer token):

```bash
export LINEAR_TOKEN="lin_api_..."

sigilum service add \
  --service-slug linear \
  --service-name "Linear" \
  --mode gateway \
  --upstream-base-url https://api.linear.app \
  --auth-mode bearer \
  --upstream-secret-env LINEAR_TOKEN
```

Gateway service (query parameter auth, for APIs that require `?API_KEY=...`):

```bash
export TYPEFULLY_API_KEY="tfy_..."

sigilum service add \
  --service-slug typefully \
  --service-name "Typefully" \
  --mode gateway \
  --upstream-base-url https://mcp.typefully.com \
  --auth-mode query_param \
  --upstream-header TYPEFULLY_API_KEY \
  --upstream-secret-key api_key \
  --upstream-secret-env TYPEFULLY_API_KEY
```

### `sigilum service list`

Lists services registered in local API DB for a namespace, and marks each as `native` or `gateway` when gateway connection metadata is available.

Examples:

```bash
sigilum service list --namespace johndee
sigilum service list --namespace johndee --json
```

### `sigilum service secret set`

Rotates/sets an upstream secret for an existing gateway connection and persists it in local workspace.

Examples:

```bash
export LINEAR_TOKEN="lin_api_..."
sigilum service secret set --service-slug linear --upstream-secret-env LINEAR_TOKEN

# explicit secret key + reveal
sigilum service secret set \
  --service-slug linear \
  --upstream-secret-key access_token \
  --upstream-secret-env LINEAR_TOKEN \
  --reveal-secrets
```

### `sigilum e2e-tests`

Runs end-to-end tests using bundled demo services:

- by default, performs clean-start by stopping listeners on ports `8787`, `38100`, `11000`, `11100`
- starts local stack
- starts demo native + gateway upstream services
- runs `scripts/test-agent-simulator.mjs` (seeds auth state via API `POST /v1/test/seed`, enabled only for local e2e with a per-run token)
- prints pass/fail matrix

Example:

```bash
sigilum e2e-tests
```

Reuse currently running processes instead of clean-start:

```bash
SIGILUM_E2E_CLEAN_START=false sigilum e2e-tests
```

### `sigilum agent-simulator`

Runs the agent simulator only (expects stack/services already running):

- creates approved/unapproved test identities
- seeds local authorization state for test namespaces
- sends signed and unsigned requests
- verifies pass/fail auth behavior for native and gateway paths

Example:

```bash
sigilum agent-simulator
```
