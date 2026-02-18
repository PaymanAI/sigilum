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
- `--auth-mode <mode>`: `bearer` or `header_key` (default: `bearer`)
- `--upstream-header <name>`: upstream auth header name
- `--auth-prefix <value>`: auth header prefix (for example `Bearer `)
- `--upstream-secret-key <key>`: key name used in gateway secrets map
- `--upstream-secret <value>`: provide token/secret directly
- `--upstream-secret-env <name>`: read token/secret from env var
- `--upstream-secret-file <path>`: read token/secret from file
- `--gateway-admin-url <url>`: gateway admin endpoint (default `http://127.0.0.1:38100`)
- `--gateway-data-dir <path>`: fallback local gateway data dir if admin API is not reachable
- `--gateway-master-key <value>`: fallback gateway master key for CLI mode

Notes:

- Use only one secret source: `--upstream-secret` or `--upstream-secret-env` or `--upstream-secret-file`.
- If none is provided, a random secret is generated and saved.
- Service API keys are persisted in `.sigilum-workspace/service-api-key-<service-slug>`.
- Gateway upstream secrets are persisted in `.sigilum-workspace/gateway-connection-secret-<service-slug>`.

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
