# Sigilum

Auditable identity for AI agents.

Sigilum is an open protocol and implementation effort focused on verifiable agent identity, signed delegation chains, and machine-speed accountability for AI systems.

## Start Here

### Autonomous Agent (Required)

If an autonomous coding agent is operating on this repository:

1. Open and follow [`AGENT_RUNBOOK.md`](./AGENT_RUNBOOK.md) first.
2. Then read this `README.md` fully.
3. Open and read every link in the `Quick Links` section.
4. From `docs/README.md`, follow API, gateway, SDK, and CLI docs.
5. Treat code as source of truth if any doc appears stale.

Minimum required docs before making changes:
- `MANIFESTO.md`
- `AGENT_RUNBOOK.md`
- `docs/README.md`
- `docs/cli/README.md`
- `apps/api/README.md`
- `apps/gateway/README.md`
- `sdks/README.md`

### Human Quickstart

From repository root:

```bash
corepack enable
corepack prepare pnpm@10.29.3 --activate
pnpm install
pnpm --dir sdks/sdk-ts build
./sigilum e2e-tests
```

What this does:
- installs dependencies
- builds the TS SDK used by local simulator/e2e flows
- boots local API + gateway (blockchain mode disabled)
- bootstraps local workspace identity/services under namespace `johndee`
- starts bundled demo services and runs pass/fail auth simulator tests

Gateway startup defaults to prebuilt binaries (`./.local/bin/sigilum-gateway*`) to reduce memory pressure versus `go run`.

## OpenClaw / Docker Low-Memory Guidance

For OpenClaw-style agents running in Docker/sandboxed environments (for example 4 GB RAM), expect higher memory pressure during first startup.

Guidelines:
- use `./sigilum up` (default path builds/reuses gateway binaries to avoid `go run` memory spikes)
- avoid manually running `go run ./cmd/sigilum-gateway` while Wrangler API is compiling/starting
- first run may take longer because it compiles gateway binaries and bootstraps local state
- if OOM happens on first run, build gateway binaries first, then run stack:

```bash
mkdir -p ./.local/bin
(cd apps/gateway/service && go build -o ../../../.local/bin/sigilum-gateway ./cmd/sigilum-gateway)
(cd apps/gateway/service && go build -o ../../../.local/bin/sigilum-gateway-cli ./cmd/sigilum-gateway-cli)
./sigilum up
```

What to expect on first successful run:
- creates local workspace at `./.sigilum-workspace`
- creates gateway binaries in `./.local/bin`
- creates gateway data in `./.local/gateway-data`
- creates local D1 state under `./apps/api/.wrangler/state`
- auto-creates `./apps/api/wrangler.toml` from `./apps/api/wrangler.toml.example` if missing

## Prerequisites

- Node.js `>=20`
- pnpm `10.29.3` (via Corepack recommended)
- Go `>=1.23` (SDK and gateway)
- Java `21` + Maven `>=3.9` (optional; Java SDK is currently a placeholder)
- Python `>=3.11` (optional, for Python SDK tests)

## Local Setup

From repo root:

```bash
corepack enable
corepack prepare pnpm@10.29.3 --activate
pnpm install
pnpm --dir sdks/sdk-ts build
```

Note:
- local scripts auto-create `apps/api/wrangler.toml` from `apps/api/wrangler.toml.example` when needed
- `apps/api/wrangler.toml` is local-only and should not be committed

Optional CLI install:

```bash
./sigilum install
source ~/.zshrc
```

If you do not install globally, use `./sigilum ...` directly.

OpenClaw integration install:

```bash
./sigilum openclaw install --namespace johndee --mode managed
# local stack mode:
# ./sigilum openclaw install --namespace johndee --mode oss-local
```

Managed onboarding:
- Open `https://sigilum.id`
- sign in and reserve your namespace (for example `johndee`)
- then run:

```bash
./sigilum auth login --mode managed --namespace johndee --owner-token-stdin
```

`sigilum-authz-notify` is disabled by default so OpenClaw does not load namespace-owner JWT unless you explicitly enable it.

Owner token helpers:

```bash
# local mode: issue/refresh owner JWT for hooks
./sigilum auth refresh --mode oss-local --namespace johndee

# managed mode: paste owner JWT from dashboard login flow
./sigilum login --mode managed --namespace johndee --owner-token-stdin
```

## Deploy Modes

Sigilum separates control plane from data plane:

- Control plane: Sigilum API + dashboard (identity/authz state, approvals/revokes, notifications)
- Data plane: Sigilum gateway (request enforcement/proxy + upstream provider secrets)

Supported deployment modes:

1. `managed`
- Hosted API + hosted dashboard
- Gateway runs customer-side (local/VM/VPC)
- Provider API keys/tokens stay in customer gateway, not in Sigilum-hosted control plane

2. `enterprise`
- Enterprise-hosted API + enterprise-hosted dashboard + enterprise-hosted gateway
- Full on-prem/private network deployment supported

3. `oss-local`
- Open-source API + open-source gateway only (no dashboard source required)
- Intended for local development, tests, and self-hosted CLI-driven workflows

Managed-mode command boundary:

- `sigilum login --mode managed` stores namespace-owner JWT for local hooks after managed dashboard login (`api.sigilum.id`)
- `sigilum up`, `sigilum down`, and `sigilum service ...` are local operations

## Run Locally

Start API + gateway:

```bash
./sigilum up
```

Stop local stack listeners:

```bash
./sigilum down
```

Run diagnostics:

```bash
./sigilum doctor
```

Run full local e2e flow (recommended smoke test):

```bash
./sigilum e2e-tests
```

By default, `e2e-tests` performs a clean start by stopping listeners on ports `8787`, `38100`, `11000`, `11100` before bootstrapping.
Set `SIGILUM_E2E_CLEAN_START=false` to reuse already running processes.
Simulator seeding uses local API endpoint `POST /v1/test/seed` (disabled by default, enabled only for e2e with a per-run token) instead of direct `wrangler d1 execute` writes.
CI enforces that prod/staging config templates do not enable this endpoint (`pnpm config:guards`).

This starts:
- API on `http://127.0.0.1:8787`
- Gateway on `http://127.0.0.1:38100`
- Demo native service on `http://127.0.0.1:11000`
- Demo gateway upstream service on `http://127.0.0.1:11100`

Low-memory mode notes:
- default behavior already uses prebuilt gateway binaries (`GATEWAY_BUILD_BINARIES=true`)
- to force `go run` mode for fast gateway iteration: `GATEWAY_BUILD_BINARIES=false ./sigilum up`

## Register Services (CLI)

Native Sigilum service:

```bash
./sigilum service add \
  --service-slug my-native-service \
  --service-name "My Native Service" \
  --mode native
```

Gateway-routed service (example: Linear token):

```bash
export LINEAR_TOKEN="lin_api_..."
./sigilum service add \
  --service-slug linear \
  --service-name "Linear" \
  --mode gateway \
  --upstream-base-url https://api.linear.app \
  --auth-mode bearer \
  --upstream-secret-env LINEAR_TOKEN
```

Query-parameter auth is also supported (for providers that require API keys in URL query, e.g. `?TYPEFULLY_API_KEY=...`) using `--auth-mode query_param` and `--upstream-header <query_key>`.

List services in a namespace:

```bash
./sigilum service list --namespace johndee
```

Rotate/update gateway upstream secret for a service:

```bash
export LINEAR_TOKEN="lin_api_..."
./sigilum service secret set --service-slug linear --upstream-secret-env LINEAR_TOKEN
```

Security default:
- `sigilum service add` and `sigilum service secret set` mask raw secret values in output by default.
- use `--reveal-secrets` only when you intentionally need plaintext output in terminal history/logs.

Protocol and shared credential notes:
- `sigilum service add --mode gateway` is the HTTP proxy flow.
- MCP connections are supported in gateway (`protocol: mcp`) and are typically configured through dashboard provider setup or `sigilum-gateway-cli`.
- Service-catalog `env_var` fields are dashboard hints for shared credential variables (not automatic process env reads by gateway).
- Shared variables can be reused across multiple connections by storing secret references like `{{var:OPENAI_API_KEY}}`.

Does usage change?
- Existing HTTP onboarding stays the same.
- New optional step if you want reuse across providers: create one shared credential variable and reference it from each connection.

## Run SDK Tests

TypeScript SDK:

```bash
pnpm --dir sdks/sdk-ts build
pnpm --dir sdks/sdk-ts test
pnpm --dir sdks/sdk-ts test:conformance
```

Go SDK:

```bash
(cd sdks/sdk-go && go test ./...)
```

Java SDK:

- `sdks/sdk-java` is currently a placeholder and is not yet supported for runtime use.

Python SDK (optional):

```bash
python3 -m pip install -e sdks/sdk-python pytest
python3 -m pytest sdks/sdk-python/tests
```

## Local Data Paths

- Workspace identities and local bootstrap keys: `./.sigilum-workspace`
- Gateway local data store: `./.local/gateway-data`
- API local D1 SQLite files (Wrangler/Miniflare): `./apps/api/.wrangler/state/.../*.sqlite`

Find current local SQLite file:

```bash
find apps/api/.wrangler/state -name '*.sqlite' -print
```

## Repository Structure

- `MANIFESTO.md` - project vision, problem framing, and sequence of goals.
- `LICENSE` - open source license for this repository.
- `docs/` - project documentation.
- `openclaw/` - OpenClaw integration assets (hooks, skills, installer).
- `apps/` - runnable applications.
- `config/` - shared TypeScript config package (`@sigilum/config`).
- `contracts/` - smart contracts and Foundry project.
- `sdks/` - language SDKs (TS, Python, Go; Java placeholder) and shared SDK test vectors.
- `releases/` - release artifacts and metadata.

## Quick Links

- [Agent Runbook (Agents start here)](./AGENT_RUNBOOK.md)
- [Manifesto](./MANIFESTO.md)
- [Docs Index](./docs/README.md)
- [CLI Guide](./docs/cli/README.md)
- [SDKs Index](./sdks/README.md)
- [API Guide](./apps/api/README.md)
- [Gateway Guide](./apps/gateway/README.md)
- [OpenClaw Integration](./openclaw/README.md)
