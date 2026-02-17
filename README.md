# Sigilum

Auditable identity for AI agents.

Sigilum is an open protocol and implementation effort focused on verifiable agent identity, signed delegation chains, and machine-speed accountability for AI systems.

## Autonomous Agent Instructions

If an autonomous coding agent is operating on this repo, do this first:

1. Read this `README.md` fully.
2. Open and read every link in the `Quick Links` section.
3. From `docs/README.md`, follow and read the API, gateway, SDK, and CLI docs.
4. Treat code as source of truth if any doc appears stale.

Minimum required docs before making changes:
- `MANIFESTO.md`
- `docs/README.md`
- `docs/cli/README.md`
- `apps/api/README.md`
- `apps/gateway/README.md`
- `sdks/README.md`

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

## Agent Quickstart

If you hand this repo to a coding agent and want a full local bring-up plus validation, ask it to run exactly:

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

## Prerequisites

- Node.js `>=20`
- pnpm `10.29.3` (via Corepack recommended)
- Go `>=1.23` (SDK and gateway)
- Java `21` + Maven `>=3.9` (Java SDK tests)
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

## Run Locally

Start API + gateway:

```bash
./sigilum up
```

Run full local e2e flow (recommended smoke test):

```bash
./sigilum e2e-tests
```

By default, `e2e-tests` performs a clean start by stopping listeners on ports `8787`, `38100`, `11000`, `11100` before bootstrapping.
Set `SIGILUM_E2E_CLEAN_START=false` to reuse already running processes.

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

```bash
(cd sdks/sdk-java && mvn test)
```

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
- `apps/` - runnable applications.
- `config/` - shared TypeScript config package (`@sigilum/config`).
- `contracts/` - smart contracts and Foundry project.
- `sdks/` - language SDKs (TS, Python, Go, Java) and shared SDK test vectors.
- `releases/` - release artifacts and metadata.

## Quick Links

- [Manifesto](./MANIFESTO.md)
- [Docs Index](./docs/README.md)
- [CLI Guide](./docs/cli/README.md)
- [SDKs Index](./sdks/README.md)
- [API Guide](./apps/api/README.md)
- [Gateway Guide](./apps/gateway/README.md)
