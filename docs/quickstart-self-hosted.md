# Quickstart: Self-Hosted / Local Development

Use `oss-local` mode for local development, testing, or fully self-hosted deployments. This runs the open-source API and gateway locally - no hosted services required.

## Prerequisites

- Node.js >= 20
- pnpm 10.29.3 (via Corepack)
- Go >= 1.23
- Python >= 3.11 (optional, for Python SDK tests)

## Step 1: Clone and Bootstrap

```bash
git clone https://github.com/PaymanAI/sigilum.git
cd sigilum
corepack enable && corepack prepare pnpm@10.29.3 --activate
pnpm install
pnpm --dir sdks/sdk-ts build
```

## Step 2: Start the Local Stack

```bash
./sigilum up
```

This starts:
- API on `http://127.0.0.1:8787`
- Gateway on `http://127.0.0.1:38100`

Verify:

```bash
curl -sf http://127.0.0.1:8787/health
curl -sf http://127.0.0.1:38100/health
```

> By default, gateway binaries are prebuilt to `./.local/bin/` to reduce memory pressure. Set `GATEWAY_BUILD_BINARIES=false` to force `go run` mode for fast iteration.

### Low-Memory Environments (e.g. 4 GB Docker/OpenClaw)

If you hit OOM on first run, build gateway binaries separately first:

```bash
mkdir -p ./.local/bin
(cd apps/gateway/service && go build -o ../../../.local/bin/sigilum-gateway ./cmd/sigilum-gateway)
(cd apps/gateway/service && go build -o ../../../.local/bin/sigilum-gateway-cli ./cmd/sigilum-gateway-cli)
./sigilum up
```

## Step 3: Set Source Home (for Global CLI)

If you installed `sigilum` globally but want local API workflows:

```bash
export SIGILUM_SOURCE_HOME="$(pwd)"
```

## Step 4: Register Services

**Native service** (your own Sigilum-aware service):

```bash
./sigilum service add \
  --service-slug my-native-service \
  --service-name "My Native Service" \
  --mode native
```

**Gateway-routed service** (proxy through gateway):

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

**Query-parameter auth** (for APIs like Typefully):

```bash
export TYPEFULLY_API_KEY="tfy_..."
./sigilum service add \
  --service-slug typefully \
  --service-name "Typefully" \
  --mode gateway \
  --upstream-base-url https://mcp.typefully.com \
  --auth-mode query_param \
  --upstream-header TYPEFULLY_API_KEY \
  --upstream-secret-env TYPEFULLY_API_KEY
```

List services:

```bash
./sigilum service list --namespace johndee
```

## Step 5: Install OpenClaw Integration (Optional)

```bash
./sigilum openclaw install --mode oss-local --namespace johndee --api-url http://127.0.0.1:8787
```

In `oss-local` mode, the installer auto-issues a local namespace-owner JWT and prints:
- Dashboard URL
- Passkey setup URL for attaching a passkey to the seeded namespace

## Step 6: Run End-to-End Tests

```bash
./sigilum e2e-tests
```

This boots demo services, seeds test authorization state, and runs the agent simulator to verify:
- Signed approved requests succeed
- Unsigned requests are rejected
- Signed unapproved requests fail

## Step 7: Verify

```bash
./sigilum doctor                         # local diagnostics
./sigilum doctor --json                  # machine-readable output
./sigilum doctor --fix                   # auto-remediate common issues
./sigilum openclaw status                # OpenClaw integration status
```

## Local Data Paths

| Path | Contents |
|------|----------|
| `./.sigilum-workspace` | Workspace identities and bootstrap keys |
| `./.local/gateway-data` | Gateway local data store (BadgerDB) |
| `./.local/bin` | Prebuilt gateway binaries |
| `./apps/api/.wrangler/state/` | API local D1 SQLite files |

## Stop the Stack

```bash
./sigilum down
```

## Owner Token Management

```bash
# Issue/refresh local owner JWT
./sigilum auth refresh --mode oss-local --namespace johndee

# Show stored token
./sigilum auth show --namespace johndee
```

## Next Steps

- [CLI Reference](./cli/README.md) - full command reference
- [API Reference](../apps/api/README.md) - API endpoints and environment variables
- [Gateway Reference](../apps/gateway/README.md) - gateway configuration and admin API
- [SDK Testing](../sdks/README.md) - run SDK tests
