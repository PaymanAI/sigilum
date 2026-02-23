# Quickstart: Managed Mode

Managed mode is the recommended way to use Sigilum. The hosted API and dashboard handle identity management, authorization approvals, and notifications. Your gateway runs locally - **provider API keys never leave your machine**.

## Prerequisites

- A terminal with `bash` and `curl`
- Node.js >= 20 (for OpenClaw integration, if used)

## Step 1: Install the Sigilum CLI

```bash
curl -fsSL https://github.com/PaymanAI/sigilum/releases/latest/download/install-curl.sh | bash
source ~/.zshrc
sigilum --help
```

To pin a specific version:

```bash
curl -fsSL https://github.com/PaymanAI/sigilum/releases/download/<tag>/install-curl.sh | bash -s -- --version <tag>
```

## Step 2: Sign Up and Reserve Your Namespace

1. Open [sigilum.id](https://sigilum.id)
2. Create an account (passkey-based WebAuthn auth)
3. Reserve your namespace (e.g. `johndee`)

Your namespace becomes your DID: `did:sigilum:johndee`

## Step 3: Authenticate Locally

After signing in to the dashboard, copy your owner token and authenticate the CLI:

```bash
sigilum auth login --mode managed --namespace johndee --owner-token-stdin
```

Paste the token and press Enter, then Ctrl+D.

> Note: `sigilum-authz-notify` is disabled by default so the owner JWT is not loaded into OpenClaw runtime unless you explicitly enable it.

## Step 4: Start the Gateway

```bash
sigilum gateway start --namespace johndee
```

The gateway runs locally on port `38100` by default.

## Step 5: Pair the Gateway with the Dashboard

In the dashboard, initiate a pairing session. You'll receive a session ID and pair code. Run:

```bash
sigilum gateway pair \
  --session-id <session-id> \
  --pair-code <pair-code> \
  --namespace johndee \
  --api-url https://api.sigilum.id
```

Keep this process running while the dashboard setup is active. The pairing bridge relays dashboard admin commands to your local gateway through the API.

## Step 6: Add Provider Connections

Use the dashboard to add providers (OpenAI, Linear, Typefully, etc.):

- For **HTTP providers**: the dashboard configures upstream URL and auth credentials stored locally in your gateway.
- For **MCP providers**: select `protocol: mcp`, configure the MCP endpoint, and run discovery.

Provider secrets are encrypted and stored locally in your gateway's BadgerDB at `GATEWAY_DATA_DIR/badger`. They never leave your machine.

You can also manage connections via CLI:

```bash
# Add an HTTP provider
export LINEAR_TOKEN="lin_api_..."
sigilum service add \
  --service-slug linear \
  --service-name "Linear" \
  --mode gateway \
  --upstream-base-url https://api.linear.app \
  --auth-mode bearer \
  --upstream-secret-env LINEAR_TOKEN

# List registered services
sigilum service list --namespace johndee
```

For full CLI options, see [CLI Reference](./cli/README.md).

## Step 7: Install OpenClaw Integration (Optional)

If you use [OpenClaw](https://openclaw.com), install the Sigilum hooks and skills:

```bash
sigilum openclaw install --namespace johndee
```

This installs:
- **sigilum-plugin** hook: bootstraps per-agent Ed25519 keys on startup
- **sigilum** skill: gateway-first provider access workflow
- **sigilum-authz-notify** hook (disabled by default): pending authorization notifications

See [OpenClaw Integration](../openclaw/README.md) for details.

## Step 8: Verify

```bash
sigilum doctor          # check local health
sigilum openclaw status # check OpenClaw integration (if installed)
```

## How It Works

```
┌─────────────────┐         ┌──────────────────┐         ┌──────────────┐
│   AI Agent      │ signed  │  Sigilum Gateway  │  auth   │  Provider    │
│   (OpenClaw)    │────────>│  (your machine)   │────────>│  (OpenAI,    │
│                 │ request │                   │ request │   Linear...) │
└─────────────────┘         └────────┬──────────┘         └──────────────┘
                                     │ claims check
                                     v
                            ┌──────────────────┐
                            │  Sigilum API      │
                            │  (api.sigilum.id) │
                            └──────────────────┘
```

1. Agent sends a signed request to the local gateway
2. Gateway verifies the signature and checks the approved-claims cache
3. If approved, gateway injects provider credentials and forwards upstream
4. If not approved, gateway returns `AUTH_CLAIM_REQUIRED` - approve via dashboard

## Credential Rotation

```bash
export LINEAR_TOKEN="lin_api_new_..."
sigilum service secret set --service-slug linear --upstream-secret-env LINEAR_TOKEN
```

## Next Steps

- [Gateway Error Codes](./product/GATEWAY_ERROR_CODES.md) - troubleshoot gateway errors
- [Onboarding Checklists](./product/ONBOARDING_CHECKLISTS.md) - production readiness checklist
- [Gateway Reference](../apps/gateway/README.md) - full gateway configuration
