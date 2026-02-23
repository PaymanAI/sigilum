# Quickstart: Managed Mode

Managed mode is the recommended way to use Sigilum. The hosted API and dashboard handle identity management, authorization approvals, and notifications. Your gateway runs locally - **provider API keys never leave your machine**.

## Prerequisites

- A terminal with `bash` and `curl`
- Node.js >= 20 (for OpenClaw integration, if used)

## Step 1: Sign Up and Reserve Your Namespace

1. Open [sigilum.id](https://sigilum.id)
2. Create an account (passkey-based authentication)
3. Reserve your namespace (e.g. `johndee`)

Your namespace becomes your DID: `did:sigilum:johndee`

## Step 2: Install the CLI and Start the Gateway

Run this on the machine where your AI agent runs:

```bash
curl -fsSL https://github.com/PaymanAI/sigilum/releases/latest/download/install-curl.sh | bash
source ~/.zshrc
sigilum gateway start --namespace johndee
```

To pin a specific version:

```bash
curl -fsSL https://github.com/PaymanAI/sigilum/releases/download/<tag>/install-curl.sh | bash -s -- --version <tag>
```

The gateway runs locally on port `38100` by default.

## Step 3: Pair the Gateway with the Dashboard

In the dashboard, click **Start Pairing**. You'll receive a command with a session ID and pair code. Run it:

```bash
sigilum gateway pair \
  --session-id <session-id> \
  --pair-code <pair-code> \
  --namespace johndee \
  --api-url https://api.sigilum.id
```

The dashboard will show your gateway as connected once pairing completes.

## Step 4: Add Provider Connections

Use the dashboard to add providers (OpenAI, Linear, Typefully, etc.):

- For **HTTP providers**: the dashboard configures upstream URL and auth credentials stored locally in your gateway.
- For **MCP providers**: select `protocol: mcp`, configure the MCP endpoint, and run discovery.

Provider secrets are encrypted and stored locally in your gateway's BadgerDB at `GATEWAY_DATA_DIR/badger`. They never leave your machine.

## Step 5: Install OpenClaw Integration (Optional)

If you use [OpenClaw](https://openclaw.com), install the Sigilum hooks and skills:

```bash
sigilum openclaw install --namespace johndee
```

This installs:
- **sigilum-plugin** hook: bootstraps per-agent Ed25519 keys on startup
- **sigilum** skill: gateway-first provider access workflow
- **sigilum-authz-notify** hook (disabled by default): pending authorization notifications

See [OpenClaw Integration](../openclaw/README.md) for details.

## Step 6: Verify

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
