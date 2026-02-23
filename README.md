# Sigilum

Auditable identity for AI agents.

Sigilum is an open protocol for verifiable agent identity, signed delegation chains, and machine-speed accountability for AI systems.

## Quickstart (Managed Mode - Recommended)

Managed mode uses the hosted Sigilum API and dashboard at [sigilum.id](https://sigilum.id). Your gateway runs locally - provider API keys never leave your machine.

### 1. Sign up and reserve your namespace

Go to [sigilum.id](https://sigilum.id), create an account, and reserve a namespace (e.g. `johndee`).

### 2. Install the CLI and start the gateway

> Run these commands on the same machine where your OpenClaw instance is hosted (DigitalOcean, AWS, VPS, etc.). The gateway runs alongside your agent.

```bash
curl -fsSL https://github.com/PaymanAI/sigilum/releases/latest/download/install-curl.sh | bash
source ~/.zshrc
sigilum gateway start --namespace johndee
```

### 3. Pair with the dashboard

In the dashboard, click **Start Pairing** and run the command it gives you:

```bash
sigilum gateway pair --session-id <id> --pair-code <code> --namespace johndee --api-url https://api.sigilum.id
```

### 4. Add providers via the dashboard

Use the dashboard to add provider connections (OpenAI, Linear, etc.). Secrets are stored locally in your gateway.

### 5. Install OpenClaw integration (optional)

```bash
sigilum openclaw install --namespace johndee
```

> For the complete managed-mode walkthrough, see [docs/quickstart-managed.md](./docs/quickstart-managed.md).

---

## Self-Hosted / Local Development

For local development, testing, or fully self-hosted deployments:

```bash
git clone https://github.com/PaymanAI/sigilum.git && cd sigilum
corepack enable && corepack prepare pnpm@10.29.3 --activate
pnpm install && pnpm --dir sdks/sdk-ts build
./sigilum up          # starts local API + gateway
./sigilum e2e-tests   # runs full end-to-end validation
```

> For the complete self-hosted guide, see [docs/quickstart-self-hosted.md](./docs/quickstart-self-hosted.md).

---

## How It Works

Sigilum separates **control plane** from **data plane**:

- **Control plane** (Sigilum API + dashboard): manages identity, authorization state, approvals/revocations, and notifications.
- **Data plane** (Sigilum gateway): enforces request signing, approved-claim checks, and proxies requests to upstream providers. Provider secrets stay in your gateway.

### Deploy Modes

| Mode | Control Plane | Gateway | Use Case |
|------|--------------|---------|----------|
| `managed` | Hosted ([api.sigilum.id](https://api.sigilum.id)) | Customer-side (local/VM/VPC) | **Recommended.** Production use. |
| `enterprise` | Self-hosted | Self-hosted | Full on-prem/private network. |
| `oss-local` | Local (open-source API) | Local | Development and testing. |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Managed Quickstart](./docs/quickstart-managed.md) | Complete managed-mode setup guide |
| [Self-Hosted Quickstart](./docs/quickstart-self-hosted.md) | OSS/local development setup |
| [Docs Index](./docs/README.md) | Full documentation index |
| [CLI Reference](./docs/cli/README.md) | All CLI commands and options |
| [API Reference](./apps/api/README.md) | API endpoints and flows |
| [Gateway Reference](./apps/gateway/README.md) | Gateway behavior and configuration |
| [SDKs](./sdks/README.md) | TypeScript, Python, Go SDK guides |
| [OpenClaw Integration](./openclaw/README.md) | Hooks, skills, and installer |
| [Protocol Specs](./docs/protocol/README.md) | DID method, SDK signing profile |
| [Manifesto](./MANIFESTO.md) | Why Sigilum exists |

## For AI Agents

If you are an autonomous coding agent operating on this repository:

1. Read [`AGENT_RUNBOOK.md`](./AGENT_RUNBOOK.md) first.
2. Read this README fully.
3. Follow links to component docs as needed.
4. Treat code as source of truth if any doc appears stale.

## Repository Structure

```
├── apps/
│   ├── api/          # Sigilum API (Cloudflare Workers)
│   └── gateway/      # Sigilum Gateway (Go)
├── config/           # Shared TypeScript config (@sigilum/config)
├── contracts/        # Smart contracts (Foundry)
├── docs/             # Project documentation
├── openclaw/         # OpenClaw integration (hooks, skills, installer)
├── releases/         # Release artifacts and metadata
└── sdks/             # Language SDKs (TS, Python, Go; Java placeholder)
```

## Prerequisites

- Node.js >= 20, pnpm 10.29.3 (via Corepack)
- Go >= 1.23 (gateway and Go SDK)
- Python >= 3.11 (optional, Python SDK)
- Java 21 + Maven >= 3.9 (optional, Java SDK placeholder)

## License

See [LICENSE](./LICENSE).
