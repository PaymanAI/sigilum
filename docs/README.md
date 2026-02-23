# Sigilum Documentation

[![GitHub Release](https://img.shields.io/github/v/release/PaymanAI/sigilum?display_name=tag)](https://github.com/PaymanAI/sigilum/releases/latest)

## Getting Started

| Guide | Description |
|-------|-------------|
| [Managed Quickstart](./quickstart-managed.md) | **Start here.** Complete managed-mode setup: namespace -> install -> pair gateway -> add providers -> done. |
| [Self-Hosted Quickstart](./quickstart-self-hosted.md) | OSS/local development and testing setup. |
| [Agent Runbook](../AGENT_RUNBOOK.md) | Step-by-step runbook for autonomous AI agents. |

## Architecture & Components

| Component | Docs |
|-----------|------|
| [API](../apps/api/README.md) | Sigilum API - namespace identity, authorization lifecycle, DID resolution, webhooks. |
| [API Environment Variables](../apps/api/ENV_VARS.md) | API configuration, Cloudflare bindings, and mode-specific variable sets. |
| [Gateway](../apps/gateway/README.md) | Sigilum Gateway - request signing verification, claim enforcement, HTTP/MCP proxy, shared credentials. |
| [Gateway OpenAPI Schema](../apps/gateway/openapi.yaml) | Gateway admin and runtime endpoint schema. |

## CLI

| Doc | Description |
|-----|-------------|
| [CLI Reference](./cli/README.md) | Full command reference with examples. |
| [Script Inventory](./cli/SCRIPT_INVENTORY.md) | Canonical script surface and responsibilities. |
| [Gateway + OpenClaw Validation](./cli/GATEWAY_OPENCLAW_VALIDATION.md) | Step-by-step validation runbook for gateway, OpenClaw hooks, and approval flows. |

## SDKs

| SDK | Docs |
|-----|------|
| [SDK Index](../sdks/README.md) | Compatibility matrix, common signing contract, and testing. |
| [TypeScript SDK](../sdks/sdk-ts/README.md) | `@sigilum/sdk` - init, certify, sign, verify. |
| [Python SDK](../sdks/sdk-python/README.md) | `sigilum` - init, certify, sign, verify. |
| [Go SDK](../sdks/sdk-go/README.md) | `sigilum.local/sdk-go` - init, certify, sign, verify. |
| [Java SDK](../sdks/sdk-java/README.md) | Placeholder - not yet supported. |

## Protocol

| Spec | Description |
|------|-------------|
| [Protocol Index](./protocol/README.md) | Protocol definitions overview. |
| [DID Method `did:sigilum`](./protocol/DID_METHOD_SIGILUM.md) | DID syntax, CRUD operations, resolution API. |
| [SDK Signing Profile](./protocol/SDK_PROFILE.md) | Cross-language SDK signing contract (Ed25519, RFC 9421). |

## OpenClaw Integration

| Doc | Description |
|-----|-------------|
| [OpenClaw Overview](../openclaw/README.md) | Integration architecture, hooks, skills, installer. |
| [sigilum-plugin Hook](../openclaw/hooks/sigilum-plugin/HOOK.md) | Per-agent Ed25519 key bootstrap on startup. |
| [sigilum-authz-notify Hook](../openclaw/hooks/sigilum-authz-notify/HOOK.md) | Optional pending authorization notifications. |
| [sigilum Skill](../openclaw/skills/sigilum/SKILL.md) | Gateway-first provider access workflow. |
| [OpenClaw Environment Variables](../openclaw_integration_files.md) | Complete environment variable catalog for OpenClaw integration. |

## Product & Operations

| Doc | Description |
|-----|-------------|
| [Gateway Error Codes](./product/GATEWAY_ERROR_CODES.md) | Error code to operator-action mapping. |
| [Message Style Guide](./product/MESSAGE_STYLE_GUIDE.md) | Error/success message standards across CLI, API, SDK, and gateway. |
| [Onboarding Checklists](./product/ONBOARDING_CHECKLISTS.md) | Deployment-mode-specific onboarding checklists. |

## Project

| Doc | Description |
|-----|-------------|
| [Manifesto](../MANIFESTO.md) | Why Sigilum exists - the accountability problem for AI agents. |
| [Contributing](../CONTRIBUTING.md) | Contribution guidelines, agent-authored PR policy, commit format. |
