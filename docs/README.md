# Sigilum Docs

This folder contains all long-form project documentation.

Latest release: [![GitHub Release](https://img.shields.io/github/v/release/PaymanAI/sigilum?display_name=tag)](https://github.com/PaymanAI/sigilum/releases/latest)
Release tags: `YYYY-MM-DD` (stable) or `YYYY-MM-DD-beta.N` (prerelease), with optional leading `v`.

## Getting Started

- **[Managed Mode Quickstart](./quickstart-managed.md)** - Install, pair, and connect in 5 minutes (recommended for most users).
- **[Running as a Service](./running-as-service.md)** - systemd, launchd, and Docker production setup.

## Sections

- `architecture/` - system design, components, and trust boundaries.
- `cli/` - local developer CLI usage, commands, and examples.
- `protocol/` - identity and delegation protocol specs.
- `governance/` - trust registries, issuer policy, and operational governance.
- `compliance/` - regulatory mapping and audit requirements.
- `roadmap/` - milestones, phases, and delivery plan.
- `product/` - onboarding, UX, and product communication standards.

## API Docs

- [`apps/api/README.md`](../apps/api/README.md) - API guide and endpoint overview.
- [`apps/api/ENV_VARS.md`](../apps/api/ENV_VARS.md) - API environment variables and Cloudflare binding configuration.
- [`apps/gateway/README.md`](../apps/gateway/README.md) - Gateway behavior, routes, `sigilum-subject` policy semantics, HTTP/MCP protocol support, and shared credential variable (`env_var` hint) usage.
- [`apps/gateway/openapi.yaml`](../apps/gateway/openapi.yaml) - Gateway admin/runtime OpenAPI schema.
- [`docs/cli/README.md`](./cli/README.md) - Local CLI install, commands, options, and examples.
- [`docs/protocol/DID_METHOD_SIGILUM.md`](./protocol/DID_METHOD_SIGILUM.md) - DID method spec for `did:sigilum` and resolver behavior.

## SDK Docs

- [`sdks/README.md`](../sdks/README.md) - SDK index and shared contract notes.
- [`sdks/sdk-ts/README.md`](../sdks/sdk-ts/README.md) - TypeScript SDK.
- [`sdks/sdk-python/README.md`](../sdks/sdk-python/README.md) - Python SDK.
- [`sdks/sdk-go/README.md`](../sdks/sdk-go/README.md) - Go SDK.
- [`sdks/sdk-java/README.md`](../sdks/sdk-java/README.md) - Java SDK placeholder status.

## Product Docs

- [`docs/product/ONBOARDING_CHECKLISTS.md`](./product/ONBOARDING_CHECKLISTS.md) - canonical onboarding checklists by deployment mode.
- [`docs/product/MESSAGE_STYLE_GUIDE.md`](./product/MESSAGE_STYLE_GUIDE.md) - product-wide error/success message standards.
- [`docs/product/GATEWAY_ERROR_CODES.md`](./product/GATEWAY_ERROR_CODES.md) - gateway error-code to operator-action mapping.
