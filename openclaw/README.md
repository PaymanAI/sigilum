# Sigilum OpenClaw Integration (v1)

Status: Active v1 source of truth for Sigilum/OpenClaw integration assets in this repository.

## What is implemented

Canonical packages:

- `openclaw/hooks/sigilum-plugin/`
- `openclaw/hooks/sigilum-authz-notify/`
- `openclaw/skills/sigilum/`

Skill status:

- Active: `openclaw/skills/sigilum/`
- Legacy and not required: `openclaw/skills/bootstrap/`, `openclaw/skills/linear/`, `openclaw/skills/sigilum-linear/`

Installer and CLI entrypoints:

- `openclaw/install-openclaw-sigilum.sh`
- `./sigilum openclaw install ...`
- `./sigilum openclaw status`

## Quick install

```bash
./sigilum openclaw install --namespace johndee --mode managed
./sigilum openclaw status
```

This installs hooks/skills into `~/.openclaw` and patches `~/.openclaw/openclaw.json`.

For a deterministic first-time validation path, use:

- `docs/cli/GATEWAY_OPENCLAW_VALIDATION.md`

Local OSS mode:

```bash
./sigilum openclaw install --namespace johndee --mode oss-local
```

In `oss-local`, install auto-issues a local namespace-owner JWT (when `--owner-token` is not supplied), stores it under `~/.openclaw/.sigilum/owner-token-<namespace>.jwt`, and prints it.
Install output also prints:

- dashboard claims URL
- passkey setup URL (`/bootstrap/passkey?namespace=<namespace>`)

Mode defaults:

- `managed`: `api=https://api.sigilum.id`, `gateway=http://localhost:38100`
- `oss-local`: `api=http://127.0.0.1:8787`, `gateway=http://localhost:38100`

## Can this work without hacking OpenClaw core?

Yes, for v1 integration flows.

OpenClaw already exposes enough extension points:

- Hooks (`gateway:startup`, `command:new`, reload events)
- Skills (command wrappers and workflows)
- Plugins (optional, external load paths)
- Provider/channel config (`models.providers.*.baseUrl`, channel proxy settings where supported)

## Proxy wiring examples

Current OpenClaw integration examples route through HTTP proxy paths (`/proxy/{connection_id}/...`).
Gateway MCP runtime support (`/mcp/{connection_id}/...`) is configured at gateway/dashboard level and can be used by clients that speak MCP directly.

Model provider through Sigilum gateway endpoint:

```json
{
  "models": {
    "providers": {
      "sigilum-openai": {
        "baseUrl": "http://127.0.0.1:38100/proxy/sigilum-secure-openai/v1",
        "apiKey": "sigilum-provider-proxy-key",
        "api": "openai-completions",
        "models": [{ "id": "gpt-5", "name": "GPT-5" }]
      }
    }
  }
}
```

Channel proxy fields (where channel supports a proxy setting) are configured directly in OpenClaw channel config, for example `channels.telegram.proxy` or `channels.discord.proxy`.

## Key custody reality (important)

### LLM provider keys

Possible to move provider credentials into Sigilum gateway, with caveats:

- Route model traffic to Sigilum gateway/proxy endpoint.
- OpenClaw still expects provider auth config shape for model providers. In practice, use a Sigilum-local token/sentinel there, not raw upstream provider keys.

### Channel API keys (Slack/Telegram/WhatsApp/etc.)

Not fully removable from OpenClaw runtime with stock channel adapters.

Reason:

- Core channel adapters use provider tokens directly for websocket/bootstrap/auth flows.
- Without replacing those adapters (plugin route), OpenClaw still needs channel credentials at runtime.

So for channel keys, v1 supports:

1. Keep channel tokens in OpenClaw runtime (current default).
2. Build dedicated channel adapter plugins that speak only to Sigilum gateway.
3. Startup hook token hydration from a local secret source (still present in OpenClaw memory at runtime).

## Hooks shipped in this repo

### `sigilum-plugin`

Purpose:

- Bootstraps one Sigilum Ed25519 keypair per OpenClaw agent ID.
- Runs on startup/new/reload events.

Required env:

- `SIGILUM_NAMESPACE`

Optional env:

- `SIGILUM_GATEWAY_URL`
- `SIGILUM_API_URL`
- `SIGILUM_DASHBOARD_URL`
- `SIGILUM_KEY_ROOT`
- `SIGILUM_AUTO_BOOTSTRAP_AGENTS`

### Attach passkey for seeded namespace (JWT-only)

When namespace owner was seeded locally (JWT exists, no passkey yet):

1. Open the installer-provided passkey setup URL.
2. Paste JWT from `~/.openclaw/.sigilum/owner-token-<namespace>.jwt` (or `sigilum auth show --namespace <namespace>`).
3. Register a passkey.
4. Sign in via dashboard login page with that passkey.

### `sigilum-authz-notify`

Purpose:

- Optional notification hook for pending Sigilum authorization requests.

Security model:

- Disabled by default in installer.
- Requires namespace owner token (`SIGILUM_OWNER_TOKEN`) to call owner-protected API routes.

## Skills shipped in this repo

### `sigilum`

- Gateway-first provider workflow skill.
- Default behavior after install:
  - check `sigilum-secure-*` gateway runtime access first for provider access (for example `sigilum-secure-linear`)
  - use signed `/mcp/{connection_id}/tools` checks with per-agent key material from `SIGILUM_KEY_ROOT`
  - treat `401/403` as authorization-required (claim approval needed for that agent key)
  - avoid direct provider API key prompts unless gateway path fails
- Installer enables the skill, and the `sigilum-plugin` hook injects gateway-first routing guidance on startup/new/reload events.

## Installer behavior

`openclaw/install-openclaw-sigilum.sh`:

1. Installs hooks to `<openclaw-home>/hooks/`
2. Installs skills to `<openclaw-home>/skills/` and mirrors them to `<agent-workspace>/skills/` when workspace is configured
3. Bundles a lean Sigilum runtime (`sigilum` launcher + scripts) to `<agent-workspace>/.sigilum/runtime` when workspace is configured (fallback: `<openclaw-home>/skills/sigilum/runtime`)
4. Backs up and updates `openclaw.json`
5. Sets Sigilum env wiring under hook/skill entries
6. Leaves `sigilum-authz-notify` disabled unless explicitly enabled

Lean-runtime note:

- Sandbox runtime focuses on gateway/provider operations.
- Full local-dev stack workflows (`sigilum up`, `service`, `e2e-tests`) remain host-side workflows.

Backup details:

- Each install creates `openclaw.json.bak.<timestamp>`.
- If Sigilum hook/skill directories already exist, install moves them to:
  - `<openclaw-home>/backups/hooks/sigilum-plugin.bak.<timestamp>`
  - `<openclaw-home>/backups/hooks/sigilum-authz-notify.bak.<timestamp>`
  - `<openclaw-home>/backups/skills/sigilum.bak.<timestamp>`
- This backup behavior is part of the installer; OpenClaw restart itself does not create these backups.
- Use `--force` to replace existing hook/skill directories without creating directory backups.

Enable authz notifications explicitly:

```bash
./sigilum openclaw install \
  --namespace johndee \
  --enable-authz-notify true \
  --owner-token '<namespace-owner-jwt>'
```

Token refresh / relogin commands:

```bash
./sigilum auth refresh --mode oss-local --namespace johndee
./sigilum auth login --mode managed --namespace johndee --owner-token-stdin
```

## Security contract

- No legacy `X-Sigilum-*` header workflow in new integration assets.
- Hooks are source-controlled (no hidden tarball-only logic).
- Owner-token based notification hook is opt-in and disabled by default.
