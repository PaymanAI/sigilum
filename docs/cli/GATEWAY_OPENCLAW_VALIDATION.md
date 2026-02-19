# Gateway + OpenClaw Validation Runbook

Use this checklist to validate Sigilum gateway, OpenClaw install, skills, hooks, and approval flow from a clean developer setup.

## 1. Prerequisites

Run from repo root (`/Users/prashanth/Work/OpenSource/sigilum`):

```bash
command -v node pnpm go curl openssl awk od
```

Expected: each command prints a path.

If `curl` is missing:
- `openclaw/skills/sigilum/bin/gateway-admin.sh` falls back to HTTP-only `/dev/tcp` transport.
- HTTPS gateway/admin URLs will fail with a clear error telling you to install `curl`.

## 2. Start Local Stack

```bash
./sigilum down
./sigilum up
```

Wait for:
- API health: `http://127.0.0.1:8787/health` returns `200`
- Gateway health: `http://127.0.0.1:38100/health` returns `200`

Quick check:

```bash
curl -sf http://127.0.0.1:8787/health
curl -sf http://127.0.0.1:38100/health
```

## 3. Install OpenClaw Integration

```bash
./sigilum openclaw install --namespace johndee --mode oss-local
```

Expected installer behavior:
- Installs hooks under `~/.openclaw/hooks/`
- Installs skill under `~/.openclaw/skills/sigilum`
- Bundles runtime under workspace/runtime path printed in output
- Backs up `openclaw.json` before patching
- Creates owner token for `oss-local` mode (unless provided)

## 4. Verify Installed File Permissions

```bash
stat -f '%Sp %N' \
  ~/.openclaw/skills/sigilum/bin/gateway-admin.sh \
  ~/.openclaw/skills/sigilum/bin/sigilum-openclaw.sh \
  ~/.openclaw/skills/sigilum/runtime/sigilum 2>/dev/null || true
```

Expected:
- scripts/binaries are executable for owner (`-rwx------` or stricter owner-exec variant depending on host)
- private key/token material remains owner-only

## 5. Verify Hook + Skill Wiring

```bash
./sigilum openclaw status
./sigilum doctor
```

Expected:
- `sigilum-plugin` present and enabled
- `sigilum` skill present and enabled
- `sigilum-authz-notify` defaults to disabled unless explicitly enabled
- doctor reports no failures

## 6. MCP Tool List Check (Signed)

Use the helper directly:

```bash
~/.openclaw/skills/sigilum/bin/gateway-admin.sh tools sigilum-secure-linear http://127.0.0.1:38100
```

Expected output always includes:
- `HTTP_STATUS=<code>`

Possible outcomes:
- `HTTP_STATUS=200`: connection is accessible for this agent key.
- `HTTP_STATUS=404`: connection is missing.
- `HTTP_STATUS=401` or `HTTP_STATUS=403`: approval required.

## 7. Approval-Required Flow Verification

When `HTTP_STATUS=401|403` and body includes `AUTH_FORBIDDEN`, helper now prints explicit approval metadata:

- `APPROVAL_REQUIRED=true`
- `APPROVAL_NAMESPACE=...`
- `APPROVAL_AGENT_ID=...`
- `APPROVAL_SUBJECT=...`
- `APPROVAL_PUBLIC_KEY=ed25519:...`
- `APPROVAL_SERVICE=...`
- `APPROVAL_MESSAGE=...`

If auto-claim submission is attempted, you may also get:
- `CLAIM_HTTP_STATUS=...`
- `CLAIM_ERROR=...`

Use these exact `APPROVAL_*` values in user-facing approval requests; do not ask users to guess namespace/agent/key.

## 8. End-to-End Simulator

```bash
./sigilum e2e-tests
```

Expected:
- simulator summary shows all checks passing
- unsigned requests are rejected
- signed approved requests pass
- signed unapproved requests fail

## 9. Managed Mode Spot Check

```bash
./sigilum openclaw install --namespace johndee --mode managed
```

Expected:
- output includes managed onboarding steps
- if owner token is not provided, authz-notify remains disabled by default

## 10. Troubleshooting

### Parse errors in OpenClaw config

Install/auth/doctor now use strict JSON/JSON5 parsing (no eval fallback).
If parse fails, fix `~/.openclaw/openclaw.json` syntax (or install JSON5 support when relying on JSON5-only syntax).

### HTTPS helper failures

If helper says HTTPS requires curl:
- install `curl`, or
- use local HTTP gateway URL for local-only validation.

### Approval blocked

If helper returns `APPROVAL_REQUIRED=true` repeatedly:
1. Confirm service exists (`HTTP_STATUS` not `404`).
2. Approve the exact `APPROVAL_PUBLIC_KEY` for `APPROVAL_SERVICE` in namespace `APPROVAL_NAMESPACE`.
3. Retry the signed tools call.

### Restricted sandbox runtime

In minimal sandboxes, missing commands or blocked network access are surfaced explicitly by scripts.
Follow the error text first; it now names the missing command/transport requirement rather than failing silently.
