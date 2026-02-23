# Sigilum Agent Runbook

Use this runbook for end-to-end Sigilum setup without manual interpretation.

## 1) Mode Selection

| Mode | Use when | Requirement |
|---|---|---|
| **Managed** (recommended) | You need gateway + hosted Sigilum API/dashboard ([sigilum.id](https://sigilum.id)) | Release tarball install (gateway binary included). |
| **OSS Local** | You need local API + local gateway for development/testing | Full source checkout and `SIGILUM_SOURCE_HOME` set. |

Critical rule:
- Managed install needs only gateway runtime/binaries.
- Local API workflows require source code (`apps/api`) and `SIGILUM_SOURCE_HOME`.

## 2) Managed Mode (Release Tarball)

Full guide: [docs/quickstart-managed.md](./docs/quickstart-managed.md)

### 2.1 Install from GitHub Releases

```bash
curl -fsSL https://github.com/PaymanAI/sigilum/releases/latest/download/install-curl.sh | bash
source ~/.zshrc
sigilum --help
```

### 2.2 Start gateway runtime

```bash
sigilum gateway start --namespace "$SIGILUM_NAMESPACE"
```

### 2.3 Pair gateway with dashboard

In the dashboard, click **Start Pairing** to get session ID and pair code, then run:

```bash
sigilum gateway connect --session-id <session-id> --pair-code <pair-code> --namespace "$SIGILUM_NAMESPACE" --api-url https://api.sigilum.id
```

Verify bridge:

```bash
sigilum gateway pair --status
```

### 2.4 Install OpenClaw integration (managed mode)

```bash
sigilum openclaw install --namespace "$SIGILUM_NAMESPACE"
```

## 3) OSS Local Mode (Source)

Full guide: [docs/quickstart-self-hosted.md](./docs/quickstart-self-hosted.md)

### 3.1 Clone and bootstrap

```bash
git clone https://github.com/PaymanAI/sigilum.git
cd sigilum
corepack enable && corepack prepare pnpm@10.29.3 --activate
pnpm install
pnpm --dir sdks/sdk-ts build
```

### 3.2 Set source home

```bash
export SIGILUM_SOURCE_HOME="$(pwd)"
```

### 3.3 Start local stack

```bash
./sigilum up
```

### 3.4 Install OpenClaw integration (local mode)

```bash
./sigilum openclaw install --mode oss-local --namespace "<namespace>" --api-url http://127.0.0.1:8787
```

If using a globally installed `sigilum` binary, pass source explicitly:

```bash
sigilum openclaw install --mode oss-local --source-home "$SIGILUM_SOURCE_HOME" --namespace "<namespace>" --api-url http://127.0.0.1:8787
```

### 3.5 Local owner token refresh

```bash
sigilum auth refresh --mode oss-local --namespace "<namespace>"
```

## 4) Verification

Run in order:

```bash
sigilum doctor
sigilum openclaw status
sigilum service list --namespace "<namespace>"
```

For full local validation (source mode):

```bash
./sigilum e2e-tests
```

## 5) Failure Recovery

Reset OpenClaw integration:

```bash
sigilum openclaw uninstall
sigilum openclaw install --namespace "<namespace>"
```

Stop local listeners:

```bash
sigilum down
```

If local auth issuance fails in `oss-local`, ensure JWT secret exists:

```bash
grep '^JWT_SECRET=' "$SIGILUM_SOURCE_HOME/apps/api/.dev.vars"
```

## 6) Key References

- [CLI Reference](./docs/cli/README.md) - all commands and options
- [Gateway Reference](./apps/gateway/README.md) - gateway configuration
- [API Reference](./apps/api/README.md) - API endpoints
- [Gateway Error Codes](./docs/product/GATEWAY_ERROR_CODES.md) - troubleshooting
- [Validation Runbook](./docs/cli/GATEWAY_OPENCLAW_VALIDATION.md) - step-by-step gateway + OpenClaw validation
