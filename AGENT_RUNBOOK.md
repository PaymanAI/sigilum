# Sigilum Agent Runbook

Use this runbook for end-to-end Sigilum setup without manual interpretation.

## 1) Mode Selection

| Mode | Use when | Requirement |
|---|---|---|
| Managed (release install) | You only need gateway + hosted Sigilum API/dashboard (`sigilum.id` / `api.sigilum.id`) | Release tarball install (gateway binary included). |
| OSS Local (source install) | You need local API + local gateway for development/testing | Full source checkout and `SIGILUM_SOURCE_HOME` set. |

Critical rule:
- Managed install needs only gateway runtime/binaries.
- Local API workflows require source code (`apps/api`) and `SIGILUM_SOURCE_HOME`.

## 2) Quick Start (Managed, Release Tarball)

### 2.1 Install from GitHub Releases

```bash
curl -fsSL https://raw.githubusercontent.com/PaymanAI/sigilum/main/scripts/install-curl.sh | bash
source ~/.zshrc
sigilum --help
```

Optional pinned version:

```bash
curl -fsSL https://raw.githubusercontent.com/PaymanAI/sigilum/main/scripts/install-curl.sh | bash -s -- --version <tag>
```

### 2.2 Start gateway runtime from release bundle

Assumption: release tarball contains gateway binaries under `$SIGILUM_HOME/bin`.

```bash
export SIGILUM_NAMESPACE="<namespace>"
export GATEWAY_SIGILUM_NAMESPACE="$SIGILUM_NAMESPACE"
export GATEWAY_SIGILUM_HOME="$HOME/.sigilum-workspace"
export GATEWAY_MASTER_KEY="<strong-random-master-key>"
export SIGILUM_API_URL="https://api.sigilum.id"
export SIGILUM_REGISTRY_URL="$SIGILUM_API_URL"
export GATEWAY_ADDR=":38100"

"$SIGILUM_HOME/bin/sigilum-gateway"
```

### 2.3 Install OpenClaw integration in managed mode

```bash
sigilum openclaw install --mode managed --namespace "$SIGILUM_NAMESPACE"
```

### 2.4 Login owner token + pair gateway

```bash
sigilum auth login --mode managed --namespace "$SIGILUM_NAMESPACE" --owner-token-stdin
sigilum gateway pair --session-id <session-id> --pair-code <pair-code> --namespace "$SIGILUM_NAMESPACE" --api-url https://api.sigilum.id
```

## 3) Install and Run from Source (OSS Local)

### 3.1 Clone and bootstrap source

```bash
git clone https://github.com/PaymanAI/sigilum.git
cd sigilum

corepack enable
corepack prepare pnpm@10.29.3 --activate
pnpm install
pnpm --dir sdks/sdk-ts build
```

### 3.2 Set source home (required for local API flows)

```bash
export SIGILUM_SOURCE_HOME="$(pwd)"
```

### 3.3 Start local API + gateway stack

```bash
./sigilum up
```

### 3.4 Install OpenClaw for local mode

```bash
./sigilum openclaw install --mode oss-local --namespace "<namespace>" --api-url http://127.0.0.1:8787
```

If using a globally installed `sigilum` binary (not running from repo root), pass source explicitly:

```bash
sigilum openclaw install --mode oss-local --source-home "$SIGILUM_SOURCE_HOME" --namespace "<namespace>" --api-url http://127.0.0.1:8787
```

### 3.5 Local owner token refresh

```bash
sigilum auth refresh --mode oss-local --namespace "<namespace>"
```

## 4) Verification Checklist

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
sigilum openclaw install --mode managed --namespace "<namespace>"
```

Stop local listeners:

```bash
sigilum down
```

If local auth issuance fails in `oss-local`, ensure JWT secret exists:

```bash
grep '^JWT_SECRET=' "$SIGILUM_SOURCE_HOME/apps/api/.dev.vars"
```
