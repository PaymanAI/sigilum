# Quickstart: Managed Mode

This is the only setup path you need for hosted Sigilum (`sigilum.id` + `api.sigilum.id`).

## 1) Sign in and reserve namespace

1. Open [sigilum.id](https://sigilum.id)
2. Create account / sign in
3. Reserve namespace (example: `johndee`)

## 2) Install CLI

Run on the machine where your agent runs:

```bash
curl -fsSL https://github.com/PaymanAI/sigilum/releases/latest/download/install-curl.sh | bash
source ~/.zshrc
sigilum --help
```

## 3) Start local gateway

```bash
sigilum gateway start --namespace johndee
```

Notes:
- If identity is missing, `gateway start` bootstraps it automatically.
- No JWT is required for gateway start or gateway pairing.

## 4) Connect gateway to dashboard

In dashboard, click **Start Pairing** and run one command:

```bash
sigilum gateway connect \
  --session-id <session-id> \
  --pair-code <pair-code> \
  --namespace johndee \
  --api-url https://api.sigilum.id
```

`gateway connect` ensures gateway is running/healthy, then starts pairing bridge in daemon mode.

Daemon helpers:

```bash
sigilum gateway pair --status
sigilum gateway pair --stop
```

## 5) Connect providers

Use **Providers** in dashboard to add provider credentials. Secrets are stored locally in your gateway.

## Optional: OpenClaw one-command onboarding

```bash
sigilum openclaw connect \
  --session-id <session-id> \
  --pair-code <pair-code> \
  --namespace johndee \
  --api-url https://api.sigilum.id
```

This command performs:
- `sigilum gateway connect`
- `sigilum openclaw install --mode managed --non-interactive`
- immediate OpenClaw agent key bootstrap under `~/.openclaw/.sigilum/keys/...`

If gateway is already paired, use:

```bash
sigilum openclaw install --namespace johndee
```

## Basic health checks

```bash
sigilum doctor
curl -fsS http://127.0.0.1:38100/health
```
