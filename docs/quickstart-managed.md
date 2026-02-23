# Sigilum Managed Mode - Quickstart

Get your Sigilum gateway running and paired in under 5 minutes. This guide is for **managed mode** - you run the gateway, Sigilum hosts the API and dashboard.

> **What stays where:** Your provider API keys and secrets never leave your gateway. The hosted control plane handles identity, approvals, and dashboards only.

---

## Prerequisites

- A Linux server (Ubuntu 20.04+, Debian 11+), macOS (Apple Silicon or Intel), or any machine with `curl` and a shell.
- A [sigilum.id](https://sigilum.id) account with a reserved namespace.

---

## 1. Install the CLI

One command. Downloads the latest release binary for your platform:

```bash
curl -fsSL https://github.com/PaymanAI/sigilum/releases/latest/download/install-curl.sh | bash
```

This installs to `~/.sigilum` and adds it to your `PATH`. Restart your shell or run:

```bash
export PATH="$HOME/.sigilum:$PATH"
```

Verify the install:

```bash
sigilum versions
```

<details>
<summary>Manual install (if you prefer)</summary>

Download the tarball for your platform from [GitHub Releases](https://github.com/PaymanAI/sigilum/releases/latest):

| Platform | Asset |
|----------|-------|
| macOS (Apple Silicon) | `sigilum-<version>-macos-apple-silicon.tar.gz` |
| Linux (x86_64) | `sigilum-<version>-linux-amd64.tar.gz` |
| Linux (ARM64) | `sigilum-<version>-linux-arm64.tar.gz` |

Extract and make scripts executable:

```bash
tar xzf sigilum-*.tar.gz
chmod +x sigilum sigilum-gateway sigilum-gateway-cli
```

Move the binaries somewhere on your `PATH`:

```bash
sudo mv sigilum sigilum-gateway sigilum-gateway-cli /usr/local/bin/
```

</details>

---

## 2. Initialize your namespace

Create a local identity for your namespace. You only need to do this once per machine:

```bash
sigilum auth login --mode managed --namespace <your-namespace> --owner-token-stdin
```

You'll be prompted to paste your owner token from the [sigilum.id](https://sigilum.id) dashboard.

> **Note:** If you see `Sigilum identity not found for namespace "<name>"`, this means the local identity hasn't been bootstrapped yet. The `auth login` command handles this for managed mode. If it doesn't, see [Troubleshooting](#troubleshooting) below.

---

## 3. Start the gateway

```bash
sigilum gateway start
```

The gateway starts on port `38100` by default. It connects to the hosted API at `https://api.sigilum.id` automatically in managed mode.

Verify it's running:

```bash
curl -s http://localhost:38100/health
```

You should see a healthy response.

> **Important:** Do NOT use `./sigilum up` for managed mode. That command starts both a local API server and a gateway, which will conflict with the hosted API at `api.sigilum.id`. For managed mode, you only need the gateway.

---

## 4. Pair with the dashboard

1. Go to [sigilum.id](https://sigilum.id) and sign in.
2. Navigate to your namespace settings.
3. Click **Start Pairing**.
4. Copy the pairing command shown on screen.
5. Run it in your terminal (the gateway must be running first - see step 3).

The command looks something like:

```bash
sigilum gateway pair --code <pairing-code>
```

Once paired, your gateway appears as connected in the dashboard.

---

## 5. Connect providers

From the [sigilum.id](https://sigilum.id) dashboard:

1. Go to **Providers** and click **Add Connection**.
2. Select a provider (e.g., OpenAI, Linear, Slack).
3. Enter your API credentials when prompted.

Your credentials are encrypted and stored **only in your gateway**. The dashboard never sees or stores the raw secret.

You can also add providers via CLI:

```bash
sigilum service add \
  --service-slug openai \
  --service-name "OpenAI" \
  --mode gateway \
  --upstream-base-url https://api.openai.com \
  --auth-mode bearer \
  --upstream-secret-env OPENAI_API_KEY
```

---

## 6. Approve agent access

When an AI agent requests access to a provider through your gateway:

1. You'll receive a notification (dashboard, email, or webhook - depending on your config).
2. Review the request: which agent, which provider, what scope.
3. Approve or deny with your passkey.

Approved agents get time-limited, scoped access. You can revoke at any time from the dashboard.

---

## Running in production

For production deployments, run the gateway as a system service. See **[Running as a Service](./running-as-service.md)** for systemd, launchd, and Docker instructions.

---

## Troubleshooting

### `Sigilum identity not found for namespace "..."`

The local identity hasn't been created yet. Run:

```bash
sigilum auth login --mode managed --namespace <your-namespace> --owner-token-stdin
```

If this still fails, the identity bootstrap may need to be done manually. Check the [gateway README](../apps/gateway/README.md) or open an issue.

> **Known issue:** Identity bootstrap currently requires a manual step that should be handled by a `sigilum init <namespace>` command. See [GitHub issue](https://github.com/PaymanAI/sigilum/issues) for status.

### Pairing command fails with preflight error

The gateway must be running **before** you run the pairing command. Start it first:

```bash
sigilum gateway start
# wait a few seconds, then run the pair command
sigilum gateway pair --code <pairing-code>
```

### `./sigilum up` started a local API on :8787

You used the local/dev stack command instead of managed mode. Stop it:

```bash
./sigilum down
```

Then start only the gateway (step 3 above).

### Scripts from tarball aren't executable

Known issue with some release tarballs. Fix with:

```bash
chmod +x ~/.sigilum/sigilum*
```

---

## What's next

- **[Running as a Service](./running-as-service.md)** - systemd, launchd, Docker setup.
- **[CLI Reference](./cli/README.md)** - Full CLI command reference.
- **[Gateway Guide](../apps/gateway/README.md)** - Deep dive into gateway behavior, routing, and MCP support.
- **[Protocol Docs](./protocol/)** - How Sigilum identity and delegation works under the hood.
