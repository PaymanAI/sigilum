# Running the Sigilum Gateway as a Service

For production use, you should run the Sigilum gateway as a persistent system service rather than a foreground process. This guide covers systemd (Linux), launchd (macOS), and Docker.

---

## systemd (Linux)

### 1. Create a dedicated user (recommended)

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sigilum
sudo mkdir -p /var/lib/sigilum-gateway
sudo chown sigilum:sigilum /var/lib/sigilum-gateway
```

### 2. Install the binary

If you used the curl installer, the binary is at `~/.sigilum/sigilum-gateway`. Copy it to a system-wide location:

```bash
sudo cp ~/.sigilum/sigilum-gateway /usr/local/bin/sigilum-gateway
sudo chmod +x /usr/local/bin/sigilum-gateway
```

### 3. Create the environment file

```bash
sudo tee /etc/sigilum-gateway.env > /dev/null <<'EOF'
# Required: your Sigilum namespace
SIGILUM_NAMESPACE=your-namespace

# Required: path to gateway data (identity, connections, secrets)
GATEWAY_DATA_DIR=/var/lib/sigilum-gateway

# Required: Sigilum API URL (managed mode)
SIGILUM_API_URL=https://api.sigilum.id

# Optional: listen address (default :38100)
# GATEWAY_ADDR=:38100

# Optional: admin access mode (loopback|token|hybrid)
# GATEWAY_ADMIN_ACCESS_MODE=loopback
EOF
```

Set restrictive permissions:

```bash
sudo chmod 600 /etc/sigilum-gateway.env
sudo chown sigilum:sigilum /etc/sigilum-gateway.env
```

### 4. Create the systemd unit

```bash
sudo tee /etc/systemd/system/sigilum-gateway.service > /dev/null <<'EOF'
[Unit]
Description=Sigilum Gateway
Documentation=https://github.com/PaymanAI/sigilum
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sigilum
Group=sigilum
EnvironmentFile=/etc/sigilum-gateway.env
ExecStart=/usr/local/bin/sigilum-gateway
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sigilum-gateway
PrivateTmp=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sigilum-gateway

[Install]
WantedBy=multi-user.target
EOF
```

### 5. Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable sigilum-gateway
sudo systemctl start sigilum-gateway
```

### 6. Check status and logs

```bash
sudo systemctl status sigilum-gateway
sudo journalctl -u sigilum-gateway -f
```

---

## launchd (macOS)

### 1. Create the plist

```bash
cat > ~/Library/LaunchAgents/id.sigilum.gateway.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>id.sigilum.gateway</string>

    <key>ProgramArguments</key>
    <array>
        <string>/Users/YOU/.sigilum/sigilum-gateway</string>
    </array>

    <key>EnvironmentVariables</key>
    <dict>
        <key>SIGILUM_NAMESPACE</key>
        <string>your-namespace</string>
        <key>GATEWAY_DATA_DIR</key>
        <string>/Users/YOU/.sigilum/gateway-data</string>
        <key>SIGILUM_API_URL</key>
        <string>https://api.sigilum.id</string>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>/Users/YOU/.sigilum/gateway.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/YOU/.sigilum/gateway.err.log</string>
</dict>
</plist>
EOF
```

Replace `YOU` with your macOS username and `your-namespace` with your Sigilum namespace.

### 2. Load and start

```bash
launchctl load ~/Library/LaunchAgents/id.sigilum.gateway.plist
```

### 3. Check status

```bash
launchctl list | grep sigilum
tail -f ~/.sigilum/gateway.log
```

### 4. Stop or unload

```bash
launchctl unload ~/Library/LaunchAgents/id.sigilum.gateway.plist
```

---

## Docker

### Quick start

```bash
docker run -d \
  --name sigilum-gateway \
  --restart unless-stopped \
  -p 38100:38100 \
  -v sigilum-gateway-data:/var/lib/sigilum-gateway \
  -e SIGILUM_NAMESPACE=your-namespace \
  -e SIGILUM_API_URL=https://api.sigilum.id \
  ghcr.io/paymanai/sigilum-gateway:latest
```

> **Note:** If the container image is not yet published to GHCR, build it locally from the repo:
>
> ```bash
> cd /path/to/sigilum
> docker build -t sigilum-gateway:local -f apps/gateway/service/Dockerfile .
> ```
>
> Then use `sigilum-gateway:local` instead of `ghcr.io/paymanai/sigilum-gateway:latest`.

### Docker Compose

Use the provided compose file at `apps/gateway/docker-compose.yml` for a setup with the optional Envoy sidecar:

```bash
cd apps/gateway
cp .env.example .env  # edit with your values
docker compose up -d
```

### Check logs

```bash
docker logs -f sigilum-gateway
```

---

## Verifying the gateway

After starting via any method:

```bash
curl -s http://localhost:38100/health
```

If you haven't paired yet, continue with the [pairing step in the quickstart](./quickstart-managed.md#4-pair-with-the-dashboard).

---

## Upgrading

1. Download the new binary (re-run the install script or download from [Releases](https://github.com/PaymanAI/sigilum/releases/latest)).
2. Replace the binary in place.
3. Restart the service:

```bash
# systemd
sudo systemctl restart sigilum-gateway

# launchd
launchctl unload ~/Library/LaunchAgents/id.sigilum.gateway.plist
launchctl load ~/Library/LaunchAgents/id.sigilum.gateway.plist

# Docker
docker pull ghcr.io/paymanai/sigilum-gateway:latest
docker restart sigilum-gateway
```

Gateway data is preserved across restarts. No migration needed for patch/minor releases.
