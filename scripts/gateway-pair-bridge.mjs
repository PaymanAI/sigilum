#!/usr/bin/env node

import process from "node:process";

function usage() {
  console.error(`Usage:
  node scripts/gateway-pair-bridge.mjs \\
    --session-id <id> \\
    --pair-code <code> \\
    --namespace <namespace> \\
    [--api-url <url>] \\
    [--gateway-admin-url <url>] \\
    [--reconnect-ms <ms>] \\
    [--heartbeat-ms <ms>]

Defaults:
  --api-url           $SIGILUM_API_URL or $SIGILUM_REGISTRY_URL or http://127.0.0.1:8787
  --gateway-admin-url $GATEWAY_ADMIN_URL or http://127.0.0.1:38100
  --reconnect-ms      2000
  --heartbeat-ms      25000
`);
}

function parseArgs(argv) {
  const out = {
    sessionId: "",
    pairCode: "",
    namespace: "",
    apiUrl: process.env.SIGILUM_API_URL || process.env.SIGILUM_REGISTRY_URL || "http://127.0.0.1:8787",
    gatewayAdminUrl: process.env.GATEWAY_ADMIN_URL || "http://127.0.0.1:38100",
    reconnectMs: 2000,
    heartbeatMs: 25000,
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = argv[i + 1];
    switch (arg) {
      case "--session-id":
        out.sessionId = next || "";
        i += 1;
        break;
      case "--pair-code":
        out.pairCode = next || "";
        i += 1;
        break;
      case "--namespace":
        out.namespace = next || "";
        i += 1;
        break;
      case "--api-url":
        out.apiUrl = next || out.apiUrl;
        i += 1;
        break;
      case "--gateway-admin-url":
        out.gatewayAdminUrl = next || out.gatewayAdminUrl;
        i += 1;
        break;
      case "--reconnect-ms":
        out.reconnectMs = Number.parseInt(next || "", 10);
        i += 1;
        break;
      case "--heartbeat-ms":
        out.heartbeatMs = Number.parseInt(next || "", 10);
        i += 1;
        break;
      case "-h":
      case "--help":
        usage();
        process.exit(0);
      default:
        console.error(`Unknown option: ${arg}`);
        usage();
        process.exit(1);
    }
  }

  if (!out.sessionId || !out.pairCode || !out.namespace) {
    usage();
    process.exit(1);
  }
  if (!Number.isFinite(out.reconnectMs) || out.reconnectMs < 100) {
    out.reconnectMs = 2000;
  }
  if (!Number.isFinite(out.heartbeatMs) || out.heartbeatMs < 1000) {
    out.heartbeatMs = 25000;
  }
  return out;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildPairConnectUrl(apiUrl, sessionId, namespace, pairCode) {
  const parsed = new URL(apiUrl);
  parsed.protocol = parsed.protocol === "https:" ? "wss:" : "ws:";
  parsed.pathname = "/v1/gateway/pairing/connect";
  parsed.searchParams.set("session_id", sessionId);
  parsed.searchParams.set("namespace", namespace);
  parsed.searchParams.set("code", pairCode);
  return parsed.toString();
}

function sanitizePath(pathname) {
  const trimmed = String(pathname || "").trim();
  if (!trimmed.startsWith("/")) return "";
  if (trimmed === "/health") return trimmed;
  if (trimmed.startsWith("/api/admin/") || trimmed === "/api/admin/connections" || trimmed === "/api/admin/service-catalog") {
    return trimmed;
  }
  return "";
}

async function relayToGateway(gatewayAdminUrl, command) {
  const method = String(command.method || "GET").toUpperCase();
  const path = sanitizePath(command.path);
  if (!path) {
    return {
      status: 400,
      headers: {},
      body: null,
      error: "Unsupported relay path",
    };
  }

  if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) {
    return {
      status: 400,
      headers: {},
      body: null,
      error: "Unsupported HTTP method",
    };
  }

  const target = new URL(path, gatewayAdminUrl).toString();
  const headers = { ...(command.headers || {}) };
  let body = command.body ?? null;
  if (body == null) {
    delete headers["Content-Type"];
    delete headers["content-type"];
  }

  try {
    const response = await fetch(target, {
      method,
      headers,
      body,
    });

    const responseHeaders = {};
    for (const [key, value] of response.headers.entries()) {
      responseHeaders[key] = value;
    }

    const text = await response.text();
    return {
      status: response.status,
      headers: responseHeaders,
      body: text || null,
      error: null,
    };
  } catch (error) {
    return {
      status: 502,
      headers: {},
      body: null,
      error: `Gateway relay fetch failed: ${String(error)}`,
    };
  }
}

async function run() {
  const cfg = parseArgs(process.argv.slice(2));

  if (typeof WebSocket === "undefined") {
    throw new Error("Global WebSocket is not available in this Node runtime");
  }

  const wsUrl = buildPairConnectUrl(cfg.apiUrl, cfg.sessionId, cfg.namespace, cfg.pairCode);
  let shuttingDown = false;

  process.on("SIGINT", () => {
    shuttingDown = true;
  });
  process.on("SIGTERM", () => {
    shuttingDown = true;
  });

  console.log(`[sigilum] gateway pairing bridge starting`);
  console.log(`[sigilum] api=${cfg.apiUrl}`);
  console.log(`[sigilum] gateway_admin=${cfg.gatewayAdminUrl}`);
  console.log(`[sigilum] session=${cfg.sessionId} namespace=${cfg.namespace}`);

  while (!shuttingDown) {
    try {
      await new Promise((resolve, reject) => {
        const ws = new WebSocket(wsUrl);
        let heartbeatTimer = null;

        ws.onopen = () => {
          console.log("[sigilum] gateway pairing websocket connected");
          heartbeatTimer = setInterval(() => {
            if (ws.readyState !== 1) return;
            try {
              ws.send(JSON.stringify({ type: "ping", ts: Date.now() }));
            } catch {
              // close handler will reconnect
            }
          }, cfg.heartbeatMs);
        };

        ws.onmessage = async (event) => {
          let payload;
          try {
            payload = JSON.parse(String(event.data));
          } catch {
            return;
          }
          if (!payload || typeof payload !== "object") {
            return;
          }
          if (payload.type === "pong") {
            return;
          }
          if (payload.type === "ping") {
            try {
              ws.send(JSON.stringify({ type: "pong", ts: Date.now() }));
            } catch {
              // ignore, close handler will reconnect
            }
            return;
          }
          if (!payload || payload.type !== "command" || !payload.request_id) {
            return;
          }

          const relay = await relayToGateway(cfg.gatewayAdminUrl, payload);
          ws.send(JSON.stringify({
            type: "response",
            request_id: payload.request_id,
            ...relay,
          }));
        };

        ws.onerror = () => {
          // Close event handler will handle reconnect.
        };

        ws.onclose = (event) => {
          if (heartbeatTimer) {
            clearInterval(heartbeatTimer);
            heartbeatTimer = null;
          }
          console.log(`[sigilum] websocket closed (${event.code}) ${event.reason || ""}`);
          resolve();
        };

        if (shuttingDown) {
          try {
            ws.close(1000, "shutdown");
          } catch {
            // ignore
          }
          resolve();
        }
      });
    } catch (error) {
      console.error(`[sigilum] websocket loop error: ${String(error)}`);
    }

    if (!shuttingDown) {
      await sleep(cfg.reconnectMs);
    }
  }

  console.log("[sigilum] gateway pairing bridge stopped");
}

run().catch((error) => {
  console.error(`[sigilum] ${String(error)}`);
  process.exit(1);
});
