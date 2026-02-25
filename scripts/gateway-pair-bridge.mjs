#!/usr/bin/env node

import process from "node:process";

const TERMINAL_PAIR_SESSION_EXIT_CODE = 42;
const TERMINAL_PAIR_SESSION_MARKER = "PAIR_SESSION_TERMINAL";
const TERMINAL_CONNECT_FAILURE_THRESHOLD = 3;

class PairSessionTerminalError extends Error {
  constructor(message) {
    super(message);
    this.name = "PairSessionTerminalError";
  }
}

function usage() {
  console.error(`Usage:
  node scripts/gateway-pair-bridge.mjs \\
    --session-id <id> \\
    --pair-code <code> \\
    --namespace <namespace> \\
    [--api-url <url>] \\
    [--gateway-admin-url <url>] \\
    [--reconnect-ms <ms>] \\
    [--connect-timeout-ms <ms>] \\
    [--heartbeat-ms <ms>] \\
    [--relay-timeout-ms <ms>]

Defaults:
  --api-url           $SIGILUM_API_URL or $SIGILUM_REGISTRY_URL or http://127.0.0.1:8787
  --gateway-admin-url $GATEWAY_ADMIN_URL or http://127.0.0.1:38100
  --reconnect-ms      2000
  --connect-timeout-ms 5000
  --heartbeat-ms      30000
  --relay-timeout-ms  10000
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
    connectTimeoutMs: 5000,
    heartbeatMs: 30000,
    relayTimeoutMs: 10000,
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
      case "--connect-timeout-ms":
        out.connectTimeoutMs = Number.parseInt(next || "", 10);
        i += 1;
        break;
      case "--heartbeat-ms":
        out.heartbeatMs = Number.parseInt(next || "", 10);
        i += 1;
        break;
      case "--relay-timeout-ms":
        out.relayTimeoutMs = Number.parseInt(next || "", 10);
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
  if (!Number.isFinite(out.connectTimeoutMs) || out.connectTimeoutMs < 1000) {
    out.connectTimeoutMs = 5000;
  }
  if (!Number.isFinite(out.heartbeatMs) || out.heartbeatMs < 1000) {
    out.heartbeatMs = 25000;
  }
  if (!Number.isFinite(out.relayTimeoutMs) || out.relayTimeoutMs < 1000) {
    out.relayTimeoutMs = 10000;
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

async function fetchWithTimeout(url, init, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort(new Error(`timeout after ${timeoutMs}ms`));
  }, timeoutMs);
  try {
    return await fetch(url, { ...(init || {}), signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function truncateText(value, max = 180) {
  const text = String(value || "").replace(/\s+/g, " ").trim();
  if (text.length <= max) return text;
  return `${text.slice(0, max)}...`;
}

function isLikelyTerminalPairFailureReason(reasonInput) {
  const reason = String(reasonInput || "").toLowerCase();
  if (!reason) return false;
  if (reason.includes("connect-timeout")) return false;
  return [
    "pair session expired",
    "pair session not found",
    "invalid pair code",
    "namespace mismatch",
    "forbidden",
    "unauthorized",
    "http 403",
    "http 404",
    "http 410",
  ].some((token) => reason.includes(token));
}

function isLikelyHtml(contentType, body) {
  const ctype = String(contentType || "").toLowerCase();
  if (ctype.includes("text/html")) return true;
  return /<!doctype html|<html[\s>]/i.test(String(body || ""));
}

const RELAY_ALLOWLIST = [
  {
    pattern: /^\/health$/,
    methods: new Set(["GET"]),
  },
  {
    pattern: /^\/api\/admin\/connections$/,
    methods: new Set(["GET", "POST"]),
  },
  {
    pattern: /^\/api\/admin\/connections\/[A-Za-z0-9._-]+$/,
    methods: new Set(["GET", "PATCH", "DELETE"]),
  },
  {
    pattern: /^\/api\/admin\/connections\/[A-Za-z0-9._-]+\/(rotate|test|discover)$/,
    methods: new Set(["POST"]),
  },
  {
    pattern: /^\/api\/admin\/credential-variables$/,
    methods: new Set(["GET", "POST"]),
  },
  {
    pattern: /^\/api\/admin\/credential-variables\/[A-Za-z0-9._-]+$/,
    methods: new Set(["DELETE"]),
  },
  {
    pattern: /^\/api\/admin\/openclaw\/legacy-keys$/,
    methods: new Set(["GET"]),
  },
  {
    pattern: /^\/api\/admin\/openclaw\/legacy-keys\/(import|purge)$/,
    methods: new Set(["POST"]),
  },
  {
    pattern: /^\/api\/admin\/service-catalog$/,
    methods: new Set(["GET", "PUT"]),
  },
  {
    pattern: /^\/api\/admin\/service-api-keys\/[a-z0-9-]+$/,
    methods: new Set(["GET", "PUT"]),
  },
];

const RELAY_ALLOWED_HEADERS = new Set([
  "accept",
  "authorization",
  "content-type",
  "x-request-id",
  "x-sigilum-admin-token",
]);

async function ensureHealthy(url, label, timeoutMs) {
  const healthUrl = new URL("/health", url).toString();
  let response;
  try {
    response = await fetchWithTimeout(healthUrl, { method: "GET" }, timeoutMs);
  } catch (error) {
    throw new Error(
      `${label} is unreachable at ${healthUrl} (${String(error)}).`,
    );
  }

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    const contentType = response.headers.get("content-type") || "";
    const htmlHint = isLikelyHtml(contentType, body)
      ? " This looks like an HTML dashboard app, not the Sigilum API."
      : "";
    throw new Error(
      `${label} health check failed at ${healthUrl} (HTTP ${response.status}).${htmlHint} Body: ${truncateText(body)}`,
    );
  }
}

async function ensurePairingRoute(apiUrl, timeoutMs) {
  const pairingUrl = new URL("/v1/gateway/pairing/connect", apiUrl).toString();
  let response;
  try {
    response = await fetchWithTimeout(pairingUrl, { method: "GET" }, timeoutMs);
  } catch (error) {
    throw new Error(`Pairing endpoint probe failed for ${pairingUrl} (${String(error)}).`);
  }

  const body = await response.text().catch(() => "");
  const contentType = response.headers.get("content-type") || "";
  if (response.status === 404) {
    throw new Error(
      `Pairing endpoint not found at ${pairingUrl} (HTTP 404). Verify --api-url points to Sigilum API.`,
    );
  }
  if (isLikelyHtml(contentType, body)) {
    throw new Error(
      `Pairing endpoint at ${pairingUrl} returned HTML, which usually means --api-url is a dashboard host, not Sigilum API.`,
    );
  }
}

async function preflight(cfg) {
  await ensureHealthy(cfg.apiUrl, "Sigilum API", cfg.connectTimeoutMs);
  await ensurePairingRoute(cfg.apiUrl, cfg.connectTimeoutMs);
  await ensureHealthy(cfg.gatewayAdminUrl, "Local Sigilum gateway admin", cfg.connectTimeoutMs);
}

async function controlPlaneHealthy(cfg, timeoutMs) {
  try {
    await ensureHealthy(cfg.apiUrl, "Sigilum API", timeoutMs);
    await ensurePairingRoute(cfg.apiUrl, timeoutMs);
    await ensureHealthy(cfg.gatewayAdminUrl, "Local Sigilum gateway admin", timeoutMs);
    return true;
  } catch {
    return false;
  }
}

function sanitizePath(pathInput) {
  const trimmed = String(pathInput || "").trim();
  if (!trimmed.startsWith("/")) return "";
  if (trimmed.includes("#")) return "";
  let parsed;
  try {
    parsed = new URL(trimmed, "http://sigilum.local");
  } catch {
    return "";
  }
  if (parsed.search) return "";
  return parsed.pathname;
}

function isAllowedRelayPath(pathname, method) {
  return RELAY_ALLOWLIST.some(
    (rule) => rule.pattern.test(pathname) && rule.methods.has(method),
  );
}

function sanitizeRelayHeaders(headersInput) {
  const sanitized = {};
  if (!headersInput || typeof headersInput !== "object") {
    return sanitized;
  }

  for (const [rawKey, rawValue] of Object.entries(headersInput)) {
    const key = String(rawKey || "").trim();
    const lower = key.toLowerCase();
    if (!key || !RELAY_ALLOWED_HEADERS.has(lower)) {
      continue;
    }
    if (typeof rawValue !== "string") {
      continue;
    }
    sanitized[key] = rawValue.trim();
  }
  return sanitized;
}

function normalizeRelayBody(body) {
  if (body == null) {
    return null;
  }
  if (typeof body === "string") {
    return body;
  }
  if (typeof body === "object") {
    return JSON.stringify(body);
  }
  return String(body);
}

async function relayToGateway(gatewayAdminUrl, command, relayTimeoutMs) {
  const method = String(command.method || "GET").toUpperCase();
  const path = sanitizePath(command.path);
  if (!path || !isAllowedRelayPath(path, method)) {
    return {
      status: 400,
      headers: {},
      body: null,
      error: "Unsupported relay path or method",
    };
  }

  const target = new URL(path, gatewayAdminUrl).toString();
  const headers = sanitizeRelayHeaders(command.headers);
  let body = normalizeRelayBody(command.body);
  if (body == null) {
    delete headers["Content-Type"];
    delete headers["content-type"];
  } else if (!headers["Content-Type"] && !headers["content-type"]) {
    headers["Content-Type"] = "application/json";
  }

  try {
    const response = await fetchWithTimeout(
      target,
      {
        method,
        headers,
        body,
      },
      relayTimeoutMs,
    );

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
  let activeSocket = null;

  const requestShutdown = () => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    if (activeSocket && (activeSocket.readyState === 0 || activeSocket.readyState === 1)) {
      try {
        activeSocket.close(1000, "shutdown");
      } catch {
        // ignore
      }
    }
  };

  process.on("SIGINT", requestShutdown);
  process.on("SIGTERM", requestShutdown);

  console.log(`[sigilum] gateway pairing bridge starting`);
  console.log(`[sigilum] api=${cfg.apiUrl}`);
  console.log(`[sigilum] gateway_admin=${cfg.gatewayAdminUrl}`);
  console.log(`[sigilum] session=${cfg.sessionId} namespace=${cfg.namespace}`);
  console.log("[sigilum] preflight: validating api and gateway admin endpoints");
  await preflight(cfg);
  console.log("[sigilum] preflight: ok");
  console.log(
    `[sigilum] success: pairing bridge ready (session=${cfg.sessionId}, namespace=${cfg.namespace}, gateway_admin=${cfg.gatewayAdminUrl})`,
  );
  console.log("[sigilum] next: keep this process running while dashboard setup is active");

  let consecutivePreOpenFailures = 0;
  while (!shuttingDown) {
    let lastCloseInfo = {
      opened: false,
      code: 0,
      reason: "",
      durationMs: 0,
    };
    try {
      lastCloseInfo = await new Promise((resolve) => {
        const ws = new WebSocket(wsUrl);
        activeSocket = ws;
        let heartbeatTimer = null;
        let opened = false;
        const attemptStartedAt = Date.now();
        let connectTimer = setTimeout(() => {
          console.error(
            `[sigilum] websocket connect timeout after ${cfg.connectTimeoutMs}ms (url=${wsUrl})`,
          );
          try {
            ws.close(1000, "connect-timeout");
          } catch {
            // ignore
          }
        }, cfg.connectTimeoutMs);

        ws.onopen = () => {
          opened = true;
          if (connectTimer) {
            clearTimeout(connectTimer);
            connectTimer = null;
          }
          console.log(
            `[sigilum] websocket connected (session=${cfg.sessionId}, namespace=${cfg.namespace})`,
          );
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

          const relay = await relayToGateway(cfg.gatewayAdminUrl, payload, cfg.relayTimeoutMs);
          if (shuttingDown) {
            return;
          }
          ws.send(JSON.stringify({
            type: "response",
            request_id: payload.request_id,
            ...relay,
          }));
        };

        ws.onerror = () => {
          // Close event handler will handle reconnect; keep this diagnostic visible.
          console.error("[sigilum] websocket error (will retry)");
        };

        ws.onclose = (event) => {
          if (activeSocket === ws) {
            activeSocket = null;
          }
          if (connectTimer) {
            clearTimeout(connectTimer);
            connectTimer = null;
          }
          if (heartbeatTimer) {
            clearInterval(heartbeatTimer);
            heartbeatTimer = null;
          }
          const closeCode = Number(event?.code ?? 0);
          const closeReason = String(event?.reason || "").trim();
          const durationMs = Math.max(0, Date.now() - attemptStartedAt);
          console.log(`[sigilum] websocket closed (${closeCode}) ${closeReason}`);
          resolve({
            opened,
            code: Number.isFinite(closeCode) ? closeCode : 0,
            reason: closeReason,
            durationMs,
          });
        };

        if (shuttingDown) {
          try {
            ws.close(1000, "shutdown");
          } catch {
            // ignore
          }
          resolve({
            opened,
            code: 1000,
            reason: "shutdown",
            durationMs: Math.max(0, Date.now() - attemptStartedAt),
          });
        }
      });
    } catch (error) {
      console.error(`[sigilum] websocket loop error: ${String(error)}`);
      lastCloseInfo = {
        opened: false,
        code: 0,
        reason: String(error),
        durationMs: 0,
      };
    }

    if (shuttingDown) {
      break;
    }

    if (lastCloseInfo.opened) {
      consecutivePreOpenFailures = 0;
    } else {
      consecutivePreOpenFailures += 1;
      const reasonHint = isLikelyTerminalPairFailureReason(lastCloseInfo.reason);
      const fastFailure = lastCloseInfo.durationMs > 0 && lastCloseInfo.durationMs <= 5000;
      if (reasonHint || (fastFailure && consecutivePreOpenFailures >= TERMINAL_CONNECT_FAILURE_THRESHOLD)) {
        const probeTimeoutMs = Math.min(Math.max(cfg.connectTimeoutMs, 1000), 3000);
        const healthy = await controlPlaneHealthy(cfg, probeTimeoutMs);
        if (healthy) {
          throw new PairSessionTerminalError(
            `Pair session appears expired or invalid after ${consecutivePreOpenFailures} failed connect attempts (close_code=${lastCloseInfo.code}, reason=${truncateText(lastCloseInfo.reason || "none", 120)}). Start a new dashboard pairing session and rerun with fresh --session-id/--pair-code.`,
          );
        }
      }
    }

    await sleep(cfg.reconnectMs);
  }

  console.log("[sigilum] gateway pairing bridge stopped");
}

run().catch((error) => {
  if (error instanceof PairSessionTerminalError) {
    console.error(`[sigilum] ${TERMINAL_PAIR_SESSION_MARKER}: ${error.message}`);
    process.exit(TERMINAL_PAIR_SESSION_EXIT_CODE);
  }
  console.error(`[sigilum] ${String(error)}`);
  process.exit(1);
});
