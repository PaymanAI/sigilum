#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");

const apiUrl = process.env.SIM_API_URL ?? "http://127.0.0.1:8787";
const nativeUrl = process.env.SIM_NATIVE_URL ?? "http://127.0.0.1:11000";
const gatewayUrl = process.env.SIM_GATEWAY_URL ?? "http://127.0.0.1:38100";
const gatewayConnectionID = process.env.SIM_GATEWAY_CONNECTION_ID ?? "demo-service-gateway";
const gatewayUpstreamUrl = process.env.SIM_GATEWAY_UPSTREAM_URL ?? "http://127.0.0.1:11100";

const nativeServiceSlug = process.env.SIM_NATIVE_SERVICE_SLUG ?? "demo-service-native";
const gatewayServiceSlug = process.env.SIM_GATEWAY_SERVICE_SLUG ?? "demo-service-gateway";

const approvedNamespace = process.env.SIM_APPROVED_NAMESPACE ?? "agent-sim-approved";
const unapprovedNamespace = process.env.SIM_UNAPPROVED_NAMESPACE ?? "agent-sim-unapproved";
const identitiesHome = process.env.SIM_IDENTITIES_HOME ?? path.join(rootDir, ".sigilum-workspace", "agent-simulator");

const bodyPayload = JSON.stringify("ping");

function sqlEscape(value) {
  return String(value).replace(/'/g, "''");
}

function runLocalD1(sql) {
  const result = spawnSync(
    "pnpm",
    ["exec", "wrangler", "d1", "execute", "sigilum-api", "--local", "--command", sql],
    {
      cwd: path.join(rootDir, "apps", "api"),
      encoding: "utf8",
      env: process.env,
    },
  );
  if (result.status !== 0) {
    const stderr = result.stderr?.trim();
    const stdout = result.stdout?.trim();
    throw new Error(
      [
        "Failed to execute local D1 SQL.",
        stderr ? `stderr: ${stderr}` : "",
        stdout ? `stdout: ${stdout}` : "",
      ].filter(Boolean).join("\n"),
    );
  }
}

function upsertApprovedAuthorization(namespace, service, publicKey) {
  const claimID = `cl_sim_${crypto.randomBytes(10).toString("hex")}`;
  const nowExpr = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')";
  const query = [
    "INSERT INTO authorizations (namespace, service, public_key, claim_id, agent_ip, status, approved_at, revoked_at)",
    `VALUES ('${sqlEscape(namespace)}', '${sqlEscape(service)}', '${sqlEscape(publicKey)}', '${sqlEscape(claimID)}', '127.0.0.1', 'approved', ${nowExpr}, NULL)`,
    "ON CONFLICT(namespace, service, public_key) DO UPDATE SET",
    "  claim_id = excluded.claim_id,",
    "  agent_ip = excluded.agent_ip,",
    "  status = 'approved',",
    "  approved_at = excluded.approved_at,",
    "  revoked_at = NULL",
  ].join(" ");
  runLocalD1(query);
}

function clearAuthorization(namespace, service, publicKey) {
  const query = [
    "DELETE FROM authorizations",
    `WHERE namespace = '${sqlEscape(namespace)}'`,
    `AND service = '${sqlEscape(service)}'`,
    `AND public_key = '${sqlEscape(publicKey)}'`,
  ].join(" ");
  runLocalD1(query);
}

async function ensureReachable(name, url, expectedStatus = 200) {
  try {
    const response = await fetch(url, { method: "GET" });
    if (response.status !== expectedStatus) {
      throw new Error(`HTTP ${response.status}`);
    }
  } catch (error) {
    throw new Error(`${name} is not reachable at ${url} (${error instanceof Error ? error.message : String(error)})`);
  }
}

async function parseJsonSafe(response) {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function shortJson(value) {
  try {
    const raw = JSON.stringify(value);
    if (raw.length <= 220) return raw;
    return `${raw.slice(0, 220)}...`;
  } catch {
    return String(value);
  }
}

async function postSigned(agent, url) {
  const signed = agent.sigilum.sign({
    url,
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: bodyPayload,
  });
  return fetch(signed.url, {
    method: signed.method,
    headers: signed.headers,
    body: signed.body ?? undefined,
  });
}

async function postUnsigned(url) {
  return fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: bodyPayload,
  });
}

async function main() {
  const sdkModule = await import(pathToFileURL(path.join(rootDir, "sdks", "sdk-ts", "dist", "index.js")).href);
  const { init, certify } = sdkModule;

  console.log("Preflight checks...");
  await ensureReachable("Native demo service", `${nativeUrl}/`);
  await ensureReachable("Gateway service", `${gatewayUrl}/health`);
  await ensureReachable("Gateway demo upstream service", `${gatewayUpstreamUrl}/health`);

  console.log(`Initializing simulator identities in ${identitiesHome} ...`);
  init({ namespace: approvedNamespace, homeDir: identitiesHome });
  init({ namespace: unapprovedNamespace, homeDir: identitiesHome });

  const approvedAgent = certify({}, {
    namespace: approvedNamespace,
    homeDir: identitiesHome,
    apiBaseUrl: apiUrl,
  });
  const unapprovedAgent = certify({}, {
    namespace: unapprovedNamespace,
    homeDir: identitiesHome,
    apiBaseUrl: apiUrl,
  });

  console.log("Seeding authorization state for pass/fail scenarios...");
  upsertApprovedAuthorization(approvedNamespace, nativeServiceSlug, approvedAgent.sigilum.publicKey);
  upsertApprovedAuthorization(approvedNamespace, gatewayServiceSlug, approvedAgent.sigilum.publicKey);
  clearAuthorization(unapprovedNamespace, nativeServiceSlug, unapprovedAgent.sigilum.publicKey);
  clearAuthorization(unapprovedNamespace, gatewayServiceSlug, unapprovedAgent.sigilum.publicKey);

  const nativePingURL = `${nativeUrl.replace(/\/+$/, "")}/v1/ping`;
  const gatewayPingURL = `${gatewayUrl.replace(/\/+$/, "")}/proxy/${gatewayConnectionID}/v1/ping`;

  const testCases = [
    {
      name: "native: unsigned request should fail",
      expectedStatuses: [401],
      run: async () => postUnsigned(nativePingURL),
    },
    {
      name: "native: signed but unapproved key should fail",
      expectedStatuses: [401],
      run: async () => postSigned(unapprovedAgent, nativePingURL),
    },
    {
      name: "native: signed + approved key should pass",
      expectedStatuses: [200],
      expectedBody: "pong",
      run: async () => postSigned(approvedAgent, nativePingURL),
    },
    {
      name: "gateway: unsigned request should fail",
      expectedStatuses: [403],
      run: async () => postUnsigned(gatewayPingURL),
    },
    {
      name: "gateway: signed but unapproved key should fail",
      expectedStatuses: [403],
      run: async () => postSigned(unapprovedAgent, gatewayPingURL),
    },
    {
      name: "gateway: signed + approved key should pass",
      expectedStatuses: [200],
      expectedBody: "pong",
      run: async () => postSigned(approvedAgent, gatewayPingURL),
    },
  ];

  let passed = 0;
  let failed = 0;

  console.log("\nRunning simulator test cases...");
  for (const testCase of testCases) {
    try {
      const response = await testCase.run();
      const body = await parseJsonSafe(response);
      const statusOk = testCase.expectedStatuses.includes(response.status);
      const bodyOk = testCase.expectedBody === undefined || body === testCase.expectedBody;
      if (statusOk && bodyOk) {
        passed += 1;
        console.log(`PASS  ${testCase.name} (status=${response.status}, body=${shortJson(body)})`);
      } else {
        failed += 1;
        console.error(
          `FAIL  ${testCase.name} (status=${response.status}, body=${shortJson(body)}, expected_statuses=${testCase.expectedStatuses.join(",")}${testCase.expectedBody !== undefined ? `, expected_body=${JSON.stringify(testCase.expectedBody)}` : ""})`,
        );
      }
    } catch (error) {
      failed += 1;
      console.error(`FAIL  ${testCase.name} (${error instanceof Error ? error.message : String(error)})`);
    }
  }

  console.log(`\nSummary: ${passed} passed, ${failed} failed`);
  if (failed > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
