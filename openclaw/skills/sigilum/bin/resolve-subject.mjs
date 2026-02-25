#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SUBJECT_HINTS_FILENAME = "subject-hints.json";
const SLACK_EMAIL_CACHE_FILENAME = "slack-user-email-cache.json";
const SLACK_EMAIL_CACHE_TTL_MS = 10 * 60 * 1000;

const SESSION_KEY_ENV_KEYS = [
  "SIGILUM_SESSION_KEY",
  "OPENCLAW_SESSION_KEY",
  "SESSION_KEY",
];

const SLACK_TOKEN_ENV_KEYS = [
  "SLACK_USER_TOKEN",
  "OPENCLAW_SLACK_USER_TOKEN",
  "SLACK_BOT_TOKEN",
  "OPENCLAW_SLACK_BOT_TOKEN",
  "SLACK_TOKEN",
];

function asString(value) {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim();
}

function asObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return {};
  }
  return value;
}

function sanitizeAgentID(value) {
  return asString(value).replace(/[^a-zA-Z0-9._-]/g, "_");
}

function parseAgentIDFromSessionKey(sessionKey) {
  const normalized = asString(sessionKey);
  if (!normalized) {
    return "";
  }
  const parts = normalized.split(":");
  if (parts.length >= 2 && parts[0].toLowerCase() === "agent") {
    return sanitizeAgentID(parts[1]);
  }
  return sanitizeAgentID(parts[0]);
}

function resolveSessionKey() {
  for (const key of SESSION_KEY_ENV_KEYS) {
    const value = asString(process.env[key]);
    if (value) {
      return value;
    }
  }
  return "";
}

function resolveAgentID(sessionKey) {
  const explicit = asString(process.env.SIGILUM_AGENT_ID);
  if (explicit) {
    return sanitizeAgentID(explicit);
  }
  const openClawAgentID = asString(process.env.OPENCLAW_AGENT_ID);
  if (openClawAgentID) {
    return sanitizeAgentID(openClawAgentID);
  }
  const openClawAgent = asString(process.env.OPENCLAW_AGENT);
  if (openClawAgent) {
    return sanitizeAgentID(openClawAgent);
  }
  return parseAgentIDFromSessionKey(sessionKey);
}

function resolveOpenClawHome() {
  const direct = asString(process.env.OPENCLAW_HOME);
  if (direct) {
    return direct;
  }
  const configPath = asString(process.env.OPENCLAW_CONFIG_PATH);
  if (configPath) {
    return path.dirname(configPath);
  }
  return path.join(os.homedir(), ".openclaw");
}

function resolveSubjectHintsPath() {
  const override = asString(process.env.SIGILUM_SUBJECT_HINTS_PATH);
  if (override) {
    return override;
  }
  return path.join(resolveOpenClawHome(), ".sigilum", SUBJECT_HINTS_FILENAME);
}

function resolveSlackEmailCachePath() {
  const override = asString(process.env.SIGILUM_SLACK_EMAIL_CACHE_PATH);
  if (override) {
    return override;
  }
  return path.join(resolveOpenClawHome(), ".sigilum", SLACK_EMAIL_CACHE_FILENAME);
}

function readJSONFile(filePath) {
  if (!filePath || !fs.existsSync(filePath)) {
    return {};
  }
  try {
    return asObject(JSON.parse(fs.readFileSync(filePath, "utf8")));
  } catch {
    return {};
  }
}

function writeJSONFile(filePath, payload) {
  if (!filePath) {
    return;
  }
  const directory = path.dirname(filePath);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, filePath);
}

function pickHintRecord(store, sessionKey, agentID) {
  const bySession = asObject(store.by_session);
  const byAgent = asObject(store.by_agent);

  if (sessionKey) {
    const match = asObject(bySession[sessionKey]);
    if (Object.keys(match).length > 0) {
      return match;
    }
  }
  if (agentID) {
    const match = asObject(byAgent[agentID]);
    if (Object.keys(match).length > 0) {
      return match;
    }
  }

  const recent = Array.isArray(store.recent) ? store.recent : [];
  for (const entry of recent) {
    const hint = asObject(entry);
    if (sessionKey && asString(hint.session_key) === sessionKey) {
      return hint;
    }
    if (agentID && asString(hint.agent_id) === agentID) {
      return hint;
    }
  }
  return {};
}

function slackSenderFromFromField(rawFrom) {
  const from = asString(rawFrom);
  if (!from) {
    return "";
  }
  const lower = from.toLowerCase();
  if (!lower.startsWith("slack:")) {
    return "";
  }
  return from.slice("slack:".length).trim();
}

function extractSubjectFromHint(rawHint) {
  const hint = asObject(rawHint);
  let channel = asString(hint.channel).toLowerCase();
  const subject = asString(hint.subject);
  const slackFromSender = slackSenderFromFromField(hint.from);
  if (!channel && slackFromSender) {
    channel = "slack";
  }
  const senderID = asString(hint.sender_id) || slackFromSender;
  const senderE164 = asString(hint.sender_e164);
  const from = asString(hint.from);

  if (channel === "slack") {
    return {
      channel,
      subject: subject || senderID || slackFromSender,
      senderID: senderID || slackFromSender,
    };
  }
  return {
    channel,
    subject: subject || senderE164 || senderID || from,
    senderID,
  };
}

function isLikelyEmail(value) {
  const input = asString(value);
  if (!input) {
    return false;
  }
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(input);
}

function normalizeSlackUserID(value) {
  let input = asString(value);
  if (!input) {
    return "";
  }
  if (input.toLowerCase().startsWith("slack:")) {
    input = input.slice("slack:".length).trim();
  }
  if (!/^[UW][A-Z0-9]{8,}$/i.test(input)) {
    return "";
  }
  return input.toUpperCase();
}

function slackTokens() {
  const tokens = [];
  for (const key of SLACK_TOKEN_ENV_KEYS) {
    const token = asString(process.env[key]);
    if (!token || tokens.includes(token)) {
      continue;
    }
    tokens.push(token);
  }
  return tokens;
}

function readCachedSlackEmail(cache, userID) {
  const users = asObject(cache.users);
  const record = asObject(users[userID]);
  const updatedAt = Date.parse(asString(record.updated_at));
  if (!Number.isFinite(updatedAt)) {
    return { found: false, email: "" };
  }
  if (Date.now() - updatedAt > SLACK_EMAIL_CACHE_TTL_MS) {
    return { found: false, email: "" };
  }
  return {
    found: true,
    email: asString(record.email),
  };
}

function writeCachedSlackEmail(cachePath, cache, userID, email) {
  const users = asObject(cache.users);
  users[userID] = {
    email: asString(email),
    updated_at: new Date().toISOString(),
  };
  const next = {
    updated_at: new Date().toISOString(),
    users,
  };
  writeJSONFile(cachePath, next);
}

async function lookupSlackEmail(userID) {
  const normalizedUserID = normalizeSlackUserID(userID);
  if (!normalizedUserID) {
    return "";
  }

  const cachePath = resolveSlackEmailCachePath();
  const cache = readJSONFile(cachePath);
  const cached = readCachedSlackEmail(cache, normalizedUserID);
  if (cached.found) {
    return cached.email;
  }

  for (const token of slackTokens()) {
    try {
      const response = await fetch(
        `https://slack.com/api/users.info?user=${encodeURIComponent(normalizedUserID)}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/json",
          },
        },
      );
      if (!response.ok) {
        continue;
      }
      const payload = asObject(await response.json());
      const ok = payload.ok === true;
      if (!ok) {
        continue;
      }
      const user = asObject(payload.user);
      const profile = asObject(user.profile);
      const email = asString(profile.email);
      writeCachedSlackEmail(cachePath, cache, normalizedUserID, email);
      if (email) {
        return email;
      }
      return "";
    } catch {
      // Continue to next token.
    }
  }

  writeCachedSlackEmail(cachePath, cache, normalizedUserID, "");
  return "";
}

async function resolveSubject() {
  const explicit = asString(process.env.SIGILUM_SUBJECT);
  if (explicit) {
    return explicit;
  }

  const sessionKey = resolveSessionKey();
  const agentID = resolveAgentID(sessionKey);
  const subjectHints = readJSONFile(resolveSubjectHintsPath());
  const hint = pickHintRecord(subjectHints, sessionKey, agentID);
  const parsed = extractSubjectFromHint(hint);

  let resolved = asString(parsed.subject);
  if (parsed.channel === "slack") {
    const slackUserID = normalizeSlackUserID(parsed.senderID || resolved);
    if (slackUserID && !isLikelyEmail(resolved)) {
      const email = await lookupSlackEmail(slackUserID);
      if (email) {
        resolved = email;
      } else if (!resolved) {
        resolved = slackUserID;
      }
    }
  }
  return asString(resolved);
}

const resolved = await resolveSubject();
if (resolved) {
  process.stdout.write(`${resolved}\n`);
}
