# Product Message Style Guide

Canonical rules for user-facing errors and success messages across CLI, API, SDK, and gateway.

## Goals

- Deterministic: users can key off stable codes.
- Actionable: every failure states what to do next.
- Safe: never leak secrets, tokens, private keys, or full certificates.
- Consistent: same class of failure uses same code and phrasing.

## Message Contract

For machine-facing responses (API/gateway), prefer:

- `code`: stable identifier (`AUTH_NONCE_INVALID`, `MCP_TOOL_FORBIDDEN`)
- `error`: short human-readable sentence
- `request_id`: correlation id
- `docs_url`: link to remediation docs (when available)

For CLI/operator output:

- First line: concise status (`FAIL`, `WARN`, `OK`)
- Second line: concrete cause in plain language
- Third line: exact next command or action

## Error Message Rules

- Use imperative, direct language.
- Do not blame users.
- Avoid stack traces by default.
- Include one remediation step minimum.
- Keep line length readable in terminals.

Pattern:
- `"<code>: <what failed>. <next action>."`

Examples:
- `AUTH_CLAIM_REQUIRED: service access is not approved for this key. Open the dashboard and request approval.`
- `MCP_DISCOVERY_FAILED: tool discovery could not complete. Retry discover or verify upstream credentials.`
- `ROTATION_REQUIRED: connection secret rotation is overdue. Rotate the credential and retry.`

## Success Message Rules

- Confirm exactly what changed.
- Include scope (namespace/service/connection) and timestamp when useful.
- Include follow-up action only if needed.

Pattern:
- `"<operation> succeeded for <resource>. <optional next step>."`

Examples:
- `Connection test succeeded for linear-mcp (HTTP 200).`
- `Service key rotation succeeded for demo-service-gateway.`
- `Gateway pairing succeeded for namespace johndee.`

## Redaction Rules

- Always redact: `token`, `secret`, `authorization`, `signature`, `cert`, `api_key`, private key material.
- Hash or mask identity data where full values are unnecessary.
- Never emit raw upstream credentials in logs, errors, or success payloads.

## Localization and Tone

- Use neutral, professional tone.
- Avoid slang and jokes in errors.
- Keep wording stable; avoid frequent string churn that breaks runbooks.
