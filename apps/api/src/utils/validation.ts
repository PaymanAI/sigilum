/**
 * SSRF protection: validate that a URL doesn't point to internal/private IP ranges.
 * This resolves DNS so hostnames that map to private IPs are rejected.
 */
const DNS_RESOLVER_URL = "https://cloudflare-dns.com/dns-query";
const DNS_RECORD_TYPES = ["A", "AAAA"] as const;

interface DnsJsonAnswer {
  type?: number;
  data?: string;
}

interface DnsJsonResponse {
  Status?: number;
  Answer?: DnsJsonAnswer[];
}

function stripIpv6Brackets(hostname: string): string {
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return hostname.slice(1, -1);
  }
  return hostname;
}

function normalizeHostname(hostname: string): string {
  const stripped = stripIpv6Brackets(hostname.trim().toLowerCase());
  if (stripped.endsWith(".")) {
    return stripped.slice(0, -1);
  }
  return stripped;
}

function parseIPv4(hostname: string): number[] | null {
  const ipv4Pattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = hostname.match(ipv4Pattern);
  if (!match) return null;

  const parts = match.slice(1).map(Number);
  if (parts.some((part) => part < 0 || part > 255)) {
    return null;
  }
  return parts;
}

function isBlockedIPv4(parts: number[]): boolean {
  const [a = 0, b = 0, c = 0] = parts;

  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  if (a === 127) return true; // 127.0.0.0/8
  if (a === 169 && b === 254) return true; // 169.254.0.0/16
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 0) return true; // 192.0.0.0/24 (includes TEST-NET-1)
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24
  if (a >= 224) return true; // multicast/reserved

  return false;
}

function isBlockedIPv6(hostname: string): boolean {
  const lower = normalizeHostname(hostname);

  if (lower === "::" || lower === "0:0:0:0:0:0:0:0") return true;
  if (lower === "::1" || lower === "0:0:0:0:0:0:0:1") return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // fc00::/7
  if (/^fe[89ab]/.test(lower)) return true; // fe80::/10
  if (lower.startsWith("ff")) return true; // ff00::/8
  if (lower.startsWith("2001:db8")) return true; // documentation range

  if (lower.startsWith("::ffff:")) {
    const mappedV4 = lower.slice("::ffff:".length);
    const v4 = parseIPv4(mappedV4);
    if (v4 && isBlockedIPv4(v4)) {
      return true;
    }
  }

  return false;
}

function toErrorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

async function resolveHostnameToIPs(hostname: string): Promise<string[]> {
  const resolved = new Set<string>();

  for (const recordType of DNS_RECORD_TYPES) {
    const url = `${DNS_RESOLVER_URL}?name=${encodeURIComponent(hostname)}&type=${recordType}`;
    let response: Response;
    try {
      response = await fetch(url, {
        headers: {
          Accept: "application/dns-json",
        },
      });
    } catch (err) {
      throw new Error(`DNS resolution failed: ${toErrorMessage(err)}`);
    }

    if (!response.ok) {
      throw new Error(`DNS resolver returned HTTP ${response.status}`);
    }

    let payload: DnsJsonResponse;
    try {
      payload = await response.json() as DnsJsonResponse;
    } catch {
      throw new Error("DNS resolver returned invalid JSON");
    }

    if (typeof payload.Status === "number" && payload.Status !== 0 && payload.Status !== 3) {
      throw new Error(`DNS resolver returned status ${payload.Status}`);
    }

    const answers = Array.isArray(payload.Answer) ? payload.Answer : [];
    for (const answer of answers) {
      const data = typeof answer.data === "string" ? normalizeHostname(answer.data) : "";
      if (!data) continue;
      if (parseIPv4(data) || data.includes(":")) {
        resolved.add(data);
      }
    }
  }

  return [...resolved];
}

export async function isValidWebhookUrl(urlString: string): Promise<{ valid: boolean; error?: string }> {
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }

  // Only allow http and https
  if (!["http:", "https:"].includes(url.protocol)) {
    return { valid: false, error: "Only HTTP and HTTPS protocols are allowed" };
  }

  const hostname = normalizeHostname(url.hostname);
  if (!hostname) {
    return { valid: false, error: "Invalid URL host" };
  }

  // Block localhost variations
  if (hostname === "localhost") {
    return { valid: false, error: "Cannot use localhost URLs" };
  }

  const directIPv4 = parseIPv4(hostname);
  if (directIPv4) {
    if (isBlockedIPv4(directIPv4)) {
      return { valid: false, error: "Cannot use non-public IPv4 addresses" };
    }
    return { valid: true };
  }

  // Handle direct IPv6 literals.
  if (hostname.includes(":")) {
    if (isBlockedIPv6(hostname)) {
      return { valid: false, error: "Cannot use non-public IPv6 addresses" };
    }
    return { valid: true };
  }

  // Resolve hostnames and block if any result is private/internal.
  let resolvedIPs: string[];
  try {
    resolvedIPs = await resolveHostnameToIPs(hostname);
  } catch (err) {
    return { valid: false, error: `Unable to resolve hostname safely: ${toErrorMessage(err)}` };
  }

  if (resolvedIPs.length === 0) {
    return { valid: false, error: "Hostname did not resolve to an IP address" };
  }

  for (const resolvedIP of resolvedIPs) {
    const resolvedV4 = parseIPv4(resolvedIP);
    if (resolvedV4) {
      if (isBlockedIPv4(resolvedV4)) {
        return {
          valid: false,
          error: `Hostname resolves to non-public IP address (${resolvedIP})`,
        };
      }
      continue;
    }

    if (resolvedIP.includes(":") && isBlockedIPv6(resolvedIP)) {
      return {
        valid: false,
        error: `Hostname resolves to non-public IP address (${resolvedIP})`,
      };
    }
  }

  return { valid: true };
}

/**
 * Standardized error response format
 */
export interface ApiError {
  error: string;
  code?: string;
  details?: unknown;
}

export function createErrorResponse(message: string, code?: string, details?: unknown): ApiError {
  const response: ApiError = { error: message };
  if (code) response.code = code;
  if (details !== undefined) response.details = details;
  return response;
}
