type ParsedIP = {
  version: 4 | 6;
  bits: 32 | 128;
  value: bigint;
};

function parseIPv4(ip: string): bigint | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let out = 0n;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0 || value > 255) return null;
    out = (out << 8n) | BigInt(value);
  }
  return out;
}

function parseIPv6(ip: string): bigint | null {
  // Drop zone index if present (for link-local addresses).
  const zoneIndex = ip.indexOf("%");
  const input = (zoneIndex === -1 ? ip : ip.slice(0, zoneIndex)).toLowerCase();
  if (!input || !input.includes(":")) return null;

  const doubleColonCount = input.split("::").length - 1;
  if (doubleColonCount > 1) return null;

  const [leftRaw, rightRaw] = input.split("::");
  const left = leftRaw ? leftRaw.split(":").filter(Boolean) : [];
  let right = rightRaw ? rightRaw.split(":").filter(Boolean) : [];

  // Handle IPv4 tail (for mapped/mixed notation).
  const convertIPv4Tail = (arr: string[]): string[] | null => {
    if (arr.length === 0) return arr;
    const last = arr[arr.length - 1];
    if (!last || !last.includes(".")) return arr;
    const ipv4 = parseIPv4(last);
    if (ipv4 === null) return null;
    const hi = Number((ipv4 >> 16n) & 0xffffn).toString(16);
    const lo = Number(ipv4 & 0xffffn).toString(16);
    return [...arr.slice(0, -1), hi, lo];
  };

  const convertedLeft = convertIPv4Tail(left);
  if (convertedLeft === null) return null;
  const convertedRight = convertIPv4Tail(right);
  if (convertedRight === null) return null;
  right = convertedRight;

  const totalGroups = convertedLeft.length + right.length;
  if (doubleColonCount === 0 && totalGroups !== 8) return null;
  if (doubleColonCount === 1 && totalGroups >= 8) return null;

  const middleZeros =
    doubleColonCount === 1 ? new Array(8 - totalGroups).fill("0") : [];
  const groups = [...convertedLeft, ...middleZeros, ...right];
  if (groups.length !== 8) return null;

  let out = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    const value = parseInt(group, 16);
    out = (out << 16n) | BigInt(value);
  }
  return out;
}

function parseIP(input: string): ParsedIP | null {
  const ipv4 = parseIPv4(input);
  if (ipv4 !== null) {
    return { version: 4, bits: 32, value: ipv4 };
  }
  const ipv6 = parseIPv6(input);
  if (ipv6 !== null) {
    return { version: 6, bits: 128, value: ipv6 };
  }
  return null;
}

function ipv6MappedToIPv4(value: bigint): bigint | null {
  // ::ffff:0:0/96 mapped prefix
  const high80 = value >> 48n;
  const mid16 = (value >> 32n) & 0xffffn;
  if (high80 === 0n && mid16 === 0xffffn) {
    return value & 0xffffffffn;
  }
  return null;
}

function normalizeForComparison(
  ip: ParsedIP,
  range: ParsedIP,
): [ParsedIP, ParsedIP] | null {
  if (ip.version === range.version) return [ip, range];

  // Support matching IPv4-mapped IPv6 agent addresses against IPv4 CIDRs.
  if (ip.version === 6 && range.version === 4) {
    const mapped = ipv6MappedToIPv4(ip.value);
    if (mapped === null) return null;
    return [{ version: 4, bits: 32, value: mapped }, range];
  }

  return null;
}

/**
 * Check if an IP address matches a CIDR range (IPv4 or IPv6), or exact IP.
 */
export function ipMatchesCIDR(ip: string, cidr: string): boolean {
  if (!cidr.includes("/")) {
    const ipParsed = parseIP(ip);
    const cidrParsed = parseIP(cidr);
    if (!ipParsed || !cidrParsed) return false;
    const normalized = normalizeForComparison(ipParsed, cidrParsed);
    if (!normalized) return false;
    return normalized[0].value === normalized[1].value;
  }

  const [rangeIpRaw, prefixLenRaw] = cidr.split("/");
  if (!rangeIpRaw || !prefixLenRaw) return false;
  if (!/^\d+$/.test(prefixLenRaw)) return false;

  const ipParsed = parseIP(ip);
  const rangeParsed = parseIP(rangeIpRaw);
  if (!ipParsed || !rangeParsed) return false;

  const normalized = normalizeForComparison(ipParsed, rangeParsed);
  if (!normalized) return false;
  const [normalizedIp, normalizedRange] = normalized;

  const bits = normalizedRange.bits;
  const prefixLen = Number(prefixLenRaw);
  if (prefixLen < 0 || prefixLen > bits) return false;

  const allOnes = (1n << BigInt(bits)) - 1n;
  const hostBits = bits - prefixLen;
  const hostMask = hostBits === 0 ? 0n : (1n << BigInt(hostBits)) - 1n;
  const networkMask = allOnes ^ hostMask;

  return (
    (normalizedIp.value & networkMask) ===
    (normalizedRange.value & networkMask)
  );
}
