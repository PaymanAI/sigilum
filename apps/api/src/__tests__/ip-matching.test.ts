import { describe, expect, it } from "vitest";
import { ipMatchesCIDR } from "../utils/ip-matching.js";

describe("ipMatchesCIDR", () => {
  it("matches IPv6 addresses inside CIDR ranges", () => {
    expect(ipMatchesCIDR("2001:db8::1234", "2001:db8::/64")).toBe(true);
    expect(ipMatchesCIDR("2001:db8:1::1", "2001:db8::/64")).toBe(false);
  });

  it("matches exact IPv6 addresses without CIDR notation", () => {
    expect(ipMatchesCIDR("2001:db8::1", "2001:db8::1")).toBe(true);
    expect(ipMatchesCIDR("2001:db8::2", "2001:db8::1")).toBe(false);
  });

  it("supports IPv4-mapped IPv6 addresses against IPv4 CIDRs", () => {
    expect(ipMatchesCIDR("::ffff:192.168.1.10", "192.168.1.0/24")).toBe(true);
    expect(ipMatchesCIDR("::ffff:10.0.0.10", "192.168.1.0/24")).toBe(false);
  });

  it("rejects invalid or incompatible inputs", () => {
    expect(ipMatchesCIDR("2001:db8::1", "10.0.0.0/8")).toBe(false);
    expect(ipMatchesCIDR("not-an-ip", "2001:db8::/64")).toBe(false);
    expect(ipMatchesCIDR("2001:db8::1", "2001:db8::/129")).toBe(false);
  });
});
