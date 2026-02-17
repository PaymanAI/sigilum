import { describe, expect, it } from "vitest";
import { resolveWebAuthnConfig } from "../utils/webauthn-config.js";

describe("resolveWebAuthnConfig", () => {
  it("derives rpID from configured WebAuthn origins", () => {
    const config = resolveWebAuthnConfig({
      WEBAUTHN_ALLOWED_ORIGINS: "https://dashboard.example.com",
    });

    expect(config.rpID).toBe("dashboard.example.com");
    expect(config.expectedOrigin).toBe("https://dashboard.example.com");
  });

  it("supports multiple allowed origins with explicit rpID", () => {
    const config = resolveWebAuthnConfig({
      WEBAUTHN_ALLOWED_ORIGINS: "https://app.example.com,https://admin.example.com",
      WEBAUTHN_RP_ID: "example.com",
    });

    expect(config.rpID).toBe("example.com");
    expect(Array.isArray(config.expectedOrigin)).toBe(true);
    expect(config.origins).toEqual(["https://app.example.com", "https://admin.example.com"]);
  });

  it("requires explicit WEBAUTHN_ALLOWED_ORIGINS", () => {
    expect(() =>
      resolveWebAuthnConfig({
      })
    ).toThrow(/WEBAUTHN_ALLOWED_ORIGINS/i);
  });

  it("throws when origin is incompatible with configured rpID", () => {
    expect(() =>
      resolveWebAuthnConfig({
        WEBAUTHN_ALLOWED_ORIGINS: "https://evil.com",
        WEBAUTHN_RP_ID: "example.com",
      })
    ).toThrow(/not compatible/i);
  });
});
