import { describe, expect, it } from "vitest";
import { resolveWebAuthnConfig } from "../utils/webauthn-config.js";

describe("resolveWebAuthnConfig", () => {
  it("derives rpID from configured WebAuthn origins", () => {
    const config = resolveWebAuthnConfig({
      WEBAUTHN_ALLOWED_ORIGINS: "https://dashboard.example.com",
      ALLOWED_ORIGINS: "",
    });

    expect(config.rpID).toBe("dashboard.example.com");
    expect(config.expectedOrigin).toBe("https://dashboard.example.com");
  });

  it("supports multiple allowed origins with explicit rpID", () => {
    const config = resolveWebAuthnConfig({
      WEBAUTHN_ALLOWED_ORIGINS: "https://app.example.com,https://admin.example.com",
      WEBAUTHN_RP_ID: "example.com",
      ALLOWED_ORIGINS: "",
    });

    expect(config.rpID).toBe("example.com");
    expect(Array.isArray(config.expectedOrigin)).toBe(true);
    expect(config.origins).toEqual(["https://app.example.com", "https://admin.example.com"]);
  });

  it("falls back to ALLOWED_ORIGINS when WebAuthn-specific origins are not provided", () => {
    const config = resolveWebAuthnConfig({
      ALLOWED_ORIGINS: "http://localhost:5000",
    });

    expect(config.rpID).toBe("localhost");
    expect(config.expectedOrigin).toBe("http://localhost:5000");
  });

  it("throws when origin is incompatible with configured rpID", () => {
    expect(() =>
      resolveWebAuthnConfig({
        WEBAUTHN_ALLOWED_ORIGINS: "https://evil.com",
        WEBAUTHN_RP_ID: "example.com",
        ALLOWED_ORIGINS: "",
      })
    ).toThrow(/not compatible/i);
  });
});
