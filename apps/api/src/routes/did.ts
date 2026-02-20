import { Hono } from "hono";
import type { Env } from "../types.js";
import { createErrorResponse } from "../utils/validation.js";
import { didResolutionHttpStatus, resolveSigilumDid } from "../utils/did-resolver.js";

export const didRouter = new Hono<{ Bindings: Env }>();

/**
 * GET /.well-known/did/:did
 * Resolve a DID document (W3C format).
 */
didRouter.get("/:did", async (c) => {
  const did = decodeURIComponent(c.req.param("did"));
  const origin = new URL(c.req.url).origin;

  try {
    const resolution = await resolveSigilumDid(c.env.DB, did, origin);
    if (!resolution.didDocument) {
      const error = resolution.didResolutionMetadata.error;
      const status = didResolutionHttpStatus(error);
      if (error === "invalidDid") {
        return c.json(
          createErrorResponse(
            resolution.didResolutionMetadata.message ?? "Invalid DID",
            "VALIDATION_ERROR",
          ),
          status as any,
        );
      }
      return c.json(
        createErrorResponse(
          resolution.didResolutionMetadata.message ?? "DID not found",
          "NOT_FOUND",
        ),
        status as any,
      );
    }

    c.header("Content-Type", "application/did+ld+json");
    c.header("Cache-Control", "public, max-age=300");
    return c.json(resolution.didDocument);
  } catch (error) {
    console.error("DID resolution failed:", error);
    return c.json(createErrorResponse("Authorization store unavailable", "DB_UNAVAILABLE"), 503);
  }
});
