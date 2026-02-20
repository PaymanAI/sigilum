import { Hono } from "hono";
import type { Env } from "../types.js";
import {
  didResolutionHttpStatus,
  resolveSigilumDid,
  type SigilumDidResolutionResult,
} from "../utils/did-resolver.js";

export const didResolutionRouter = new Hono<{ Bindings: Env }>();

/**
 * GET /1.0/identifiers/:did
 * DID Resolution endpoint (W3C DID Resolution shape).
 */
didResolutionRouter.get("/identifiers/:did", async (c) => {
  const did = decodeURIComponent(c.req.param("did"));
  const origin = new URL(c.req.url).origin;

  let resolution: SigilumDidResolutionResult;
  try {
    resolution = await resolveSigilumDid(c.env.DB, did, origin);
  } catch (error) {
    console.error("DID resolution endpoint failed:", error);
    resolution = {
      "@context": "https://w3id.org/did-resolution/v1",
      didDocument: null,
      didDocumentMetadata: {},
      didResolutionMetadata: {
        error: "internalError",
        message: "Authorization store unavailable",
      },
    };
  }

  const status = didResolutionHttpStatus(resolution.didResolutionMetadata.error);
  c.header("Content-Type", 'application/ld+json;profile="https://w3id.org/did-resolution"');
  if (status === 200) {
    c.header("Cache-Control", "public, max-age=300");
  } else {
    c.header("Cache-Control", "no-store");
  }
  return c.json(resolution, status as any);
});
