import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

// @noble/ed25519 requires a sha512 implementation at runtime.
ed.hashes.sha512 = (...messages: Uint8Array[]) => sha512(ed.etc.concatBytes(...messages));
