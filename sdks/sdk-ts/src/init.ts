import { initIdentity } from "./identity-store.js";
import type { InitIdentityOptions, InitIdentityResult } from "./types.js";

export function init(options: InitIdentityOptions): InitIdentityResult {
  return initIdentity(options);
}
