import "./setup.js";

export { init } from "./init.js";
export {
  certify,
  getSigilum,
  SIGILUM_CONTEXT_SYMBOL,
} from "./certify.js";
export {
  signHttpRequest,
  verifyHttpSignature,
  encodeCertificateHeader,
  decodeCertificateHeader,
} from "./http-signatures.js";
export {
  DEFAULT_SIGILUM_HOME,
  getNamespaceApiBase,
  initIdentity,
  listNamespaces,
  loadIdentity,
  verifyCertificate,
} from "./identity-store.js";

export type {
  CertifiedAgent,
  CertifyOptions,
  InitIdentityOptions,
  InitIdentityResult,
  LoadIdentityOptions,
  SigilumAgentBindings,
  SigilumCertificate,
  SigilumIdentity,
  SignRequestInput,
  SignedRequest,
  VerifySignatureInput,
  VerifySignatureResult,
} from "./types.js";
