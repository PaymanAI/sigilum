export interface SigilumCertificate {
  version: 1;
  namespace: string;
  did: string;
  keyId: string;
  publicKey: string;
  issuedAt: string;
  expiresAt: string | null;
  proof: {
    alg: "ed25519";
    sig: string;
  };
}

export interface StoredIdentityRecord {
  version: 1;
  namespace: string;
  did: string;
  keyId: string;
  publicKey: string;
  privateKey: string;
  certificate: SigilumCertificate;
  createdAt: string;
  updatedAt: string;
}

export interface SigilumIdentity {
  namespace: string;
  did: string;
  keyId: string;
  publicKey: string;
  privateKey: Uint8Array;
  certificate: SigilumCertificate;
  homeDir: string;
  identityPath: string;
}

export interface InitIdentityOptions {
  namespace: string;
  homeDir?: string;
  force?: boolean;
}

export interface InitIdentityResult {
  namespace: string;
  did: string;
  keyId: string;
  publicKey: string;
  created: boolean;
  homeDir: string;
  identityPath: string;
}

export interface LoadIdentityOptions {
  namespace?: string;
  homeDir?: string;
}

export interface CertifyOptions {
  namespace?: string;
  homeDir?: string;
  apiBaseUrl?: string;
  fetchImpl?: typeof fetch;
}

export type HeaderInput = unknown;

export interface SignRequestInput {
  url: string | URL;
  method?: string;
  headers?: HeaderInput;
  body?: string | Uint8Array | ArrayBuffer | null;
  created?: number;
  nonce?: string;
}

export interface SignedRequest {
  url: string;
  method: string;
  headers: Headers;
  body?: string | Uint8Array | ArrayBuffer | null;
}

export interface SigilumAgentBindings {
  namespace: string;
  did: string;
  keyId: string;
  publicKey: string;
  certificate: SigilumCertificate;
  apiBaseUrl: string;
  sign(request: SignRequestInput): SignedRequest;
  fetch(input: string | URL | Request, init?: RequestInit): Promise<Response>;
  request(path: string, init?: RequestInit): Promise<Response>;
}

export type CertifiedAgent<T extends object> = T & {
  sigilum: SigilumAgentBindings;
};

export interface VerifySignatureInput {
  url: string | URL;
  method: string;
  headers: HeaderInput;
  body?: string | Uint8Array | ArrayBuffer | null;
  expectedNamespace?: string;
  strict?: {
    now?: number;
    maxAgeSeconds?: number;
    nonceStore?: Set<string>;
  };
}

export interface VerifySignatureResult {
  valid: boolean;
  namespace?: string;
  keyId?: string;
  reason?: string;
}
