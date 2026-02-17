"""Local identity lifecycle for Sigilum agents."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from nacl.signing import SigningKey, VerifyKey

from sigilum.types import (
    InitIdentityResult,
    JsonDict,
    SigilumCertificate,
    SigilumCertificateProof,
    SigilumIdentity,
)

IDENTITY_RECORD_VERSION = 1
CERTIFICATE_VERSION = 1
IDENTITIES_DIR = "identities"
DEFAULT_SIGILUM_HOME = str(Path.home() / ".sigilum")


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalize_namespace(raw: str) -> str:
    namespace = raw.strip().lower()
    if not namespace:
        raise ValueError("Namespace is required")

    import re

    if not re.match(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$", namespace):
        raise ValueError(
            "Namespace must match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$ (3-64 chars, lowercase)",
        )
    return namespace


def _to_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _from_base64url(value: str) -> bytes:
    pad = len(value) % 4
    padded = value if pad == 0 else value + ("=" * (4 - pad))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _get_home_dir(explicit_home_dir: str | None = None) -> str:
    return explicit_home_dir or os.environ.get("SIGILUM_HOME") or DEFAULT_SIGILUM_HOME


def _identity_dir(home_dir: str, namespace: str) -> Path:
    return Path(home_dir) / IDENTITIES_DIR / namespace


def _identity_path(home_dir: str, namespace: str) -> Path:
    return _identity_dir(home_dir, namespace) / "identity.json"


def _did(namespace: str) -> str:
    return f"did:sigilum:{namespace}"


def _fingerprint(public_key: bytes) -> str:
    return hashlib.sha256(public_key).digest()[:8].hex()


def _key_id(did: str, public_key: bytes) -> str:
    return f"{did}#ed25519-{_fingerprint(public_key)}"


def _certificate_payload(certificate: SigilumCertificate) -> bytes:
    parts = [
        "sigilum-certificate-v1",
        f"namespace:{certificate.namespace}",
        f"did:{certificate.did}",
        f"key-id:{certificate.key_id}",
        f"public-key:{certificate.public_key}",
        f"issued-at:{certificate.issued_at}",
        f"expires-at:{certificate.expires_at or ''}",
    ]
    return "\n".join(parts).encode("utf-8")


def _certificate_to_dict(certificate: SigilumCertificate) -> JsonDict:
    return JsonDict({
        "version": certificate.version,
        "namespace": certificate.namespace,
        "did": certificate.did,
        "keyId": certificate.key_id,
        "publicKey": certificate.public_key,
        "issuedAt": certificate.issued_at,
        "expiresAt": certificate.expires_at,
        "proof": {
            "alg": certificate.proof.alg,
            "sig": certificate.proof.sig,
        },
    })


def _certificate_from_dict(value: JsonDict) -> SigilumCertificate:
    proof_raw = value.get("proof")
    if not isinstance(proof_raw, dict):
        raise ValueError("Certificate proof is missing")
    proof = SigilumCertificateProof(
        alg=str(proof_raw.get("alg", "")),
        sig=str(proof_raw.get("sig", "")),
    )
    return SigilumCertificate(
        version=int(value.get("version", 0)),
        namespace=str(value.get("namespace", "")),
        did=str(value.get("did", "")),
        key_id=str(value.get("keyId", "")),
        public_key=str(value.get("publicKey", "")),
        issued_at=str(value.get("issuedAt", "")),
        expires_at=(
            str(value["expiresAt"]) if value.get("expiresAt") is not None else None
        ),
        proof=proof,
    )


def verify_certificate(certificate: SigilumCertificate) -> bool:
    if certificate.version != CERTIFICATE_VERSION:
        return False
    if certificate.proof.alg != "ed25519":
        return False
    if not certificate.public_key.startswith("ed25519:"):
        return False

    public_key = base64.b64decode(certificate.public_key.removeprefix("ed25519:"))
    if len(public_key) != 32:
        return False

    payload = _certificate_payload(certificate)

    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(payload, _from_base64url(certificate.proof.sig))
    except Exception:
        return False

    return True


def _create_record(namespace: str) -> JsonDict:
    signing_key = SigningKey.generate()
    private_key = bytes(signing_key)
    public_key = bytes(signing_key.verify_key)

    did = _did(namespace)
    public_key_b64 = base64.b64encode(public_key).decode("ascii")
    key_id = _key_id(did, public_key)
    now = _iso_now()

    cert = SigilumCertificate(
        version=CERTIFICATE_VERSION,
        namespace=namespace,
        did=did,
        key_id=key_id,
        public_key=f"ed25519:{public_key_b64}",
        issued_at=now,
        expires_at=None,
        proof=SigilumCertificateProof(alg="ed25519", sig=""),
    )

    cert_signature = signing_key.sign(_certificate_payload(cert)).signature
    cert = SigilumCertificate(
        version=cert.version,
        namespace=cert.namespace,
        did=cert.did,
        key_id=cert.key_id,
        public_key=cert.public_key,
        issued_at=cert.issued_at,
        expires_at=cert.expires_at,
        proof=SigilumCertificateProof(alg="ed25519", sig=_to_base64url(cert_signature)),
    )

    return JsonDict({
        "version": IDENTITY_RECORD_VERSION,
        "namespace": namespace,
        "did": did,
        "keyId": key_id,
        "publicKey": f"ed25519:{public_key_b64}",
        "privateKey": base64.b64encode(private_key).decode("ascii"),
        "certificate": _certificate_to_dict(cert),
        "createdAt": now,
        "updatedAt": now,
    })


def list_namespaces(home_dir: str | None = None) -> list[str]:
    root = Path(_get_home_dir(home_dir)) / IDENTITIES_DIR
    if not root.exists():
        return []
    namespaces: list[str] = []
    for child in sorted(root.iterdir()):
        if (child / "identity.json").exists() and child.is_dir():
            namespaces.append(child.name)
    return namespaces


def _resolve_namespace(namespace: str | None, home_dir: str | None) -> str:
    if namespace:
        return _normalize_namespace(namespace)

    env_namespace = os.environ.get("SIGILUM_NAMESPACE")
    if env_namespace:
        return _normalize_namespace(env_namespace)

    namespaces = list_namespaces(home_dir)
    if len(namespaces) == 1:
        return namespaces[0]
    if len(namespaces) == 0:
        raise ValueError("No Sigilum identity found. Run `sigilum init <namespace>` first.")
    raise ValueError(
        f"Multiple identities found ({', '.join(namespaces)}). Pass namespace explicitly or set SIGILUM_NAMESPACE.",
    )


def load_identity(namespace: str | None = None, home_dir: str | None = None) -> SigilumIdentity:
    home = _get_home_dir(home_dir)
    ns = _resolve_namespace(namespace, home)
    identity_path = _identity_path(home, ns)

    if not identity_path.exists():
        raise ValueError(
            f"Sigilum identity not found for namespace '{ns}' at {identity_path}. Run `sigilum init {ns}` first.",
        )

    try:
        raw = json.loads(identity_path.read_text(encoding="utf-8"))
    except Exception as error:
        raise ValueError(f"Failed to parse identity file {identity_path}: {error}")

    if not isinstance(raw, dict):
        raise ValueError(f"Identity file {identity_path} is invalid")

    if int(raw.get("version", 0)) != IDENTITY_RECORD_VERSION:
        raise ValueError("Unsupported identity record version")

    cert_raw = raw.get("certificate")
    if not isinstance(cert_raw, dict):
        raise ValueError("Identity certificate missing")

    cert = _certificate_from_dict(JsonDict(cert_raw))
    if not verify_certificate(cert):
        raise ValueError("Identity certificate verification failed")

    private_key = base64.b64decode(str(raw.get("privateKey", "")))
    if len(private_key) != 32:
        raise ValueError("Invalid private key length")

    public_key = bytes(SigningKey(private_key).verify_key)
    expected_public = f"ed25519:{base64.b64encode(public_key).decode('ascii')}"

    if raw.get("publicKey") != expected_public:
        raise ValueError("Public key mismatch in identity file")

    did = str(raw.get("did", ""))
    key_id = str(raw.get("keyId", ""))
    if cert.namespace != ns or cert.did != did or cert.key_id != key_id or cert.public_key != expected_public:
        raise ValueError("Certificate and identity record do not match")

    return SigilumIdentity(
        namespace=ns,
        did=did,
        key_id=key_id,
        public_key=expected_public,
        private_key=private_key,
        certificate=cert,
        home_dir=home,
        identity_path=str(identity_path),
    )


def init_identity(
    namespace: str,
    home_dir: str | None = None,
    force: bool = False,
) -> InitIdentityResult:
    ns = _normalize_namespace(namespace)
    home = _get_home_dir(home_dir)
    identity_path = _identity_path(home, ns)

    if identity_path.exists() and not force:
        identity = load_identity(namespace=ns, home_dir=home)
        return InitIdentityResult(
            namespace=identity.namespace,
            did=identity.did,
            key_id=identity.key_id,
            public_key=identity.public_key,
            created=False,
            home_dir=home,
            identity_path=str(identity_path),
        )

    record = _create_record(ns)
    identity_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(identity_path.parent, 0o700)
    identity_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    os.chmod(identity_path, 0o600)

    return InitIdentityResult(
        namespace=ns,
        did=str(record["did"]),
        key_id=str(record["keyId"]),
        public_key=str(record["publicKey"]),
        created=True,
        home_dir=home,
        identity_path=str(identity_path),
    )


def get_namespace_api_base(api_base_url: str, namespace: str) -> str:
    return f"{api_base_url.rstrip('/')}/v1/namespaces/{quote(namespace, safe='')}"
