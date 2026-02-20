"""RFC 9421 HTTP Message Signatures for Sigilum agent identity."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from nacl.signing import SigningKey, VerifyKey

from sigilum.identity_store import verify_certificate
from sigilum.types import (
    HeaderInput,
    SigilumCertificate,
    SigilumIdentity,
    SignedRequest,
    VerifySignatureResult,
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _from_b64url(value: str) -> bytes:
    pad = len(value) % 4
    padded = value if pad == 0 else value + ("=" * (4 - pad))
    return base64.urlsafe_b64decode(padded)


def _normalize_headers(headers: HeaderInput | None) -> dict[str, str]:
    if headers is None:
        return {}

    out: dict[str, str] = {}
    if isinstance(headers, dict):
        for key, value in headers.items():
            out[str(key).lower()] = str(value)
        return out

    for entry in headers:
        if len(entry) != 2:
            raise ValueError("Header entries must be [name, value]")
        out[str(entry[0]).lower()] = str(entry[1])

    return out


def _normalize_body(body: bytes | str | None) -> bytes | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body
    if isinstance(body, str):
        return body.encode("utf-8")
    raise ValueError("Unsupported body type. Use bytes, str, or None.")


def _content_digest(body: bytes) -> str:
    digest = hashlib.sha256(body).digest()
    return f"sha-256=:{base64.b64encode(digest).decode('ascii')}:"


def _signature_params(components: list[str], created: int, key_id: str, nonce: str) -> str:
    component_str = " ".join(f'"{component}"' for component in components)
    return (
        f"({component_str});created={created};keyid=\"{key_id}\";"
        f"alg=\"ed25519\";nonce=\"{nonce}\""
    )


def _normalize_target_uri(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _component_value(component: str, method: str, url: str, headers: dict[str, str]) -> str:
    if component == "@method":
        return method.lower()
    if component == "@target-uri":
        return url

    value = headers.get(component)
    if not value:
        raise ValueError(f"Missing required signed header: {component}")
    return value


def _signing_base(
    components: list[str],
    method: str,
    url: str,
    headers: dict[str, str],
    signature_params: str,
) -> bytes:
    lines = []
    for component in components:
        value = _component_value(component, method, url, headers)
        lines.append(f'"{component}": {value}')
    lines.append(f'"@signature-params": {signature_params}')
    return "\n".join(lines).encode("utf-8")


def encode_certificate_header(certificate: SigilumCertificate) -> str:
    payload = {
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
    }
    return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")


def decode_certificate_header(value: str) -> SigilumCertificate:
    raw = json.loads(_from_b64url(value).decode("utf-8"))
    proof_raw = raw["proof"]
    from sigilum.types import SigilumCertificateProof

    return SigilumCertificate(
        version=int(raw["version"]),
        namespace=str(raw["namespace"]),
        did=str(raw["did"]),
        key_id=str(raw["keyId"]),
        public_key=str(raw["publicKey"]),
        issued_at=str(raw["issuedAt"]),
        expires_at=str(raw["expiresAt"]) if raw.get("expiresAt") is not None else None,
        proof=SigilumCertificateProof(alg=str(proof_raw["alg"]), sig=str(proof_raw["sig"])),
    )


def sign_http_request(
    identity: SigilumIdentity,
    url: str,
    method: str = "GET",
    headers: HeaderInput | None = None,
    body: bytes | str | None = None,
    created: int | None = None,
    nonce: str | None = None,
    subject: str | None = None,
) -> SignedRequest:
    normalized_method = method.upper()
    normalized_url = _normalize_target_uri(url)
    normalized_headers = _normalize_headers(headers)
    body_bytes = _normalize_body(body)

    if body_bytes:
        normalized_headers["content-digest"] = _content_digest(body_bytes)

    normalized_headers["sigilum-namespace"] = identity.namespace
    subject_value = (subject or normalized_headers.get("sigilum-subject") or identity.namespace).strip()
    if not subject_value:
        subject_value = identity.namespace
    normalized_headers["sigilum-subject"] = subject_value
    normalized_headers["sigilum-agent-key"] = identity.public_key
    normalized_headers["sigilum-agent-cert"] = encode_certificate_header(identity.certificate)

    components = [
        "@method",
        "@target-uri",
        "sigilum-namespace",
        "sigilum-subject",
        "sigilum-agent-key",
        "sigilum-agent-cert",
    ]
    if body_bytes:
        components.insert(2, "content-digest")

    created_value = created if created is not None else int(datetime.now(timezone.utc).timestamp())
    nonce_value = nonce or str(uuid.uuid4())
    signature_params = _signature_params(components, created_value, identity.key_id, nonce_value)

    signing_base = _signing_base(
        components=components,
        method=normalized_method,
        url=normalized_url,
        headers=normalized_headers,
        signature_params=signature_params,
    )

    signature = SigningKey(identity.private_key).sign(signing_base).signature

    normalized_headers["signature-input"] = f"sig1={signature_params}"
    normalized_headers["signature"] = f"sig1=:{base64.b64encode(signature).decode('ascii')}:"

    return SignedRequest(
        url=normalized_url,
        method=normalized_method,
        headers=normalized_headers,
        body=body,
    )


_SIGNATURE_INPUT_PATTERN = re.compile(
    r'^sig1=\(([^)]*)\);created=(\d+);keyid="([^"]+)";alg="([^"]+)";nonce="([^"]+)"$',
)

_SIGNATURE_PATTERN = re.compile(r"^sig1=:([^:]+):$")

_REQUIRED_COMPONENTS_NO_BODY = [
    "@method",
    "@target-uri",
    "sigilum-namespace",
    "sigilum-subject",
    "sigilum-agent-key",
    "sigilum-agent-cert",
]

_REQUIRED_COMPONENTS_WITH_BODY = [
    "@method",
    "@target-uri",
    "content-digest",
    "sigilum-namespace",
    "sigilum-subject",
    "sigilum-agent-key",
    "sigilum-agent-cert",
]


def _valid_signed_component_set(components: list[str], has_body: bool) -> bool:
    expected = _REQUIRED_COMPONENTS_WITH_BODY if has_body else _REQUIRED_COMPONENTS_NO_BODY
    return components == expected


def verify_http_signature(
    *,
    url: str,
    method: str,
    headers: HeaderInput,
    body: bytes | str | None = None,
    expected_namespace: str | None = None,
    expected_subject: str | None = None,
    max_age_seconds: int | None = None,
    now_ts: int | None = None,
    seen_nonces: set[str] | None = None,
) -> VerifySignatureResult:
    try:
        normalized_headers = _normalize_headers(headers)
        signature_input = normalized_headers.get("signature-input")
        signature_header = normalized_headers.get("signature")

        if not signature_input or not signature_header:
            return VerifySignatureResult(valid=False, reason="Missing Signature-Input or Signature header")

        match = _SIGNATURE_INPUT_PATTERN.match(signature_input)
        if not match:
            return VerifySignatureResult(valid=False, reason="Invalid Signature-Input format")

        raw_components, created_raw, key_id, alg, nonce = match.groups()
        created_value = int(created_raw)
        if created_value <= 0:
            return VerifySignatureResult(valid=False, reason="Invalid Signature-Input created timestamp")
        if alg.lower() != "ed25519":
            return VerifySignatureResult(valid=False, reason="Unsupported signature algorithm")
        if max_age_seconds is not None:
            now_value = now_ts if now_ts is not None else int(datetime.now(timezone.utc).timestamp())
            age = now_value - created_value
            if age < 0 or age > max_age_seconds:
                return VerifySignatureResult(valid=False, reason="Signature expired or not yet valid")
        if seen_nonces is not None:
            if nonce in seen_nonces:
                return VerifySignatureResult(valid=False, reason="Replay detected: nonce already seen")
            seen_nonces.add(nonce)

        components: list[str] = []
        for token in raw_components.strip().split():
            if not (token.startswith('"') and token.endswith('"')):
                return VerifySignatureResult(valid=False, reason="Invalid component in Signature-Input")
            components.append(token[1:-1])

        signature_match = _SIGNATURE_PATTERN.match(signature_header)
        if not signature_match:
            return VerifySignatureResult(valid=False, reason="Invalid Signature format")
        signature = base64.b64decode(signature_match.group(1).encode("ascii"))

        cert_header = normalized_headers.get("sigilum-agent-cert")
        if not cert_header:
            return VerifySignatureResult(valid=False, reason="Missing sigilum-agent-cert header")
        cert = decode_certificate_header(cert_header)

        if not verify_certificate(cert):
            return VerifySignatureResult(valid=False, reason="Invalid agent certificate")

        namespace_header = normalized_headers.get("sigilum-namespace")
        if namespace_header != cert.namespace:
            return VerifySignatureResult(valid=False, reason="Namespace header mismatch")
        subject_header = (normalized_headers.get("sigilum-subject") or "").strip()
        if not subject_header:
            return VerifySignatureResult(valid=False, reason="Missing sigilum-subject header")
        if "sigilum-subject" not in components:
            return VerifySignatureResult(valid=False, reason="Missing sigilum-subject in signed components")

        if expected_namespace and expected_namespace != namespace_header:
            return VerifySignatureResult(
                valid=False,
                reason=f"Namespace mismatch: expected {expected_namespace}, got {namespace_header}",
            )
        if expected_subject and expected_subject != subject_header:
            return VerifySignatureResult(
                valid=False,
                reason=f"Subject mismatch: expected {expected_subject}, got {subject_header}",
            )

        key_header = normalized_headers.get("sigilum-agent-key")
        if key_header != cert.public_key:
            return VerifySignatureResult(valid=False, reason="Certificate public key mismatch")

        if key_id != cert.key_id:
            return VerifySignatureResult(valid=False, reason="keyid mismatch")

        body_bytes = _normalize_body(body)
        has_body = bool(body_bytes and len(body_bytes) > 0)
        if not _valid_signed_component_set(components, has_body):
            return VerifySignatureResult(valid=False, reason="Invalid signed component set")
        if body_bytes:
            digest = _content_digest(body_bytes)
            if normalized_headers.get("content-digest") != digest:
                return VerifySignatureResult(valid=False, reason="Content digest mismatch")

        signature_params = _signature_params(
            components=components,
            created=created_value,
            key_id=key_id,
            nonce=nonce,
        )
        signing_base = _signing_base(
            components=components,
            method=method.upper(),
            url=_normalize_target_uri(url),
            headers=normalized_headers,
            signature_params=signature_params,
        )

        if not key_header or not key_header.startswith("ed25519:"):
            return VerifySignatureResult(valid=False, reason="Invalid sigilum-agent-key header")

        public_key = base64.b64decode(key_header.removeprefix("ed25519:"))
        VerifyKey(public_key).verify(signing_base, signature)

        return VerifySignatureResult(valid=True, namespace=cert.namespace, subject=subject_header, key_id=cert.key_id)
    except Exception as error:
        return VerifySignatureResult(valid=False, reason=str(error))
