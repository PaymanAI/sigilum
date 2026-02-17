"""Shared SDK datatypes for the Sigilum Python SDK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Union


@dataclass(frozen=True)
class SigilumCertificateProof:
    alg: str
    sig: str


@dataclass(frozen=True)
class SigilumCertificate:
    version: int
    namespace: str
    did: str
    key_id: str
    public_key: str
    issued_at: str
    expires_at: str | None
    proof: SigilumCertificateProof


@dataclass(frozen=True)
class SigilumIdentity:
    namespace: str
    did: str
    key_id: str
    public_key: str
    private_key: bytes
    certificate: SigilumCertificate
    home_dir: str
    identity_path: str


@dataclass(frozen=True)
class InitIdentityResult:
    namespace: str
    did: str
    key_id: str
    public_key: str
    created: bool
    home_dir: str
    identity_path: str


@dataclass(frozen=True)
class SignedRequest:
    url: str
    method: str
    headers: dict[str, str]
    body: bytes | str | None


@dataclass(frozen=True)
class VerifySignatureResult:
    valid: bool
    namespace: str | None = None
    key_id: str | None = None
    reason: str | None = None


HeaderInput = Union[Dict[str, str], List[Tuple[str, str]], List[List[str]]]


class JsonDict(dict[str, Any]):
    """Typed alias for JSON dictionaries used in internal serialization."""
