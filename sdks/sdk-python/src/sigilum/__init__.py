"""Sigilum Python SDK: local identity, one-line certify, and RFC 9421 signatures."""

from sigilum.certify import SigilumBindings, certify
from sigilum.http_signatures import (
    decode_certificate_header,
    encode_certificate_header,
    sign_http_request,
    verify_http_signature,
)
from sigilum.identity_store import (
    DEFAULT_SIGILUM_HOME,
    get_namespace_api_base,
    init_identity,
    list_namespaces,
    load_identity,
    verify_certificate,
)
from sigilum.init import init
from sigilum.types import (
    InitIdentityResult,
    SigilumCertificate,
    SigilumCertificateProof,
    SigilumIdentity,
    SignedRequest,
    VerifySignatureResult,
)

__all__ = [
    "DEFAULT_SIGILUM_HOME",
    "InitIdentityResult",
    "SigilumBindings",
    "SigilumCertificate",
    "SigilumCertificateProof",
    "SigilumIdentity",
    "SignedRequest",
    "VerifySignatureResult",
    "certify",
    "decode_certificate_header",
    "encode_certificate_header",
    "get_namespace_api_base",
    "init",
    "init_identity",
    "list_namespaces",
    "load_identity",
    "sign_http_request",
    "verify_certificate",
    "verify_http_signature",
]

__version__ = "0.0.1"
