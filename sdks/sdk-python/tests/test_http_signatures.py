from __future__ import annotations

import tempfile

from sigilum.http_signatures import sign_http_request, verify_http_signature
from sigilum.identity_store import init_identity, load_identity


def test_sign_and_verify_request() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        init_identity(namespace="alice", home_dir=tmp)
        identity = load_identity(namespace="alice", home_dir=tmp)

        signed = sign_http_request(
            identity,
            url="https://api.sigilum.local/v1/namespaces/alice/claims",
            method="POST",
            headers={"content-type": "application/json"},
            body='{"action":"approve"}',
        )

        result = verify_http_signature(
            url=signed.url,
            method=signed.method,
            headers=signed.headers,
            body=signed.body,
            expected_namespace="alice",
        )

        assert result.valid is True
        assert result.namespace == "alice"
        assert result.subject == "alice"


def test_verify_fails_on_body_tamper() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        init_identity(namespace="alice", home_dir=tmp)
        identity = load_identity(namespace="alice", home_dir=tmp)

        signed = sign_http_request(
            identity,
            url="https://api.sigilum.local/v1/namespaces/alice/claims",
            method="POST",
            body='{"action":"approve"}',
        )

        result = verify_http_signature(
            url=signed.url,
            method=signed.method,
            headers=signed.headers,
            body='{"action":"tampered"}',
            expected_namespace="alice",
        )

        assert result.valid is False
        assert result.reason is not None
        assert "digest" in result.reason.lower()


def test_verify_fails_on_subject_mismatch() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        init_identity(namespace="alice", home_dir=tmp)
        identity = load_identity(namespace="alice", home_dir=tmp)

        signed = sign_http_request(
            identity,
            url="https://api.sigilum.local/v1/namespaces/alice/claims",
            method="GET",
            subject="user:123",
        )

        result = verify_http_signature(
            url=signed.url,
            method=signed.method,
            headers=signed.headers,
            expected_namespace="alice",
            expected_subject="user:999",
        )

        assert result.valid is False
        assert result.reason is not None
        assert "subject mismatch" in result.reason.lower()


def test_verify_fails_on_invalid_signed_component_set() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        init_identity(namespace="alice", home_dir=tmp)
        identity = load_identity(namespace="alice", home_dir=tmp)

        signed = sign_http_request(
            identity,
            url="https://api.sigilum.local/v1/namespaces/alice/claims",
            method="GET",
        )
        signature_input = signed.headers.get("signature-input")
        assert signature_input is not None
        signed.headers["signature-input"] = signature_input.replace('"sigilum-agent-cert"', "")

        result = verify_http_signature(
            url=signed.url,
            method=signed.method,
            headers=signed.headers,
            expected_namespace="alice",
        )

        assert result.valid is False
        assert result.reason is not None
        assert "component set" in result.reason.lower()
