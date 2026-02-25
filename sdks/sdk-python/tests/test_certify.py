from __future__ import annotations

import tempfile
from dataclasses import dataclass

from sigilum import certify, init_identity, verify_http_signature


@dataclass
class FakeAgent:
    role: str


def test_certify_attaches_sigilum_bindings_without_wrapping() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        init_identity(namespace="alice", home_dir=tmp)
        captured: dict[str, object] = {}

        def fetcher(url: str, method: str, headers: dict[str, str], body: bytes | str | None):
            captured["url"] = url
            captured["method"] = method
            captured["headers"] = headers
            captured["body"] = body
            return {"ok": True}

        agent = FakeAgent(role="wire_approver")
        certified = certify(
            agent,
            namespace="alice",
            home_dir=tmp,
            api_base_url="https://api.sigilum.local",
            fetcher=fetcher,
        )

        assert certified is agent
        assert certified.sigilum.namespace == "alice"

        response = certified.sigilum.request(
            "/claims",
            method="GET",
        )

        assert response == {"ok": True}
        assert captured["url"] == "https://api.sigilum.local/v1/namespaces/alice/claims"

        verify = verify_http_signature(
            url=str(captured["url"]),
            method=str(captured["method"]),
            headers=captured["headers"],
            body=captured["body"],
            expected_namespace="alice",
        )
        assert verify.valid is True


def test_certify_is_idempotent() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        init_identity(namespace="alice", home_dir=tmp)
        agent = FakeAgent(role="wire_approver")

        first = certify(agent, namespace="alice", home_dir=tmp)
        second = certify(agent, namespace="alice", home_dir=tmp)

        assert first is second
        assert first.sigilum.key_id == second.sigilum.key_id


def test_certify_request_supports_subject_override() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        init_identity(namespace="alice", home_dir=tmp)
        captured: dict[str, object] = {}

        def fetcher(url: str, method: str, headers: dict[str, str], body: bytes | str | None):
            captured["url"] = url
            captured["method"] = method
            captured["headers"] = headers
            captured["body"] = body
            return {"ok": True}

        agent = FakeAgent(role="wire_approver")
        certified = certify(
            agent,
            namespace="alice",
            home_dir=tmp,
            api_base_url="https://api.sigilum.local",
            fetcher=fetcher,
        )

        response = certified.sigilum.request(
            "/claims",
            method="GET",
            subject="customer-12345",
        )

        assert response == {"ok": True}

        verify = verify_http_signature(
            url=str(captured["url"]),
            method=str(captured["method"]),
            headers=captured["headers"],
            body=captured["body"],
            expected_namespace="alice",
            expected_subject="customer-12345",
        )
        assert verify.valid is True
        assert verify.subject == "customer-12345"
