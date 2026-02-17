from __future__ import annotations

import json
import tempfile
from pathlib import Path

from sigilum.http_signatures import sign_http_request, verify_http_signature
from sigilum.identity_store import init_identity, load_identity


def _fixture() -> dict:
    root = Path(__file__).resolve().parents[3]
    path = root / "sdks" / "shared" / "test-vectors" / "http-signatures-rfc9421.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_rfc9421_profile_vectors_and_strict_checks() -> None:
    fixture = _fixture()
    fixed = fixture["fixed"]

    with tempfile.TemporaryDirectory() as tmp:
        init_identity(namespace="alice", home_dir=tmp)
        identity = load_identity(namespace="alice", home_dir=tmp)

        for vector in fixture["vectors"]:
            signed = sign_http_request(
                identity,
                url=vector["url"],
                method=vector["method"],
                body=vector["body"],
                created=fixed["created"],
                nonce=fixed["nonce"],
            )

            assert signed.url == vector["expected_target_uri"]
            signature_input = signed.headers.get("signature-input")
            assert signature_input is not None
            assert f'created={fixed["created"]}' in signature_input
            assert f'nonce="{fixed["nonce"]}"' in signature_input
            expected_components = " ".join(f'"{c}"' for c in vector["expected_components"])
            assert f"({expected_components})" in signature_input

            if "expected_content_digest" in vector:
                assert signed.headers.get("content-digest") == vector["expected_content_digest"]

            seen_nonces: set[str] = set()
            ok = verify_http_signature(
                url=signed.url,
                method=signed.method,
                headers=signed.headers,
                body=signed.body,
                expected_namespace="alice",
                now_ts=fixed["created"] + 5,
                max_age_seconds=60,
                seen_nonces=seen_nonces,
            )
            assert ok.valid is True

            replay = verify_http_signature(
                url=signed.url,
                method=signed.method,
                headers=signed.headers,
                body=signed.body,
                expected_namespace="alice",
                now_ts=fixed["created"] + 5,
                max_age_seconds=60,
                seen_nonces=seen_nonces,
            )
            assert replay.valid is False
            assert replay.reason is not None
            assert "replay" in replay.reason.lower()

            stale = verify_http_signature(
                url=signed.url,
                method=signed.method,
                headers=signed.headers,
                body=signed.body,
                expected_namespace="alice",
                now_ts=fixed["created"] + 500,
                max_age_seconds=60,
            )
            assert stale.valid is False
            assert stale.reason is not None
            assert "expired" in stale.reason.lower() or "valid" in stale.reason.lower()
