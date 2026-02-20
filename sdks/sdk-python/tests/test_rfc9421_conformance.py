from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from sigilum.http_signatures import sign_http_request, verify_http_signature
from sigilum.identity_store import init_identity, load_identity


def _fixture() -> dict:
    root = Path(__file__).resolve().parents[3]
    path = root / "sdks" / "test-vectors" / "http-signatures-rfc9421.json"
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
            assert signed.method.lower() == vector["expected_method_component"]
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

        signed_by_name: dict[str, object] = {}
        for vector in fixture["vectors"]:
            signed_by_name[vector["name"]] = sign_http_request(
                identity,
                url=vector["url"],
                method=vector["method"],
                body=vector["body"],
                created=fixed["created"],
                nonce=fixed["nonce"],
            )

        for negative in fixture.get("negative_vectors", []):
            base_signed = signed_by_name.get(negative["source_vector"])
            assert base_signed is not None, f'{negative["name"]}: source vector not found'

            headers = dict(base_signed.headers)
            method = base_signed.method
            body = base_signed.body

            mutation = str(negative["mutation"]).lower()
            if mutation == "method":
                method = str(negative["value"])
            elif mutation == "header":
                field = str(negative.get("field", "")).strip().lower()
                assert field, f'{negative["name"]}: header mutation requires field'
                headers[field] = str(negative["value"])
            elif mutation == "body":
                body = str(negative["value"])
            else:
                raise AssertionError(f'{negative["name"]}: unsupported mutation {mutation}')

            result = verify_http_signature(
                url=base_signed.url,
                method=method,
                headers=headers,
                body=body,
                expected_namespace="alice",
                now_ts=fixed["created"] + 5,
                max_age_seconds=60,
            )
            assert result.valid is False
            assert result.reason is not None
            normalized_reason = re.sub(r"[^a-z0-9]+", " ", result.reason.lower()).strip()
            normalized_expected = re.sub(
                r"[^a-z0-9]+",
                " ",
                str(negative["expected_reason_contains"]).lower(),
            ).strip()
            assert normalized_expected in normalized_reason
