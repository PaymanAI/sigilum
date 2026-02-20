from __future__ import annotations

import json
import tempfile
from pathlib import Path

from sigilum.identity_store import init_identity, list_namespaces, load_identity


def test_init_identity_creates_local_record() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        result = init_identity(namespace="alice", home_dir=tmp)
        assert result.created is True
        assert result.namespace == "alice"
        assert result.did == "did:sigilum:alice"
        assert Path(result.identity_path).exists()


def test_init_identity_reuses_existing_without_force() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        first = init_identity(namespace="alice", home_dir=tmp)
        second = init_identity(namespace="alice", home_dir=tmp)
        assert first.created is True
        assert second.created is False
        assert first.public_key == second.public_key


def test_load_identity_and_list_namespaces() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        init_identity(namespace="alice", home_dir=tmp)
        init_identity(namespace="bob", home_dir=tmp)

        identity = load_identity(namespace="alice", home_dir=tmp)
        namespaces = list_namespaces(tmp)

        assert identity.namespace == "alice"
        assert namespaces == ["alice", "bob"]


def test_load_identity_shared_v1_fixture() -> None:
    fixture_path = Path(__file__).resolve().parents[2] / "test-vectors" / "identity-record-v1.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    namespace = str(fixture["namespace"])

    with tempfile.TemporaryDirectory() as tmp:
        identity_dir = Path(tmp) / "identities" / namespace
        identity_dir.mkdir(parents=True, exist_ok=True)
        (identity_dir / "identity.json").write_text(
            json.dumps(fixture, indent=2) + "\n",
            encoding="utf-8",
        )

        identity = load_identity(namespace=namespace, home_dir=tmp)
        assert identity.namespace == namespace
        assert identity.did == fixture["did"]
        assert identity.key_id == fixture["keyId"]
