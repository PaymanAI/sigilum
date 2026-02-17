from __future__ import annotations

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
