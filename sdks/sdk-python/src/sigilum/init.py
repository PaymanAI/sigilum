"""Top-level init() helper matching the SDK's one-command identity bootstrap."""

from __future__ import annotations

from sigilum.identity_store import init_identity


def init(*, namespace: str, home_dir: str | None = None, force: bool = False):
    return init_identity(namespace=namespace, home_dir=home_dir, force=force)
