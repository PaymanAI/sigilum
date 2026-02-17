"""Sigilum Python CLI."""

from __future__ import annotations

import argparse

from sigilum.identity_store import init_identity, list_namespaces


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sigilum", description="Sigilum CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create or load local identity")
    init_parser.add_argument("namespace")
    init_parser.add_argument("--force", action="store_true")
    init_parser.add_argument("--home", default=None)

    list_parser = subparsers.add_parser("list", help="List local identity namespaces")
    list_parser.add_argument("--home", default=None)

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "list":
        namespaces = list_namespaces(args.home)
        if not namespaces:
            print("No identities found.")
            return 0
        for namespace in namespaces:
            print(namespace)
        return 0

    if args.command == "init":
        result = init_identity(namespace=args.namespace, home_dir=args.home, force=args.force)
        print("Created Sigilum identity" if result.created else "Loaded existing Sigilum identity")
        print(f"namespace: {result.namespace}")
        print(f"did: {result.did}")
        print(f"keyId: {result.key_id}")
        print(f"publicKey: {result.public_key}")
        print(f"identityPath: {result.identity_path}")
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

