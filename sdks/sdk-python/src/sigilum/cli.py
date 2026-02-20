"""Sigilum Python CLI."""

from __future__ import annotations

import argparse
import json

from sigilum.identity_store import init_identity, list_namespaces


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sigilum", description="Sigilum CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Create or load local identity")
    init_parser.add_argument("namespace")
    init_parser.add_argument("--force", action="store_true")
    init_parser.add_argument("--home", default=None)
    init_parser.add_argument("--json", action="store_true")

    list_parser = subparsers.add_parser("list", help="List local identity namespaces")
    list_parser.add_argument("--home", default=None)
    list_parser.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "list":
        namespaces = list_namespaces(args.home)
        if args.json:
            print(
                json.dumps(
                    {
                        "command": "list",
                        "home": args.home,
                        "count": len(namespaces),
                        "namespaces": namespaces,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if not namespaces:
            print("No identities found.")
            return 0
        for namespace in namespaces:
            print(namespace)
        return 0

    if args.command == "init":
        result = init_identity(namespace=args.namespace, home_dir=args.home, force=args.force)
        if args.json:
            print(
                json.dumps(
                    {
                        "command": "init",
                        "created": result.created,
                        "namespace": result.namespace,
                        "did": result.did,
                        "key_id": result.key_id,
                        "public_key": result.public_key,
                        "identity_path": result.identity_path,
                    },
                    sort_keys=True,
                )
            )
            return 0
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
