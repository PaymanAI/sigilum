import json

from sigilum.cli import main


def test_cli_list_json_empty(tmp_path, capsys) -> None:
    exit_code = main(["list", "--home", str(tmp_path), "--json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    payload = json.loads(captured.out.strip())
    assert payload["command"] == "list"
    assert payload["count"] == 0
    assert payload["namespaces"] == []


def test_cli_init_json(tmp_path, capsys) -> None:
    exit_code = main(["init", "alice", "--home", str(tmp_path), "--json"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    payload = json.loads(captured.out.strip())
    assert payload["command"] == "init"
    assert payload["created"] is True
    assert payload["namespace"] == "alice"
    assert payload["did"] == "did:sigilum:alice"
    assert "#ed25519-" in payload["key_id"]
    assert len(payload["public_key"]) > 10
    assert payload["identity_path"].endswith("identities/alice/identity.json")
