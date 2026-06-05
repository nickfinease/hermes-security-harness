import json

from security_harness.cli import main


def test_validate_target_cli_writes_json(capsys):
    rc = main(["validate-target", "examples/web-target.local.yaml"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["success"] is True
    assert out["target_id"] == "local-demo"
