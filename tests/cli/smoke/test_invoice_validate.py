import builtins
import json
import os

import pytest
from tests.test_fa3_parse import basic_invoice

from ksef_client.cli import app
from ksef_client.documents.fa3 import report as validation


def test_no_profile_valid_invalid_and_input_errors(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "empty"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty"))
    path = tmp_path / "PRIVATE-path.xml"
    args = ["--json", "invoice", "validate", str(path)]
    missing = runner.invoke(app, args)
    assert missing.exit_code == 8
    assert json.loads(missing.stdout)["errors"][0]["code"] == "IO_ERROR"
    assert "PRIVATE-path" not in missing.stdout
    xml = basic_invoice("PRIVATE invoice").to_xml()
    path.write_bytes(xml)
    valid = runner.invoke(app, args)
    assert valid.exit_code == 0, valid.output
    assert json.loads(valid.stdout)["data"]["valid"] is True
    path.write_bytes(xml.replace(b"<NIP>", b"<NIP>secret-"))
    monkeypatch.setattr(validation, "_MAX_ISSUES", 1)
    invalid = runner.invoke(app, args)
    assert invalid.exit_code == 2
    result = json.loads(invalid.stdout)
    assert result["ok"] is False
    assert result["data"] == validation.validate_invoice_xml(path.read_bytes()).to_dict()
    assert "secret-" not in invalid.stdout and "PRIVATE" not in invalid.stdout
    human = runner.invoke(app, args[1:])
    assert human.exit_code == 2 and "NIP" in human.output
    assert "10 cyfr" in human.output and "skrócona" in human.output
    path.write_bytes(b"")
    assert runner.invoke(app, args).exit_code == 2


def test_install_hint_for_missing_extra(runner, monkeypatch, tmp_path):
    original = builtins.__import__

    def no_lxml(name, *args, **kwargs):
        if name == "lxml":
            raise ImportError
        return original(name, *args, **kwargs)

    path = tmp_path / "sample.xml"
    path.write_bytes(b"<Faktura/>")
    monkeypatch.setattr(builtins, "__import__", no_lxml)
    result = runner.invoke(app, ["--json", "invoice", "validate", str(path)])
    assert result.exit_code == 6
    assert "[cli,fa3]" in json.loads(result.stdout)["errors"][0]["hint"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX device input")
def test_non_regular_input(runner):
    result = runner.invoke(app, ["--json", "invoice", "validate", os.devnull])
    assert result.exit_code == 8
