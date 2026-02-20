from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import upo_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_upo_get_help(runner) -> None:
    result = runner.invoke(app, ["upo", "get", "--help"])
    assert result.exit_code == 0


def test_upo_get_success(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_get(**kwargs):
        seen.update(kwargs)
        return {"session_ref": kwargs["session_ref"], "path": "upo.xml", "bytes": 100}

    monkeypatch.setattr(upo_cmd, "get_upo", _fake_get)

    result = runner.invoke(
        app,
        [
            "upo",
            "get",
            "--session-ref",
            "SES-1",
            "--invoice-ref",
            "INV-1",
            "--out",
            "tmp/upo.xml",
            "--overwrite",
        ],
    )

    assert result.exit_code == 0
    assert seen["session_ref"] == "SES-1"
    assert seen["invoice_ref"] == "INV-1"
    assert seen["overwrite"] is True


def test_upo_get_json_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        upo_cmd, "get_upo", lambda **kwargs: {"session_ref": "SES-1", "path": "upo.xml", "bytes": 5}
    )

    result = runner.invoke(
        app,
        [
            "--json",
            "upo",
            "get",
            "--session-ref",
            "SES-1",
            "--invoice-ref",
            "INV-1",
            "--out",
            "upo.xml",
        ],
    )

    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "upo.get"
    assert payload["data"]["session_ref"] == "SES-1"


def test_upo_get_validation_error_exit_code(runner, monkeypatch) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise CliError("select one identifier", ExitCode.VALIDATION_ERROR, "use --invoice-ref")

    monkeypatch.setattr(upo_cmd, "get_upo", _raise_error)

    result = runner.invoke(
        app, ["upo", "get", "--session-ref", "SES-1", "--invoice-ref", "INV", "--out", "upo.xml"]
    )

    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
