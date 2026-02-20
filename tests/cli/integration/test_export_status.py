from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import export_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_export_status_help(runner) -> None:
    result = runner.invoke(app, ["export", "status", "--help"])
    assert result.exit_code == 0


def test_export_status_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        export_cmd,
        "get_export_status",
        lambda **kwargs: {"reference_number": "EXP-1", "status_code": 200},
    )
    result = runner.invoke(app, ["export", "status", "--reference", "EXP-1"])
    assert result.exit_code == 0


def test_export_status_json_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        export_cmd,
        "get_export_status",
        lambda **kwargs: {"reference_number": "EXP-2", "status_code": 100},
    )
    result = runner.invoke(app, ["--json", "export", "status", "--reference", "EXP-2"])
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "export.status"


def test_export_status_error_exit(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        export_cmd,
        "get_export_status",
        lambda **kwargs: (_ for _ in ()).throw(CliError("auth", ExitCode.AUTH_ERROR, "login")),
    )
    result = runner.invoke(app, ["export", "status", "--reference", "EXP-3"])
    assert result.exit_code == int(ExitCode.AUTH_ERROR)
