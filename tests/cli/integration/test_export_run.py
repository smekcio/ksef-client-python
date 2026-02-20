from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import export_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_export_run_help(runner) -> None:
    result = runner.invoke(app, ["export", "run", "--help"])
    assert result.exit_code == 0


def test_export_run_success(runner, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        export_cmd,
        "run_export",
        lambda **kwargs: {
            "reference_number": "EXP-1",
            "out_dir": str(tmp_path),
            "xml_files_count": 1,
        },
    )
    result = runner.invoke(
        app, ["export", "run", "--from", "2026-01-01", "--to", "2026-01-31", "--out", str(tmp_path)]
    )
    assert result.exit_code == 0


def test_export_run_json_success(runner, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(export_cmd, "run_export", lambda **kwargs: {"reference_number": "EXP-2"})
    result = runner.invoke(app, ["--json", "export", "run", "--out", str(tmp_path)])
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "export.run"


def test_export_run_validation_error_exit(runner, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        export_cmd,
        "run_export",
        lambda **kwargs: (_ for _ in ()).throw(CliError("bad", ExitCode.VALIDATION_ERROR, "fix")),
    )
    result = runner.invoke(app, ["export", "run", "--out", str(tmp_path)])
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
