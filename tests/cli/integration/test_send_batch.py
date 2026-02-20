from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import send_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_send_batch_help(runner) -> None:
    result = runner.invoke(app, ["send", "batch", "--help"])
    assert result.exit_code == 0


def test_send_batch_success(runner, monkeypatch, tmp_path) -> None:
    seen: dict[str, object] = {}

    def _fake_send(**kwargs):
        seen.update(kwargs)
        return {"session_ref": "BATCH-1"}

    monkeypatch.setattr(send_cmd, "send_batch_invoices", _fake_send)
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()

    result = runner.invoke(
        app,
        [
            "send",
            "batch",
            "--dir",
            str(batch_dir),
            "--parallelism",
            "2",
            "--wait-status",
            "--max-attempts",
            "5",
        ],
    )

    assert result.exit_code == 0
    assert seen["directory"] == str(batch_dir)
    assert seen["parallelism"] == 2
    assert seen["wait_status"] is True
    assert seen["save_upo_overwrite"] is False


def test_send_batch_save_upo_overwrite_flag(runner, monkeypatch, tmp_path) -> None:
    seen: dict[str, object] = {}

    def _fake_send(**kwargs):
        seen.update(kwargs)
        return {"session_ref": "BATCH-1"}

    monkeypatch.setattr(send_cmd, "send_batch_invoices", _fake_send)
    batch_dir = tmp_path / "batch"
    batch_dir.mkdir()

    result = runner.invoke(
        app,
        [
            "send",
            "batch",
            "--dir",
            str(batch_dir),
            "--wait-upo",
            "--save-upo",
            str(tmp_path / "upo.xml"),
            "--save-upo-overwrite",
        ],
    )

    assert result.exit_code == 0
    assert seen["save_upo_overwrite"] is True


def test_send_batch_json_success(runner, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        send_cmd, "send_batch_invoices", lambda **kwargs: {"session_ref": "BATCH-2"}
    )
    zip_path = tmp_path / "batch.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    result = runner.invoke(app, ["--json", "send", "batch", "--zip", str(zip_path)])

    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "send.batch"
    assert payload["data"]["session_ref"] == "BATCH-2"


def test_send_batch_validation_error_exit_code(runner, monkeypatch, tmp_path) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise CliError("bad input", ExitCode.VALIDATION_ERROR, "use --zip or --dir")

    monkeypatch.setattr(send_cmd, "send_batch_invoices", _raise_error)
    zip_path = tmp_path / "batch.zip"
    zip_path.write_bytes(b"PK\x03\x04")

    result = runner.invoke(app, ["send", "batch", "--zip", str(zip_path)])

    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
