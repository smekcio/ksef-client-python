from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import send_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_send_online_help(runner) -> None:
    result = runner.invoke(app, ["send", "online", "--help"])
    assert result.exit_code == 0


def test_send_online_success(runner, monkeypatch, tmp_path) -> None:
    seen: dict[str, object] = {}

    def _fake_send(**kwargs):
        seen.update(kwargs)
        return {"session_ref": "SES-1", "invoice_ref": "INV-1"}

    monkeypatch.setattr(send_cmd, "send_online_invoice", _fake_send)

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<f/>", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "send",
            "online",
            "--invoice",
            str(invoice_path),
            "--wait-status",
            "--wait-upo",
            "--poll-interval",
            "0.1",
            "--max-attempts",
            "4",
            "--save-upo",
            str(tmp_path / "upo.xml"),
        ],
    )

    assert result.exit_code == 0
    assert seen["wait_status"] is True
    assert seen["wait_upo"] is True
    assert seen["max_attempts"] == 4
    assert seen["save_upo_overwrite"] is False


def test_send_online_save_upo_overwrite_flag(runner, monkeypatch, tmp_path) -> None:
    seen: dict[str, object] = {}

    def _fake_send(**kwargs):
        seen.update(kwargs)
        return {"session_ref": "SES-1", "invoice_ref": "INV-1"}

    monkeypatch.setattr(send_cmd, "send_online_invoice", _fake_send)

    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<f/>", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "send",
            "online",
            "--invoice",
            str(invoice_path),
            "--wait-upo",
            "--save-upo",
            str(tmp_path / "upo.xml"),
            "--save-upo-overwrite",
        ],
    )

    assert result.exit_code == 0
    assert seen["save_upo_overwrite"] is True


def test_send_online_json_success(runner, monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        send_cmd,
        "send_online_invoice",
        lambda **kwargs: {"session_ref": "SES-1", "invoice_ref": "INV-1"},
    )
    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<f/>", encoding="utf-8")

    result = runner.invoke(app, ["--json", "send", "online", "--invoice", str(invoice_path)])

    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "send.online"
    assert payload["data"]["session_ref"] == "SES-1"


def test_send_online_validation_error_exit_code(runner, monkeypatch, tmp_path) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise CliError("bad input", ExitCode.VALIDATION_ERROR, "fix args")

    monkeypatch.setattr(send_cmd, "send_online_invoice", _raise_error)
    invoice_path = tmp_path / "invoice.xml"
    invoice_path.write_text("<f/>", encoding="utf-8")

    result = runner.invoke(app, ["send", "online", "--invoice", str(invoice_path)])

    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
