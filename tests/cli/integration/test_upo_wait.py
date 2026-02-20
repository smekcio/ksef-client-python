from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import upo_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_upo_wait_help(runner) -> None:
    result = runner.invoke(app, ["upo", "wait", "--help"])
    assert result.exit_code == 0


def test_upo_wait_success(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_wait(**kwargs):
        seen.update(kwargs)
        return {"session_ref": kwargs["session_ref"], "path": "upo.xml", "bytes": 12}

    monkeypatch.setattr(upo_cmd, "wait_for_upo", _fake_wait)

    result = runner.invoke(
        app,
        [
            "upo",
            "wait",
            "--session-ref",
            "SES-1",
            "--invoice-ref",
            "INV-1",
            "--poll-interval",
            "0.1",
            "--max-attempts",
            "3",
            "--out",
            "tmp/upo.xml",
        ],
    )

    assert result.exit_code == 0
    assert seen["invoice_ref"] == "INV-1"
    assert seen["poll_interval"] == 0.1
    assert seen["max_attempts"] == 3


def test_upo_wait_json_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        upo_cmd, "wait_for_upo", lambda **kwargs: {"session_ref": "SES-1", "bytes": 5, "path": ""}
    )

    result = runner.invoke(
        app,
        ["--json", "upo", "wait", "--session-ref", "SES-1", "--batch-auto", "--max-attempts", "1"],
    )

    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "upo.wait"
    assert payload["data"]["session_ref"] == "SES-1"


def test_upo_wait_retry_exhausted_exit_code(runner, monkeypatch) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise CliError("timeout", ExitCode.RETRY_EXHAUSTED, "increase attempts")

    monkeypatch.setattr(upo_cmd, "wait_for_upo", _raise_error)

    result = runner.invoke(app, ["upo", "wait", "--session-ref", "SES-1", "--batch-auto"])

    assert result.exit_code == int(ExitCode.RETRY_EXHAUSTED)
