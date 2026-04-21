from __future__ import annotations

import json

import pytest

from ksef_client.cli import app
from ksef_client.cli.commands import session_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _payload(stdout: str) -> dict:
    return json.loads(stdout.strip())


def test_session_list_command_uses_selected_profile(runner, monkeypatch) -> None:
    seen: dict[str, str] = {}

    def _fake_list_saved_sessions(*, profile: str):
        seen["profile"] = profile
        return {"count": 1, "items": [{"id": "demo"}]}

    monkeypatch.setattr(session_cmd, "list_saved_sessions", _fake_list_saved_sessions)

    result = runner.invoke(app, ["--json", "session", "list"])

    assert result.exit_code == 0
    assert seen["profile"] == "demo"
    assert _payload(result.stdout)["data"]["count"] == 1


def test_session_online_open_command_resolves_base_url(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_open_online_session(**kwargs):
        seen.update(kwargs)
        return {"id": kwargs["session_id"], "session_ref": "SES-1"}

    monkeypatch.setattr(session_cmd, "open_online_session", _fake_open_online_session)

    result = runner.invoke(
        app,
        [
            "--json",
            "session",
            "online",
            "open",
            "--id",
            "resume-1",
        ],
    )

    assert result.exit_code == 0
    assert seen["profile"] == "demo"
    assert seen["base_url"] == "https://api-demo.ksef.mf.gov.pl"
    assert seen["session_id"] == "resume-1"
    assert _payload(result.stdout)["command"] == "session.online.open"


def test_session_status_command_passes_invoice_ref(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_get_saved_session_status(**kwargs):
        seen.update(kwargs)
        return {"session_ref": "SES-1", "status_code": 200}

    monkeypatch.setattr(session_cmd, "get_saved_session_status", _fake_get_saved_session_status)

    result = runner.invoke(
        app,
        [
            "--json",
            "session",
            "status",
            "--id",
            "resume-1",
            "--invoice-ref",
            "INV-1",
        ],
    )

    assert result.exit_code == 0
    assert seen["session_id"] == "resume-1"
    assert seen["invoice_ref"] == "INV-1"
    assert _payload(result.stdout)["data"]["status_code"] == 200


@pytest.mark.parametrize(
    ("attribute_name", "argv", "command"),
    [
        ("show_saved_session", ["--json", "session", "show", "--id", "resume-1"], "session.show"),
        (
            "export_saved_session",
            ["--json", "session", "export", "--id", "resume-1", "--out", "out.json"],
            "session.export",
        ),
        (
            "import_saved_session",
            ["--json", "session", "import", "--in", "resume.json"],
            "session.import",
        ),
        ("drop_saved_session", ["--json", "session", "drop", "--id", "resume-1"], "session.drop"),
    ],
)
def test_session_commands_render_success_for_general_actions(
    runner, monkeypatch, attribute_name, argv, command
) -> None:
    monkeypatch.setattr(
        session_cmd,
        attribute_name,
        lambda **kwargs: {"id": kwargs.get("session_id", "resume-1"), "ok": True},
    )

    result = runner.invoke(app, argv)

    assert result.exit_code == 0
    payload = _payload(result.stdout)
    assert payload["command"] == command
    assert payload["data"]["ok"] is True


def test_session_batch_close_command_forwards_wait_options(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_close_batch_session(**kwargs):
        seen.update(kwargs)
        return {"id": kwargs["session_id"], "stage": "closed"}

    monkeypatch.setattr(session_cmd, "close_batch_session", _fake_close_batch_session)

    result = runner.invoke(
        app,
        [
            "--json",
            "session",
            "batch",
            "close",
            "--id",
            "batch-1",
            "--wait-status",
            "--wait-upo",
            "--poll-interval",
            "0.5",
            "--max-attempts",
            "5",
            "--save-upo",
            "upo.xml",
        ],
    )

    assert result.exit_code == 0
    assert seen["session_id"] == "batch-1"
    assert seen["wait_status"] is True
    assert seen["wait_upo"] is True
    assert seen["save_upo"] == "upo.xml"
    assert _payload(result.stdout)["command"] == "session.batch.close"


@pytest.mark.parametrize(
    ("attribute_name", "argv", "command"),
    [
        ("list_saved_sessions", ["--json", "session", "list"], "session.list"),
        ("show_saved_session", ["--json", "session", "show", "--id", "resume-1"], "session.show"),
        (
            "get_saved_session_status",
            ["--json", "session", "status", "--id", "resume-1"],
            "session.status",
        ),
        (
            "export_saved_session",
            ["--json", "session", "export", "--id", "resume-1", "--out", "out.json"],
            "session.export",
        ),
        (
            "import_saved_session",
            ["--json", "session", "import", "--in", "resume.json"],
            "session.import",
        ),
        ("drop_saved_session", ["--json", "session", "drop", "--id", "resume-1"], "session.drop"),
        (
            "open_online_session",
            ["--json", "session", "online", "open", "--id", "resume-1"],
            "session.online.open",
        ),
        (
            "send_online_session_invoice",
            [
                "--json",
                "session",
                "online",
                "send",
                "--id",
                "resume-1",
                "--invoice",
                "invoice.xml",
            ],
            "session.online.send",
        ),
        (
            "close_online_session",
            ["--json", "session", "online", "close", "--id", "resume-1"],
            "session.online.close",
        ),
        (
            "open_batch_session",
            ["--json", "session", "batch", "open", "--id", "resume-1", "--zip", "batch.zip"],
            "session.batch.open",
        ),
        (
            "upload_batch_session",
            ["--json", "session", "batch", "upload", "--id", "resume-1"],
            "session.batch.upload",
        ),
        (
            "close_batch_session",
            ["--json", "session", "batch", "close", "--id", "resume-1"],
            "session.batch.close",
        ),
    ],
)
def test_session_commands_render_cli_errors(
    runner, monkeypatch, attribute_name, argv, command
) -> None:
    def _boom(**kwargs):
        _ = kwargs
        raise CliError("broken", ExitCode.VALIDATION_ERROR, "fix-it")

    monkeypatch.setattr(session_cmd, attribute_name, _boom)

    result = runner.invoke(app, argv)

    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
    payload = _payload(result.stdout)
    assert payload["command"] == command
    assert payload["errors"][0]["code"] == ExitCode.VALIDATION_ERROR.name
