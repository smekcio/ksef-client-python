from __future__ import annotations

import json

from ksef_client.cli import app
from ksef_client.cli.commands import session_cmd


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
