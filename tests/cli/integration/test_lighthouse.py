from __future__ import annotations

import json
from pathlib import Path

from ksef_client.cli.app import app
from ksef_client.cli.commands import lighthouse_cmd
from ksef_client.cli.config import paths
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_lighthouse_help(runner) -> None:
    result = runner.invoke(app, ["lighthouse", "--help"])
    assert result.exit_code == 0


def test_lighthouse_status_success(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_status(**kwargs):
        seen.update(kwargs)
        return {"status": "AVAILABLE", "messages": []}

    monkeypatch.setattr(lighthouse_cmd, "get_lighthouse_status", _fake_status)
    result = runner.invoke(
        app,
        [
            "lighthouse",
            "status",
            "--base-url",
            "https://api-latarnia-test.ksef.mf.gov.pl",
        ],
    )
    assert result.exit_code == 0
    assert seen["profile"] == "demo"
    assert seen["lighthouse_base_url"] == "https://api-latarnia-test.ksef.mf.gov.pl"
    assert "lighthouse.status" in result.stdout


def test_lighthouse_messages_json_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        lighthouse_cmd,
        "get_lighthouse_messages",
        lambda **kwargs: {"count": 1, "items": [{"id": "m-1"}]},
    )
    result = runner.invoke(app, ["--json", "lighthouse", "messages"])
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "lighthouse.messages"
    assert payload["data"]["count"] == 1


def test_lighthouse_status_validation_error_exit_code(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        lighthouse_cmd,
        "get_lighthouse_status",
        lambda **kwargs: (_ for _ in ()).throw(
            CliError("bad input", ExitCode.VALIDATION_ERROR, "fix args")
        ),
    )
    result = runner.invoke(app, ["lighthouse", "status"])
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)


def test_lighthouse_status_works_without_active_profile(runner, monkeypatch, tmp_path) -> None:
    _write_unconfigured_config(monkeypatch, tmp_path)
    seen: dict[str, object] = {}

    def _fake_status(**kwargs):
        seen.update(kwargs)
        return {"status": "AVAILABLE", "messages": []}

    monkeypatch.setattr(lighthouse_cmd, "get_lighthouse_status", _fake_status)
    result = runner.invoke(app, ["lighthouse", "status"])
    assert result.exit_code == 0
    assert seen["profile"] == ""
    assert seen["lighthouse_base_url"] == "https://api-latarnia-test.ksef.mf.gov.pl"
    assert "<unconfigured>" in result.stdout


def test_lighthouse_status_without_profile_prefers_env_base_url(
    runner, monkeypatch, tmp_path
) -> None:
    _write_unconfigured_config(monkeypatch, tmp_path)
    seen: dict[str, object] = {}

    def _fake_status(**kwargs):
        seen.update(kwargs)
        return {"status": "AVAILABLE", "messages": []}

    monkeypatch.setattr(lighthouse_cmd, "get_lighthouse_status", _fake_status)
    monkeypatch.setenv("KSEF_LIGHTHOUSE_BASE_URL", "https://api-latarnia.ksef.mf.gov.pl")
    result = runner.invoke(app, ["lighthouse", "status"])
    assert result.exit_code == 0
    assert seen["lighthouse_base_url"] == "https://api-latarnia.ksef.mf.gov.pl"


def _write_unconfigured_config(monkeypatch, tmp_path: Path) -> Path:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        """
{
  "version": 1,
  "active_profile": null,
  "profiles": {}
}
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(paths, "config_file", lambda: config_path)
    return config_path
