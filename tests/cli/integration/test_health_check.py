from __future__ import annotations

import json

from ksef_client.cli.app import app
from ksef_client.cli.commands import health_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_health_help(runner) -> None:
    result = runner.invoke(app, ["health", "check", "--help"])
    assert result.exit_code == 0


def test_health_check_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        health_cmd,
        "run_health_check",
        lambda **kwargs: {"overall": "PASS", "checks": [{"name": "base_url", "status": "PASS"}]},
    )
    result = runner.invoke(app, ["health", "check", "--dry-run", "--check-certs"])
    assert result.exit_code == 0


def test_health_check_json_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        health_cmd, "run_health_check", lambda **kwargs: {"overall": "WARN", "checks": []}
    )
    result = runner.invoke(app, ["--json", "health", "check"])
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "health.check"


def test_health_check_error_exit(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        health_cmd,
        "run_health_check",
        lambda **kwargs: (_ for _ in ()).throw(CliError("auth", ExitCode.AUTH_ERROR, "login")),
    )
    result = runner.invoke(app, ["health", "check", "--check-auth"])
    assert result.exit_code == int(ExitCode.AUTH_ERROR)


def test_health_check_json_includes_token_store_mode(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        health_cmd,
        "run_health_check",
        lambda **kwargs: {"overall": "PASS", "checks": [{"name": "base_url", "status": "PASS"}]},
    )
    monkeypatch.setattr(health_cmd, "get_token_store_mode", lambda: "plaintext-fallback")

    result = runner.invoke(app, ["--json", "health", "check"])
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    token_store_checks = [c for c in payload["data"]["checks"] if c["name"] == "token_store"]
    assert token_store_checks == [
        {"name": "token_store", "status": "WARN", "message": "plaintext-fallback"}
    ]


def test_health_check_does_not_duplicate_existing_token_store_check(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        health_cmd,
        "run_health_check",
        lambda **kwargs: {
            "overall": "PASS",
            "checks": [{"name": "token_store", "status": "PASS", "message": "keyring"}],
        },
    )
    monkeypatch.setattr(health_cmd, "get_token_store_mode", lambda: "plaintext-fallback")

    result = runner.invoke(app, ["--json", "health", "check"])
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    token_store_checks = [c for c in payload["data"]["checks"] if c["name"] == "token_store"]
    assert token_store_checks == [{"name": "token_store", "status": "PASS", "message": "keyring"}]


def test_health_check_replaces_non_list_checks_with_token_store_check(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        health_cmd,
        "run_health_check",
        lambda **kwargs: {"overall": "PASS", "checks": {"name": "base_url", "status": "PASS"}},
    )
    monkeypatch.setattr(health_cmd, "get_token_store_mode", lambda: "keyring")

    result = runner.invoke(app, ["--json", "health", "check"])
    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["data"]["checks"] == [
        {"name": "token_store", "status": "PASS", "message": "keyring"}
    ]
