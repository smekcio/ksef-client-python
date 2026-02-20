from __future__ import annotations

from ksef_client.cli.app import app
from ksef_client.cli.auth.keyring_store import clear_tokens
from ksef_client.cli.commands import auth_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def test_auth_status_and_logout_success(runner) -> None:
    assert runner.invoke(app, ["auth", "status"]).exit_code == 0
    assert runner.invoke(app, ["auth", "logout"]).exit_code == 0


def test_auth_refresh_error_without_tokens(runner) -> None:
    clear_tokens("demo")
    result = runner.invoke(app, ["auth", "refresh"])
    assert result.exit_code == int(ExitCode.AUTH_ERROR)


def test_auth_refresh_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        auth_cmd,
        "refresh_access_token",
        lambda **kwargs: {"profile": "demo", "access_valid_until": "later", "saved": True},
    )
    result = runner.invoke(app, ["auth", "refresh"])
    assert result.exit_code == 0


def test_auth_status_refresh_logout_error_paths(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        auth_cmd,
        "get_auth_status",
        lambda profile: (_ for _ in ()).throw(CliError("x", ExitCode.API_ERROR)),
    )
    monkeypatch.setattr(
        auth_cmd,
        "refresh_access_token",
        lambda **kwargs: (_ for _ in ()).throw(CliError("x", ExitCode.API_ERROR)),
    )
    monkeypatch.setattr(
        auth_cmd, "logout", lambda profile: (_ for _ in ()).throw(CliError("x", ExitCode.API_ERROR))
    )

    assert runner.invoke(app, ["auth", "status"]).exit_code == int(ExitCode.API_ERROR)
    assert runner.invoke(app, ["auth", "refresh"]).exit_code == int(ExitCode.API_ERROR)
    assert runner.invoke(app, ["auth", "logout"]).exit_code == int(ExitCode.API_ERROR)
