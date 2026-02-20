from __future__ import annotations

from ksef_client.cli.app import app
from ksef_client.cli.commands import auth_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def test_auth_login_token_help(runner) -> None:
    result = runner.invoke(app, ["auth", "login-token", "--help"])
    assert result.exit_code == 0


def test_auth_login_token_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        "ksef_client.cli.commands.auth_cmd.login_with_token",
        lambda **kwargs: {"reference_number": "r1", "saved": True},
    )
    result = runner.invoke(
        app,
        [
            "auth",
            "login-token",
            "--ksef-token",
            "token",
            "--context-type",
            "nip",
            "--context-value",
            "5265877635",
        ],
    )
    assert result.exit_code == 0
    assert "Authentication successful." in result.stdout


def test_auth_login_token_uses_env_vars_without_flags(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_login(**kwargs):
        seen.update(kwargs)
        return {"reference_number": "r-env", "saved": True}

    monkeypatch.setattr(auth_cmd, "login_with_token", _fake_login)
    monkeypatch.setenv("KSEF_TOKEN", "env-token")
    monkeypatch.setenv("KSEF_CONTEXT_TYPE", "nip")
    monkeypatch.setenv("KSEF_CONTEXT_VALUE", "5265877635")

    result = runner.invoke(app, ["auth", "login-token"])

    assert result.exit_code == 0
    assert seen["token"] == "env-token"
    assert seen["context_type"] == "nip"
    assert seen["context_value"] == "5265877635"
    assert "Authentication successful." in result.stdout


def test_auth_login_token_validation_error(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        "ksef_client.cli.commands.auth_cmd.login_with_token",
        lambda **kwargs: (_ for _ in ()).throw(
            CliError("missing", ExitCode.VALIDATION_ERROR, "set token")
        ),
    )
    result = runner.invoke(app, ["auth", "login-token"])
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
