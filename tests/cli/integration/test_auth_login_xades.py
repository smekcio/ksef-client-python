from __future__ import annotations

from ksef_client.cli.app import app
from ksef_client.cli.commands import auth_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode


def test_auth_login_xades_help(runner) -> None:
    result = runner.invoke(app, ["auth", "login-xades", "--help"])
    assert result.exit_code == 0


def test_auth_login_xades_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        auth_cmd,
        "login_with_xades",
        lambda **kwargs: {"reference_number": "x1", "saved": True},
    )
    result = runner.invoke(
        app,
        [
            "auth",
            "login-xades",
            "--pkcs12-path",
            "cert.p12",
            "--context-type",
            "nip",
            "--context-value",
            "5265877635",
        ],
    )
    assert result.exit_code == 0
    assert "Authentication successful." in result.stdout


def test_auth_login_xades_validation_error(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        auth_cmd,
        "login_with_xades",
        lambda **kwargs: (_ for _ in ()).throw(
            CliError("invalid", ExitCode.VALIDATION_ERROR, "fix")
        ),
    )
    result = runner.invoke(app, ["auth", "login-xades"])
    assert result.exit_code == int(ExitCode.VALIDATION_ERROR)
