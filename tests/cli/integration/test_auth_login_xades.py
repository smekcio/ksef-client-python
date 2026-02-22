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


def test_auth_login_xades_warns_for_cli_pkcs12_password(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        auth_cmd,
        "login_with_xades",
        lambda **kwargs: {"reference_number": "x-p12", "saved": True},
    )
    result = runner.invoke(
        app,
        [
            "auth",
            "login-xades",
            "--pkcs12-path",
            "cert.p12",
            "--pkcs12-password",
            "secret-pass",
            "--context-type",
            "nip",
            "--context-value",
            "5265877635",
        ],
    )
    assert result.exit_code == 0
    assert "WARNING: Secret provided via --pkcs12-password." in result.stdout
    assert "secret-pass" not in result.stdout


def test_auth_login_xades_warns_for_cli_key_password(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        auth_cmd,
        "login_with_xades",
        lambda **kwargs: {"reference_number": "x-key", "saved": True},
    )
    result = runner.invoke(
        app,
        [
            "auth",
            "login-xades",
            "--cert-pem",
            "cert.pem",
            "--key-pem",
            "key.pem",
            "--key-password",
            "secret-key",
            "--context-type",
            "nip",
            "--context-value",
            "5265877635",
        ],
    )
    assert result.exit_code == 0
    assert "WARNING: Secret provided via --key-password." in result.stdout
    assert "secret-key" not in result.stdout


def test_auth_login_xades_prompts_pkcs12_password_when_interactive(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_login(**kwargs):
        seen.update(kwargs)
        return {"reference_number": "x-prompt", "saved": True}

    monkeypatch.setattr(auth_cmd, "login_with_xades", _fake_login)
    monkeypatch.setattr(auth_cmd, "_is_interactive_terminal", lambda: True)

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
        input="prompt-pass\n",
    )
    assert result.exit_code == 0
    assert seen["pkcs12_password"] == "prompt-pass"
    assert "WARNING: Secret provided via --pkcs12-password." not in result.stdout
    assert "prompt-pass" not in result.stdout
    assert "PKCS#12 password (leave empty if not set):" in result.stdout


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
