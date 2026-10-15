from __future__ import annotations

import json

from ksef_client import models as m
from ksef_client.cli import app
from ksef_client.cli.auth import keyring_store, manager
from ksef_client.cli.auth.keyring_store import clear_tokens
from ksef_client.cli.commands import auth_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.cli.sdk import factory
from ksef_client.exceptions import KsefApiError


def test_auth_status_and_logout_success(runner) -> None:
    assert runner.invoke(app, ["auth", "status"]).exit_code == 0
    assert runner.invoke(app, ["auth", "logout"]).exit_code == 0


def test_auth_logout_does_not_claim_success_when_the_keyring_blocks_verification(
    runner, monkeypatch, tmp_path
) -> None:
    """`auth logout` nie może raportować `logged_out` bez potwierdzenia usunięcia.

    Keyring, który rzuca zarówno na `delete_password`, jak i na `get_password`,
    nie pozwala stwierdzić, czy ważny refresh token nadal tam jest — wcześniej
    CLI kończyło takie wylogowanie kodem 0 i `data={"logged_out": true}`.
    """

    class _BrokenKeyring:
        def set_password(self, service: str, key: str, value: str) -> None:
            _ = (service, key, value)
            raise keyring_store.KeyringErrorType("brak backendu")

        def get_password(self, service: str, key: str) -> str | None:
            _ = (service, key)
            raise keyring_store.KeyringErrorType("brak backendu")

        def delete_password(self, service: str, key: str) -> None:
            _ = (service, key)
            raise keyring_store.KeyringErrorType("brak backendu")

    monkeypatch.setattr(keyring_store, "_KEYRING_AVAILABLE", True)
    monkeypatch.setattr(keyring_store, "_keyring", _BrokenKeyring())
    monkeypatch.setattr(keyring_store, "cache_dir", lambda: tmp_path)

    result = runner.invoke(app, ["--json", "auth", "logout"])

    assert result.exit_code == int(ExitCode.CONFIG_ERROR)
    payload = json.loads(result.stdout)
    assert payload["ok"] is False
    assert payload["errors"][0]["code"] == "CONFIG_ERROR"
    assert payload["data"] is None


def test_auth_revoke_self_token_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        auth_cmd,
        "revoke_self_token",
        lambda **kwargs: {"profile": "demo", "reference_number": "REF-123", "revoked": True},
    )
    result = runner.invoke(app, ["auth", "revoke-self-token"])
    assert result.exit_code == 0


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


def test_auth_refresh_uses_problem_details_header_for_rich_error_hint(runner, monkeypatch) -> None:
    seen_headers: list[dict[str, str] | None] = []

    class _FakeKsefClient:
        def __init__(self, options, access_token=None) -> None:
            _ = access_token
            seen_headers.append(options.custom_headers)
            self.auth = type(
                "_FakeAuthClient",
                (),
                {
                    "refresh_access_token": staticmethod(
                        lambda refresh_token: (_ for _ in ()).throw(
                            KsefApiError(
                                status_code=400,
                                message="API error",
                                problem=m.BadRequestProblemDetails(
                                    detail="Request is invalid.",
                                    errors=[
                                        m.ApiError(
                                            code=21405,
                                            description="Validation error.",
                                            details=["Field X is required."],
                                        )
                                    ],
                                    instance="/auth/refresh",
                                    status=400,
                                    timestamp="2026-04-13T10:00:00Z",
                                    title="Bad Request",
                                    trace_id="trace-400",
                                ),
                            )
                        )
                    )
                },
            )()

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            _ = (exc_type, exc, tb)

    monkeypatch.setattr(manager, "get_tokens", lambda profile: ("acc", "ref"))
    monkeypatch.setattr(factory, "KsefClient", _FakeKsefClient)

    result = runner.invoke(app, ["--json", "auth", "refresh", "--no-save"])

    assert result.exit_code == int(ExitCode.API_ERROR)
    assert seen_headers == [{"X-Error-Format": "problem-details"}]
    payload = json.loads(result.stdout)
    assert payload["errors"][0]["code"] == "API_ERROR"
    assert "Detail: Request is invalid." in payload["errors"][0]["hint"]
    assert "Trace ID: trace-400" in payload["errors"][0]["hint"]


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
    monkeypatch.setattr(
        auth_cmd,
        "revoke_self_token",
        lambda **kwargs: (_ for _ in ()).throw(CliError("x", ExitCode.API_ERROR)),
    )

    assert runner.invoke(app, ["auth", "status"]).exit_code == int(ExitCode.API_ERROR)
    assert runner.invoke(app, ["auth", "refresh"]).exit_code == int(ExitCode.API_ERROR)
    assert runner.invoke(app, ["auth", "logout"]).exit_code == int(ExitCode.API_ERROR)
    assert runner.invoke(app, ["auth", "revoke-self-token"]).exit_code == int(ExitCode.API_ERROR)
