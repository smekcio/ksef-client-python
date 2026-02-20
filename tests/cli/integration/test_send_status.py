from __future__ import annotations

import json

import pytest

from ksef_client.cli.app import app
from ksef_client.cli.commands import send_cmd
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError


def _json_output(text: str) -> dict:
    return json.loads(text.strip().splitlines()[-1])


def test_send_status_help(runner) -> None:
    result = runner.invoke(app, ["send", "status", "--help"])
    assert result.exit_code == 0


def test_send_status_success(runner, monkeypatch) -> None:
    seen: dict[str, object] = {}

    def _fake_status(**kwargs):
        seen.update(kwargs)
        return {"session_ref": kwargs["session_ref"], "status_code": 200}

    monkeypatch.setattr(send_cmd, "get_send_status", _fake_status)

    result = runner.invoke(
        app, ["send", "status", "--session-ref", "SES-1", "--invoice-ref", "INV-1"]
    )

    assert result.exit_code == 0
    assert seen["session_ref"] == "SES-1"
    assert seen["invoice_ref"] == "INV-1"


def test_send_status_json_success(runner, monkeypatch) -> None:
    monkeypatch.setattr(
        send_cmd, "get_send_status", lambda **kwargs: {"session_ref": "SES-1", "status_code": 200}
    )

    result = runner.invoke(app, ["--json", "send", "status", "--session-ref", "SES-1"])

    assert result.exit_code == 0
    payload = _json_output(result.stdout)
    assert payload["ok"] is True
    assert payload["command"] == "send.status"
    assert payload["data"]["status_code"] == 200


def test_send_status_auth_error_exit_code(runner, monkeypatch) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise CliError("auth", ExitCode.AUTH_ERROR, "login first")

    monkeypatch.setattr(send_cmd, "get_send_status", _raise_error)

    result = runner.invoke(app, ["send", "status", "--session-ref", "SES-1"])

    assert result.exit_code == int(ExitCode.AUTH_ERROR)


@pytest.mark.parametrize(
    ("error", "expected_exit"),
    [
        (
            KsefRateLimitError(status_code=429, message="too many requests", retry_after="7"),
            ExitCode.RETRY_EXHAUSTED,
        ),
        (KsefApiError(status_code=400, message="bad request"), ExitCode.API_ERROR),
        (KsefHttpError(status_code=503, message="upstream unavailable"), ExitCode.API_ERROR),
    ],
)
def test_send_status_mapped_error_exit_codes(runner, monkeypatch, error, expected_exit) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise error

    monkeypatch.setattr(send_cmd, "get_send_status", _raise_error)

    result = runner.invoke(app, ["send", "status", "--session-ref", "SES-1"])

    assert result.exit_code == int(expected_exit)


def test_send_status_json_rate_limit_error_envelope(runner, monkeypatch) -> None:
    def _raise_error(**kwargs):
        _ = kwargs
        raise KsefRateLimitError(status_code=429, message="too many requests", retry_after="7")

    monkeypatch.setattr(send_cmd, "get_send_status", _raise_error)

    result = runner.invoke(app, ["--json", "send", "status", "--session-ref", "SES-1"])

    assert result.exit_code == int(ExitCode.RETRY_EXHAUSTED)
    payload = _json_output(result.stdout)
    assert payload["ok"] is False
    assert payload["command"] == "send.status"
    assert payload["profile"] == "demo"
    assert payload["data"] is None
    assert payload["errors"][0]["code"] == "RATE_LIMIT"
    assert payload["errors"][0]["message"] == "HTTP 429: too many requests"
    assert payload["errors"][0]["hint"] == "Retry-After: 7"
