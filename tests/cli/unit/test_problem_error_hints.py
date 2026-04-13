from __future__ import annotations

from types import SimpleNamespace

import pytest
import typer
from click import Command

from ksef_client import models as m
from ksef_client.cli.commands import (
    auth_cmd,
    export_cmd,
    health_cmd,
    invoice_cmd,
    send_cmd,
    upo_cmd,
)
from ksef_client.cli.commands._error_utils import build_problem_hint
from ksef_client.cli.context import CliContext
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.exceptions import KsefApiError, KsefRateLimitError


class _RecordingRenderer:
    def __init__(self) -> None:
        self.last_error: dict[str, str | None] | None = None

    def info(self, message: str, *, command: str | None = None) -> None:
        _ = (message, command)

    def success(
        self,
        *,
        command: str,
        profile: str,
        data: dict | None = None,
        message: str | None = None,
    ) -> None:
        _ = (command, profile, data, message)

    def error(
        self,
        *,
        command: str,
        profile: str,
        code: str,
        message: str,
        hint: str | None = None,
    ) -> None:
        self.last_error = {
            "command": command,
            "profile": profile,
            "code": code,
            "message": message,
            "hint": hint,
        }


def _ctx() -> typer.Context:
    ctx = typer.Context(Command("cmd"))
    ctx.obj = CliContext(profile="demo", json_output=True, verbose=0, no_color=True)
    return ctx


@pytest.mark.parametrize(
    "module",
    [auth_cmd, invoice_cmd, send_cmd, upo_cmd, export_cmd, health_cmd],
)
def test_render_error_problem_details_hint_includes_structured_fields(module, monkeypatch) -> None:
    renderer = _RecordingRenderer()
    monkeypatch.setattr(module, "get_renderer", lambda _cli_ctx: renderer)

    problem = m.BadRequestProblemDetails(
        detail="Request is invalid.",
        errors=[
            m.ApiError(
                code=21405,
                description="Validation error.",
                details=["Field X is required."],
            )
        ],
        instance="/tokens",
        status=400,
        timestamp="2026-04-13T10:00:00Z",
        title="Bad Request",
        trace_id="trace-400",
    )
    error = KsefApiError(status_code=400, message="api", problem=problem)

    with pytest.raises(typer.Exit) as exc:
        module._render_error(_ctx(), "cmd.test", error)

    assert exc.value.exit_code == int(ExitCode.API_ERROR)
    assert renderer.last_error is not None
    hint = renderer.last_error["hint"]
    assert hint is not None
    assert "Detail: Request is invalid." in hint
    assert "Errors: 21405 - Validation error. - Field X is required." in hint
    assert "Trace ID: trace-400" in hint
    assert "Instance: /tokens" in hint


@pytest.mark.parametrize(
    "module",
    [auth_cmd, invoice_cmd, send_cmd, upo_cmd, export_cmd, health_cmd],
)
def test_render_error_rate_limit_problem_hint_includes_detail_and_retry_after(
    module, monkeypatch
) -> None:
    renderer = _RecordingRenderer()
    monkeypatch.setattr(module, "get_renderer", lambda _cli_ctx: renderer)

    problem = m.TooManyRequestsProblemDetails(
        detail="Retry later.",
        instance="/invoices/exports",
        status=429,
        timestamp="2026-04-13T10:00:00Z",
        title="Too Many Requests",
        trace_id="trace-429",
    )
    error = KsefRateLimitError(
        status_code=429,
        message="too many",
        problem=problem,
        retry_after=5,
        retry_after_raw="5",
    )

    with pytest.raises(typer.Exit) as exc:
        module._render_error(_ctx(), "cmd.test", error)

    assert exc.value.exit_code == int(ExitCode.RETRY_EXHAUSTED)
    assert renderer.last_error is not None
    hint = renderer.last_error["hint"]
    assert hint is not None
    assert "Detail: Retry later." in hint
    assert "Trace ID: trace-429" in hint
    assert "Retry-After: 5" in hint


def test_build_problem_hint_reads_reason_code_from_raw_payload() -> None:
    problem = SimpleNamespace(
        detail="Missing permissions",
        reason_code=None,
        errors=None,
        trace_id=None,
        instance=None,
        raw={"reasonCode": "missing-permissions"},
    )

    hint = build_problem_hint(problem, default_hint="Check request.")

    assert hint is not None
    assert "Detail: Missing permissions" in hint
    assert "Reason: missing-permissions" in hint
    assert hint.endswith("Check request.")


def test_build_problem_hint_ignores_unrenderable_error_items() -> None:
    problem = SimpleNamespace(
        detail=None,
        reason_code=None,
        errors=[SimpleNamespace(code=None, description=None, details=None)],
        trace_id=None,
        instance=None,
        raw=None,
    )

    assert build_problem_hint(problem, default_hint=None) is None
