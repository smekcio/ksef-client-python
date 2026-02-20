from __future__ import annotations

import pytest
import typer
from click import Command

from ksef_client.cli.commands import (
    auth_cmd,
    export_cmd,
    health_cmd,
    init_cmd,
    invoice_cmd,
    profile_cmd,
    send_cmd,
    upo_cmd,
)
from ksef_client.cli.context import CliContext
from ksef_client.cli.errors import CliError
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError


def _ctx() -> typer.Context:
    ctx = typer.Context(Command("cmd"))
    ctx.obj = CliContext(profile="demo", json_output=True, verbose=0, no_color=True)
    return ctx


@pytest.mark.parametrize(
    ("module", "command"),
    [
        (auth_cmd, "auth.test"),
        (invoice_cmd, "invoice.test"),
        (send_cmd, "send.test"),
        (upo_cmd, "upo.test"),
        (export_cmd, "export.test"),
        (health_cmd, "health.test"),
    ],
)
def test_render_error_cli_error(module, command) -> None:
    with pytest.raises(typer.Exit) as exc:
        module._render_error(_ctx(), command, CliError("bad", ExitCode.VALIDATION_ERROR, "fix"))
    assert exc.value.exit_code == int(ExitCode.VALIDATION_ERROR)


@pytest.mark.parametrize(
    ("module", "command"),
    [
        (auth_cmd, "auth.test"),
        (invoice_cmd, "invoice.test"),
        (send_cmd, "send.test"),
        (upo_cmd, "upo.test"),
        (export_cmd, "export.test"),
        (health_cmd, "health.test"),
    ],
)
def test_render_error_rate_limit(module, command) -> None:
    err = KsefRateLimitError(status_code=429, message="too many", retry_after="2")
    with pytest.raises(typer.Exit) as exc:
        module._render_error(_ctx(), command, err)
    assert exc.value.exit_code == int(ExitCode.RETRY_EXHAUSTED)


def test_auth_render_error_api_and_http() -> None:
    with pytest.raises(typer.Exit) as api_exc:
        auth_cmd._render_error(_ctx(), "auth.test", KsefApiError(status_code=400, message="api"))
    assert api_exc.value.exit_code == int(ExitCode.API_ERROR)

    with pytest.raises(typer.Exit) as http_exc:
        auth_cmd._render_error(_ctx(), "auth.test", KsefHttpError(status_code=500, message="http"))
    assert http_exc.value.exit_code == int(ExitCode.API_ERROR)


@pytest.mark.parametrize(
    "module",
    [invoice_cmd, send_cmd, upo_cmd, export_cmd, health_cmd],
)
def test_render_error_api_http_combined(module) -> None:
    with pytest.raises(typer.Exit) as api_exc:
        module._render_error(_ctx(), "cmd.test", KsefApiError(status_code=400, message="api"))
    assert api_exc.value.exit_code == int(ExitCode.API_ERROR)

    with pytest.raises(typer.Exit) as http_exc:
        module._render_error(_ctx(), "cmd.test", KsefHttpError(status_code=500, message="http"))
    assert http_exc.value.exit_code == int(ExitCode.API_ERROR)


@pytest.mark.parametrize(
    "module",
    [auth_cmd, invoice_cmd, send_cmd, upo_cmd, export_cmd, health_cmd, init_cmd, profile_cmd],
)
def test_render_error_unexpected(module) -> None:
    with pytest.raises(typer.Exit) as exc:
        module._render_error(_ctx(), "cmd.test", RuntimeError("x"))
    assert exc.value.exit_code == int(ExitCode.CONFIG_ERROR)


@pytest.mark.parametrize(
    "module",
    [init_cmd, profile_cmd],
)
def test_render_error_cli_error_for_init_and_profile(module) -> None:
    with pytest.raises(typer.Exit) as exc:
        module._render_error(_ctx(), "cmd.test", CliError("bad", ExitCode.VALIDATION_ERROR, "fix"))
    assert exc.value.exit_code == int(ExitCode.VALIDATION_ERROR)
