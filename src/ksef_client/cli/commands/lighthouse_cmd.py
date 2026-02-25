from __future__ import annotations

import os

import typer

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError

from ..auth.manager import resolve_base_url, resolve_lighthouse_base_url
from ..context import profile_label, require_context
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer
from ..sdk.adapters import get_lighthouse_messages, get_lighthouse_status

app = typer.Typer(help="Read public KSeF Lighthouse status and messages.")


def _render_error(ctx: typer.Context, command: str, exc: Exception) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)

    if isinstance(exc, CliError):
        renderer.error(
            command=command,
            profile=profile_label(cli_ctx),
            code=exc.code.name,
            message=exc.message,
            hint=exc.hint,
        )
        raise typer.Exit(int(exc.code))

    if isinstance(exc, KsefRateLimitError):
        hint = f"Retry-After: {exc.retry_after}" if exc.retry_after else "Wait and retry."
        renderer.error(
            command=command,
            profile=profile_label(cli_ctx),
            code="RATE_LIMIT",
            message=str(exc),
            hint=hint,
        )
        raise typer.Exit(int(ExitCode.RETRY_EXHAUSTED))

    if isinstance(exc, (KsefApiError, KsefHttpError)):
        renderer.error(
            command=command,
            profile=profile_label(cli_ctx),
            code="API_ERROR",
            message=str(exc),
            hint="Check Lighthouse response and request parameters.",
        )
        raise typer.Exit(int(ExitCode.API_ERROR))

    renderer.error(
        command=command,
        profile=profile_label(cli_ctx),
        code="UNEXPECTED",
        message=str(exc),
        hint="Run with -v and inspect logs.",
    )
    raise typer.Exit(int(ExitCode.CONFIG_ERROR))


@app.command("status")
def lighthouse_status(
    ctx: typer.Context,
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override Lighthouse base URL for this command."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    selected_profile = cli_ctx.profile
    try:
        result = get_lighthouse_status(
            profile=selected_profile or "",
            base_url=resolve_base_url(os.getenv("KSEF_BASE_URL"), profile=selected_profile),
            lighthouse_base_url=resolve_lighthouse_base_url(
                base_url or os.getenv("KSEF_LIGHTHOUSE_BASE_URL"),
                profile=selected_profile,
            ),
        )
    except Exception as exc:
        _render_error(ctx, "lighthouse.status", exc)
    renderer.success(command="lighthouse.status", profile=profile, data=result)


@app.command("messages")
def lighthouse_messages(
    ctx: typer.Context,
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override Lighthouse base URL for this command."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    selected_profile = cli_ctx.profile
    try:
        result = get_lighthouse_messages(
            profile=selected_profile or "",
            base_url=resolve_base_url(os.getenv("KSEF_BASE_URL"), profile=selected_profile),
            lighthouse_base_url=resolve_lighthouse_base_url(
                base_url or os.getenv("KSEF_LIGHTHOUSE_BASE_URL"),
                profile=selected_profile,
            ),
        )
    except Exception as exc:
        _render_error(ctx, "lighthouse.messages", exc)
    renderer.success(command="lighthouse.messages", profile=profile, data=result)
