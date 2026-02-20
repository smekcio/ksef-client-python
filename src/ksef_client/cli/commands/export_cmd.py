from __future__ import annotations

import os

import typer

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError

from ..auth.manager import resolve_base_url
from ..context import profile_label, require_context, require_profile
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer
from ..sdk.adapters import get_export_status, run_export

app = typer.Typer(help="Run and inspect exports.")


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
            hint="Check KSeF response and request parameters.",
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


@app.command("run")
def export_run(
    ctx: typer.Context,
    date_from: str | None = typer.Option(None, "--from", help="Start date (YYYY-MM-DD)."),
    date_to: str | None = typer.Option(None, "--to", help="End date (YYYY-MM-DD)."),
    subject_type: str = typer.Option(
        "Subject1", "--subject-type", help="KSeF subject type filter."
    ),
    poll_interval: float = typer.Option(
        2.0, "--poll-interval", help="Polling interval in seconds."
    ),
    max_attempts: int = typer.Option(120, "--max-attempts", help="Maximum polling attempts."),
    out: str = typer.Option(..., "--out", help="Output directory for exported files and metadata."),
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override KSeF base URL for this command."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = run_export(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            date_from=date_from,
            date_to=date_to,
            subject_type=subject_type,
            poll_interval=poll_interval,
            max_attempts=max_attempts,
            out=out,
        )
    except Exception as exc:
        _render_error(ctx, "export.run", exc)
    renderer.success(command="export.run", profile=profile, data=result)


@app.command("status")
def export_status(
    ctx: typer.Context,
    reference: str = typer.Option(..., "--reference", help="Export reference number."),
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override KSeF base URL for this command."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = get_export_status(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            reference=reference,
        )
    except Exception as exc:
        _render_error(ctx, "export.status", exc)
    renderer.success(command="export.status", profile=profile, data=result)
