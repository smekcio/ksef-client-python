from __future__ import annotations

import os

import typer

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError

from ..auth.manager import resolve_base_url
from ..context import profile_label, require_context, require_profile
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer
from ..sdk.adapters import get_upo, wait_for_upo

app = typer.Typer(help="Download and poll UPO.")


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
            hint="Check KSeF response and provided references.",
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


@app.command("get")
def upo_get(
    ctx: typer.Context,
    session_ref: str = typer.Option(..., "--session-ref", help="Session reference number."),
    invoice_ref: str | None = typer.Option(
        None, "--invoice-ref", help="Invoice reference within session."
    ),
    ksef_number: str | None = typer.Option(None, "--ksef-number", help="KSeF invoice number."),
    upo_ref: str | None = typer.Option(None, "--upo-ref", help="Batch UPO reference number."),
    out: str = typer.Option(..., "--out", help="Target output path (file or directory)."),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Overwrite output file if it already exists."
    ),
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override KSeF base URL for this command."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = get_upo(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            session_ref=session_ref,
            invoice_ref=invoice_ref,
            ksef_number=ksef_number,
            upo_ref=upo_ref,
            out=out,
            overwrite=overwrite,
        )
    except Exception as exc:
        _render_error(ctx, "upo.get", exc)
    renderer.success(
        command="upo.get",
        profile=profile,
        data=result,
    )


@app.command("wait")
def upo_wait(
    ctx: typer.Context,
    session_ref: str = typer.Option(..., "--session-ref", help="Session reference number."),
    invoice_ref: str | None = typer.Option(
        None, "--invoice-ref", help="Wait for UPO of one invoice reference."
    ),
    upo_ref: str | None = typer.Option(
        None, "--upo-ref", help="Wait for a known batch UPO reference."
    ),
    batch_auto: bool = typer.Option(
        False, "--batch-auto", help="Auto-discover batch UPO reference from session."
    ),
    poll_interval: float = typer.Option(
        2.0, "--poll-interval", help="Polling interval in seconds."
    ),
    max_attempts: int = typer.Option(60, "--max-attempts", help="Maximum polling attempts."),
    out: str | None = typer.Option(None, "--out", help="Optional output path to save UPO content."),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Overwrite output file if it already exists."
    ),
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override KSeF base URL for this command."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = wait_for_upo(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            session_ref=session_ref,
            invoice_ref=invoice_ref,
            upo_ref=upo_ref,
            batch_auto=batch_auto,
            poll_interval=poll_interval,
            max_attempts=max_attempts,
            out=out,
            overwrite=overwrite,
        )
    except Exception as exc:
        _render_error(ctx, "upo.wait", exc)
    renderer.success(
        command="upo.wait",
        profile=profile,
        data=result,
    )
