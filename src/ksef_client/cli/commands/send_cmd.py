from __future__ import annotations

import os

import typer

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError

from ..auth.manager import resolve_base_url
from ..context import profile_label, require_context, require_profile
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer
from ..sdk.adapters import get_send_status, send_batch_invoices, send_online_invoice

app = typer.Typer(help="Send invoices in online and batch modes.")


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


@app.command("online")
def send_online(
    ctx: typer.Context,
    invoice: str = typer.Option(..., "--invoice", help="Path to invoice XML file."),
    system_code: str = typer.Option("FA (3)", "--system-code", help="Form code systemCode."),
    schema_version: str = typer.Option("1-0E", "--schema-version", help="Form code schemaVersion."),
    form_value: str = typer.Option("FA", "--form-value", help="Form code value."),
    upo_v43: bool = typer.Option(False, "--upo-v43", help="Request UPO v4.3 format."),
    wait_status: bool = typer.Option(
        False, "--wait-status", help="Wait until invoice processing status is final."
    ),
    wait_upo: bool = typer.Option(False, "--wait-upo", help="Wait until UPO becomes available."),
    poll_interval: float = typer.Option(
        2.0, "--poll-interval", help="Polling interval in seconds."
    ),
    max_attempts: int = typer.Option(60, "--max-attempts", help="Maximum polling attempts."),
    save_upo: str | None = typer.Option(
        None,
        "--save-upo",
        help="Save UPO to this path (requires --wait-upo).",
    ),
    save_upo_overwrite: bool = typer.Option(
        False,
        "--save-upo-overwrite",
        help="Overwrite file specified by --save-upo when it already exists.",
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
        result = send_online_invoice(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            invoice=invoice,
            system_code=system_code,
            schema_version=schema_version,
            form_value=form_value,
            upo_v43=upo_v43,
            wait_status=wait_status,
            wait_upo=wait_upo,
            poll_interval=poll_interval,
            max_attempts=max_attempts,
            save_upo=save_upo,
            save_upo_overwrite=save_upo_overwrite,
        )
    except Exception as exc:
        _render_error(ctx, "send.online", exc)
    renderer.success(command="send.online", profile=profile, data=result)


@app.command("batch")
def send_batch(
    ctx: typer.Context,
    zip_path: str | None = typer.Option(None, "--zip", help="Path to input ZIP with invoices."),
    directory: str | None = typer.Option(
        None, "--dir", help="Directory with XML files to ZIP and upload."
    ),
    system_code: str = typer.Option("FA (3)", "--system-code", help="Form code systemCode."),
    schema_version: str = typer.Option("1-0E", "--schema-version", help="Form code schemaVersion."),
    form_value: str = typer.Option("FA", "--form-value", help="Form code value."),
    parallelism: int = typer.Option(4, "--parallelism", help="Parallel upload worker count."),
    upo_v43: bool = typer.Option(False, "--upo-v43", help="Request UPO v4.3 format."),
    wait_status: bool = typer.Option(
        False, "--wait-status", help="Wait until batch session status is final."
    ),
    wait_upo: bool = typer.Option(
        False, "--wait-upo", help="Wait until batch UPO becomes available."
    ),
    poll_interval: float = typer.Option(
        2.0, "--poll-interval", help="Polling interval in seconds."
    ),
    max_attempts: int = typer.Option(120, "--max-attempts", help="Maximum polling attempts."),
    save_upo: str | None = typer.Option(
        None,
        "--save-upo",
        help="Save UPO to this path (requires --wait-upo).",
    ),
    save_upo_overwrite: bool = typer.Option(
        False,
        "--save-upo-overwrite",
        help="Overwrite file specified by --save-upo when it already exists.",
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
        result = send_batch_invoices(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            zip_path=zip_path,
            directory=directory,
            system_code=system_code,
            schema_version=schema_version,
            form_value=form_value,
            parallelism=parallelism,
            upo_v43=upo_v43,
            wait_status=wait_status,
            wait_upo=wait_upo,
            poll_interval=poll_interval,
            max_attempts=max_attempts,
            save_upo=save_upo,
            save_upo_overwrite=save_upo_overwrite,
        )
    except Exception as exc:
        _render_error(ctx, "send.batch", exc)
    renderer.success(command="send.batch", profile=profile, data=result)


@app.command("status")
def send_status(
    ctx: typer.Context,
    session_ref: str = typer.Option(..., "--session-ref", help="Session reference number."),
    invoice_ref: str | None = typer.Option(
        None, "--invoice-ref", help="Invoice reference within session."
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
        result = get_send_status(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            session_ref=session_ref,
            invoice_ref=invoice_ref,
        )
    except Exception as exc:
        _render_error(ctx, "send.status", exc)
    renderer.success(command="send.status", profile=profile, data=result)
