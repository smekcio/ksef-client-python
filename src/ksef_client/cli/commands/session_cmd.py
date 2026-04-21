from __future__ import annotations

import os

import typer

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError

from ..auth.manager import resolve_base_url
from ..context import profile_label, require_context, require_profile
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer
from ..sdk.session_ops import (
    close_batch_session,
    close_online_session,
    drop_saved_session,
    export_saved_session,
    get_saved_session_status,
    import_saved_session,
    list_saved_sessions,
    open_batch_session,
    open_online_session,
    send_online_session_invoice,
    show_saved_session,
    upload_batch_session,
)
from ._error_utils import build_api_error_hint, build_rate_limit_hint

app = typer.Typer(help="Manage resumable online and batch sessions.")
online_app = typer.Typer(help="Manage resumable online sessions.")
batch_app = typer.Typer(help="Manage resumable batch sessions.")


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
        hint = build_rate_limit_hint(exc, default_hint="Wait and retry.")
        renderer.error(
            command=command,
            profile=profile_label(cli_ctx),
            code="RATE_LIMIT",
            message=str(exc),
            hint=hint,
        )
        raise typer.Exit(int(ExitCode.RETRY_EXHAUSTED))

    if isinstance(exc, (KsefApiError, KsefHttpError)):
        hint = (
            build_api_error_hint(exc, default_hint="Check KSeF response and request parameters.")
            if isinstance(exc, KsefApiError)
            else "Check KSeF response and request parameters."
        )
        renderer.error(
            command=command,
            profile=profile_label(cli_ctx),
            code="API_ERROR",
            message=str(exc),
            hint=hint,
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


@app.command("list")
def session_list(ctx: typer.Context) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = list_saved_sessions(profile=profile)
    except Exception as exc:
        _render_error(ctx, "session.list", exc)
    renderer.success(command="session.list", profile=profile, data=result)


@app.command("show")
def session_show(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = show_saved_session(profile=profile, session_id=session_id)
    except Exception as exc:
        _render_error(ctx, "session.show", exc)
    renderer.success(command="session.show", profile=profile, data=result)


@app.command("status")
def session_status(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
    invoice_ref: str | None = typer.Option(
        None, "--invoice-ref", help="Invoice reference for online-session invoice status."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = get_saved_session_status(
            profile=profile,
            session_id=session_id,
            invoice_ref=invoice_ref,
        )
    except Exception as exc:
        _render_error(ctx, "session.status", exc)
    renderer.success(command="session.status", profile=profile, data=result)


@app.command("export")
def session_export(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
    out: str = typer.Option(..., "--out", help="Destination JSON path or directory."),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = export_saved_session(profile=profile, session_id=session_id, out=out)
    except Exception as exc:
        _render_error(ctx, "session.export", exc)
    renderer.success(command="session.export", profile=profile, data=result)


@app.command("import")
def session_import(
    ctx: typer.Context,
    source_path: str = typer.Option(..., "--in", help="Checkpoint JSON file to import."),
    session_id: str | None = typer.Option(None, "--id", help="Override imported session id."),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = import_saved_session(
            profile=profile,
            source_path=source_path,
            session_id=session_id,
        )
    except Exception as exc:
        _render_error(ctx, "session.import", exc)
    renderer.success(command="session.import", profile=profile, data=result)


@app.command("drop")
def session_drop(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = drop_saved_session(profile=profile, session_id=session_id)
    except Exception as exc:
        _render_error(ctx, "session.drop", exc)
    renderer.success(command="session.drop", profile=profile, data=result)


@online_app.command("open")
def session_online_open(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
    system_code: str = typer.Option("FA (3)", "--system-code", help="Form code systemCode."),
    schema_version: str = typer.Option("1-0E", "--schema-version", help="Form code schemaVersion."),
    form_value: str = typer.Option(
        "FA",
        "--form-value",
        help="Form code value (use FA_RR for FA_RR (1) 1-1E).",
    ),
    upo_v43: bool = typer.Option(False, "--upo-v43", help="Request UPO v4.3 format."),
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override KSeF base URL for this command."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = open_online_session(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            session_id=session_id,
            system_code=system_code,
            schema_version=schema_version,
            form_value=form_value,
            upo_v43=upo_v43,
        )
    except Exception as exc:
        _render_error(ctx, "session.online.open", exc)
    renderer.success(command="session.online.open", profile=profile, data=result)


@online_app.command("send")
def session_online_send(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
    invoice: str = typer.Option(..., "--invoice", help="Path to invoice XML file."),
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
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = send_online_session_invoice(
            profile=profile,
            session_id=session_id,
            invoice=invoice,
            wait_status=wait_status,
            wait_upo=wait_upo,
            poll_interval=poll_interval,
            max_attempts=max_attempts,
            save_upo=save_upo,
            save_upo_overwrite=save_upo_overwrite,
        )
    except Exception as exc:
        _render_error(ctx, "session.online.send", exc)
    renderer.success(command="session.online.send", profile=profile, data=result)


@online_app.command("close")
def session_online_close(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = close_online_session(profile=profile, session_id=session_id)
    except Exception as exc:
        _render_error(ctx, "session.online.close", exc)
    renderer.success(command="session.online.close", profile=profile, data=result)


@batch_app.command("open")
def session_batch_open(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
    zip_path: str | None = typer.Option(None, "--zip", help="Path to input ZIP with invoices."),
    directory: str | None = typer.Option(
        None, "--dir", help="Directory with XML files to ZIP and upload."
    ),
    system_code: str = typer.Option("FA (3)", "--system-code", help="Form code systemCode."),
    schema_version: str = typer.Option("1-0E", "--schema-version", help="Form code schemaVersion."),
    form_value: str = typer.Option(
        "FA",
        "--form-value",
        help="Form code value (use FA_RR for FA_RR (1) 1-1E).",
    ),
    upo_v43: bool = typer.Option(False, "--upo-v43", help="Request UPO v4.3 format."),
    base_url: str | None = typer.Option(
        None, "--base-url", help="Override KSeF base URL for this command."
    ),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = open_batch_session(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            session_id=session_id,
            zip_path=zip_path,
            directory=directory,
            system_code=system_code,
            schema_version=schema_version,
            form_value=form_value,
            upo_v43=upo_v43,
        )
    except Exception as exc:
        _render_error(ctx, "session.batch.open", exc)
    renderer.success(command="session.batch.open", profile=profile, data=result)


@batch_app.command("upload")
def session_batch_upload(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
    parallelism: int = typer.Option(4, "--parallelism", help="Parallel upload worker count."),
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = upload_batch_session(
            profile=profile,
            session_id=session_id,
            parallelism=parallelism,
        )
    except Exception as exc:
        _render_error(ctx, "session.batch.upload", exc)
    renderer.success(command="session.batch.upload", profile=profile, data=result)


@batch_app.command("close")
def session_batch_close(
    ctx: typer.Context,
    session_id: str = typer.Option(..., "--id", help="Saved session checkpoint id."),
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
) -> None:
    cli_ctx = require_context(ctx)
    renderer = get_renderer(cli_ctx)
    profile = profile_label(cli_ctx)
    try:
        profile = require_profile(cli_ctx)
        result = close_batch_session(
            profile=profile,
            session_id=session_id,
            wait_status=wait_status,
            wait_upo=wait_upo,
            poll_interval=poll_interval,
            max_attempts=max_attempts,
            save_upo=save_upo,
            save_upo_overwrite=save_upo_overwrite,
        )
    except Exception as exc:
        _render_error(ctx, "session.batch.close", exc)
    renderer.success(command="session.batch.close", profile=profile, data=result)


app.add_typer(online_app, name="online")
app.add_typer(batch_app, name="batch")
