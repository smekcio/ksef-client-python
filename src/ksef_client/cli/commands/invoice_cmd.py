from __future__ import annotations

import os
from enum import Enum

import typer

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError

from ..auth.manager import resolve_base_url
from ..context import profile_label, require_context, require_profile
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer
from ..sdk.adapters import download_invoice, list_invoices

app = typer.Typer(help="List and download invoices.")


class SortOrder(str, Enum):
    ASC = "Asc"
    DESC = "Desc"


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


@app.command("list")
def invoice_list(
    ctx: typer.Context,
    date_from: str | None = typer.Option(None, "--from", help="Start date (YYYY-MM-DD)."),
    date_to: str | None = typer.Option(None, "--to", help="End date (YYYY-MM-DD)."),
    subject_type: str = typer.Option(
        "Subject1", "--subject-type", help="KSeF subject type filter."
    ),
    date_type: str = typer.Option(
        "Issue", "--date-type", help="Date field used in filter, e.g. Issue."
    ),
    page_size: int = typer.Option(10, "--page-size", help="Number of items per page."),
    page_offset: int = typer.Option(0, "--page-offset", help="Pagination offset."),
    sort_order: SortOrder = typer.Option(  # noqa: B008
        SortOrder.DESC,
        "--sort-order",
        case_sensitive=False,
        help="Sort order: Asc or Desc.",
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
        result = list_invoices(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            date_from=date_from,
            date_to=date_to,
            subject_type=subject_type,
            date_type=date_type,
            page_size=page_size,
            page_offset=page_offset,
            sort_order=sort_order.value,
        )
    except Exception as exc:
        _render_error(ctx, "invoice.list", exc)
    renderer.success(
        command="invoice.list",
        profile=profile,
        data=result,
    )


@app.command("download")
def invoice_download(
    ctx: typer.Context,
    ksef_number: str = typer.Option(..., "--ksef-number", help="KSeF invoice reference number."),
    out: str = typer.Option(..., "--out", help="Target output path (file or directory)."),
    as_format: str = typer.Option("xml", "--as", help="Download format: xml or bytes."),
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
        result = download_invoice(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            ksef_number=ksef_number,
            out=out,
            as_format=as_format,
            overwrite=overwrite,
        )
    except Exception as exc:
        _render_error(ctx, "invoice.download", exc)
    renderer.success(
        command="invoice.download",
        profile=profile,
        data=result,
    )
