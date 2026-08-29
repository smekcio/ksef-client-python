from __future__ import annotations

import os
from pathlib import Path

import typer

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError
from ksef_client.utils.collective_identifier import (
    PAGE_SIZE_INVOICES_MAX,
    PAGE_SIZE_MAX,
    PAGE_SIZE_MIN,
)

from ..auth.manager import resolve_base_url
from ..context import profile_label, require_context, require_profile
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer
from ..sdk.adapters import (
    generate_collective_identifier,
    list_collective_identifier_invoices,
    list_collective_identifiers_by_ksef_number,
    query_collective_identifiers,
)
from ._error_utils import build_api_error_hint, build_rate_limit_hint

app = typer.Typer(help="Generate and query KSeF collective identifiers (IZ).")


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
            build_api_error_hint(
                exc,
                default_hint="Check KSeF response and collective identifier parameters.",
            )
            if isinstance(exc, KsefApiError)
            else "Check KSeF response and collective identifier parameters."
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


@app.command("generate")
def iz_generate(
    ctx: typer.Context,
    ksef_number: list[str] | None = typer.Option(  # noqa: B008
        None, "--ksef-number", help="KSeF number to include (repeatable)."
    ),
    from_file: Path | None = typer.Option(  # noqa: B008
        None, "--from-file", help="File with one KSeF number per line."
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
        result = generate_collective_identifier(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            ksef_numbers=list(ksef_number or []),
            from_file=str(from_file) if from_file is not None else None,
        )
    except Exception as exc:
        _render_error(ctx, "iz.generate", exc)
    renderer.success(
        command="iz.generate",
        profile=profile,
        data=result,
    )


@app.command("query")
def iz_query(
    ctx: typer.Context,
    date_from: str = typer.Option(..., "--from", help="Created-from date (YYYY-MM-DD)."),
    date_to: str = typer.Option(..., "--to", help="Created-to date (YYYY-MM-DD)."),
    iz_number: str | None = typer.Option(
        None, "--iz", help="Filter by collective identifier number."
    ),
    page_size: int = typer.Option(
        PAGE_SIZE_MIN,
        "--page-size",
        min=PAGE_SIZE_MIN,
        max=PAGE_SIZE_MAX,
        help=f"Number of items per page ({PAGE_SIZE_MIN}-{PAGE_SIZE_MAX}).",
    ),
    fetch_all: bool = typer.Option(
        False, "--all", help="Follow continuation tokens and return every page."
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
        result = query_collective_identifiers(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            date_from=date_from,
            date_to=date_to,
            collective_identifier_number=iz_number,
            page_size=page_size,
            fetch_all=fetch_all,
        )
    except Exception as exc:
        _render_error(ctx, "iz.query", exc)
    renderer.success(
        command="iz.query",
        profile=profile,
        data=result,
    )


@app.command("invoices")
def iz_invoices(
    ctx: typer.Context,
    iz_number: list[str] | None = typer.Option(  # noqa: B008
        None, "--iz", help="Collective identifier number (repeatable, max 10)."
    ),
    page_size: int = typer.Option(
        PAGE_SIZE_MIN,
        "--page-size",
        min=PAGE_SIZE_MIN,
        max=PAGE_SIZE_INVOICES_MAX,
        help=f"Number of items per page ({PAGE_SIZE_MIN}-{PAGE_SIZE_INVOICES_MAX}).",
    ),
    fetch_all: bool = typer.Option(
        False, "--all", help="Follow continuation tokens and return every page."
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
        result = list_collective_identifier_invoices(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            iz_numbers=list(iz_number or []),
            page_size=page_size,
            fetch_all=fetch_all,
        )
    except Exception as exc:
        _render_error(ctx, "iz.invoices", exc)
    renderer.success(
        command="iz.invoices",
        profile=profile,
        data=result,
    )


@app.command("by-ksef")
def iz_by_ksef(
    ctx: typer.Context,
    ksef_number: str = typer.Option(..., "--ksef-number", help="KSeF invoice number."),
    page_size: int = typer.Option(
        PAGE_SIZE_MIN,
        "--page-size",
        min=PAGE_SIZE_MIN,
        max=PAGE_SIZE_MAX,
        help=f"Number of items per page ({PAGE_SIZE_MIN}-{PAGE_SIZE_MAX}).",
    ),
    fetch_all: bool = typer.Option(
        False, "--all", help="Follow continuation tokens and return every page."
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
        result = list_collective_identifiers_by_ksef_number(
            profile=profile,
            base_url=resolve_base_url(base_url or os.getenv("KSEF_BASE_URL"), profile=profile),
            ksef_number=ksef_number,
            page_size=page_size,
            fetch_all=fetch_all,
        )
    except Exception as exc:
        _render_error(ctx, "iz.by-ksef", exc)
    renderer.success(
        command="iz.by-ksef",
        profile=profile,
        data=result,
    )
