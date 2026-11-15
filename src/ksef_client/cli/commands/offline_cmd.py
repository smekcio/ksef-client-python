from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import typer

from ksef_client._offline_invoice_store import MAX_OFFLINE_XML_BYTES
from ksef_client.invoice_search import _date
from ksef_client.invoice_sync_state import utc_timestamp
from ksef_client.invoice_xml_storage import _safe_directory
from ksef_client.offline_invoices import (
    OfflineInvoiceMode,
    OfflineInvoiceQueue,
    OfflineInvoiceStatus,
    StoredOfflineInvoice,
)

from ..context import require_context
from ..errors import CliError
from ..exit_codes import ExitCode
from ..output import get_renderer
from ._workflow import offline_store, workflow_client, workflow_config, workflow_errors

app = typer.Typer(help="Manage a durable offline invoice queue.")


@contextmanager
def _local_queue(
    ctx: typer.Context, root: Path, *, create: bool = False
) -> Iterator[tuple[str, OfflineInvoiceQueue]]:
    profile, options, kind, context, directory = workflow_config(ctx, root)
    with offline_store(directory, create=create) as store:
        yield (
            profile,
            OfflineInvoiceQueue(
                store, options=options, context_type=kind, context_value=context, namespace=profile
            ),
        )


def _summary(row: StoredOfflineInvoice, now: str) -> dict[str, Any]:
    status = row.progress.status
    return {
        "invoice_hash": row.progress.invoice_hash,
        "status": status.value,
        "due_at": row.due_at,
        "overdue": _date(row.due_at) <= _date(now)
        and status not in {OfflineInvoiceStatus.ACCEPTED, OfflineInvoiceStatus.COMPLETE},
        "revision": row.revision,
        "mode": row.mode.value,
        "ksef_status": row.progress.ksef_status,
    }


def _page_cursor(
    invoice_hash: str | None, due_at: str | None, after_hash: str | None
) -> tuple[str, str] | None:
    if due_at is None and after_hash is None:
        return None
    if not due_at or not after_hash or invoice_hash is not None:
        raise CliError("Use both cursor fields when listing the queue.", ExitCode.VALIDATION_ERROR)
    return due_at, after_hash


@app.command("enqueue")
def enqueue(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Private workflow directory.")],
    xml: Annotated[Path, typer.Option("--xml", help="Path to the original FA(3) XML file.")],
    due_at: str = typer.Option(..., "--due-at", help="Submission deadline in ISO 8601 with zone."),
    mode: Annotated[OfflineInvoiceMode, typer.Option("--mode")] = OfflineInvoiceMode.OFFLINE24,
    correction_of: str | None = typer.Option(
        None, "--correction-of", help="Original invoice hash."
    ),
) -> None:
    with workflow_errors(ctx, "offline.enqueue"):
        with _local_queue(ctx, state_dir, create=True) as (profile, queue):
            with xml.open("rb") as source:
                content = source.read(MAX_OFFLINE_XML_BYTES + 1)
            row = queue.enqueue(content, due_at=due_at, correction_of=correction_of, mode=mode)
        now = utc_timestamp(datetime.now(timezone.utc).isoformat())
        get_renderer(require_context(ctx)).success(
            command="offline.enqueue", profile=profile, data=_summary(row, now)
        )


@app.command("status")
def status(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Private workflow directory.")],
    invoice_hash: str | None = typer.Option(None, "--invoice-hash"),
    limit: int = typer.Option(100, "--limit", min=1, max=100),  # noqa: B008
    after_due_at: str | None = typer.Option(None, "--after-due-at"),
    after_hash: str | None = typer.Option(None, "--after-hash"),
) -> None:
    with workflow_errors(ctx, "offline.status"):
        after = _page_cursor(invoice_hash, after_due_at, after_hash)
        now = utc_timestamp(datetime.now(timezone.utc).isoformat())
        with _local_queue(ctx, state_dir) as (profile, queue):
            if invoice_hash is not None:
                row = queue.status(invoice_hash)
                if row is None:
                    raise CliError("Invoice not found in this profile.", ExitCode.VALIDATION_ERROR)
                data = _summary(row, now)
            else:
                rows = queue.pending(limit=limit, after=after)
                data = {"invoices": [_summary(row, now) for row in rows]}
        get_renderer(require_context(ctx)).success(
            command="offline.status", profile=profile, data=data
        )


@app.command("run")
def run(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Private workflow directory.")],
    limit: int = typer.Option(20, "--limit", min=1, max=100),  # noqa: B008
    timeout: float = typer.Option(60.0, "--timeout", min=1, max=600),  # noqa: B008
    invoice_hash: str | None = typer.Option(None, "--invoice-hash"),
    after_due_at: str | None = typer.Option(None, "--after-due-at"),
    after_hash: str | None = typer.Option(None, "--after-hash"),
) -> None:
    with workflow_errors(ctx, "offline.run"):
        after = _page_cursor(invoice_hash, after_due_at, after_hash)
        profile, options, kind, context, directory = workflow_config(ctx, state_dir)
        with (
            offline_store(directory) as store,
            workflow_client(profile, options, kind, context) as client,
        ):
            worker = client.invoices.offline(store, namespace=profile)
            page = worker.pending(limit=limit, after=after) if invoice_hash is None else ()
            hashes = (
                [invoice_hash]
                if invoice_hash is not None
                else [entry.progress.invoice_hash for entry in page]
            )
            rows = [worker.advance(digest, timeout=timeout) for digest in hashes]
        next_cursor = (
            {"due_at": page[-1].due_at, "invoice_hash": page[-1].progress.invoice_hash}
            if len(page) == limit
            else None
        )
        now = utc_timestamp(datetime.now(timezone.utc).isoformat())
        get_renderer(require_context(ctx)).success(
            command="offline.run",
            profile=profile,
            data={"invoices": [_summary(row, now) for row in rows], "next_cursor": next_cursor},
        )


@app.command("upo")
def upo(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Private workflow directory.")],
    invoice_hash: Annotated[str, typer.Option("--invoice-hash")],
    out: Annotated[Path, typer.Option("--out", help="New private UPO file.")],
) -> None:
    with workflow_errors(ctx, "offline.upo"):
        with _local_queue(ctx, state_dir) as (profile, queue):
            receipt = queue.read_upo(invoice_hash)
        # Write and close before publishing the file. Linking fails if the
        # destination already exists, including an existing symbolic link.
        destination = out.absolute()
        _safe_directory(destination.parent)
        fd, filename = tempfile.mkstemp(dir=destination.parent, prefix=".ksef-upo-")
        temporary = Path(filename)
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(receipt)
                file.flush()
                os.fsync(file.fileno())
            os.link(temporary, destination)
        finally:
            temporary.unlink()
        get_renderer(require_context(ctx)).success(
            command="offline.upo", profile=profile, data={"saved": str(out)}
        )


@app.command("reschedule")
def reschedule(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Private workflow directory.")],
    invoice_hash: Annotated[str, typer.Option("--invoice-hash")],
    due_at: Annotated[str, typer.Option("--due-at", help="New deadline in ISO 8601 with zone.")],
    revision: Annotated[int, typer.Option("--revision", min=1)],
) -> None:
    with workflow_errors(ctx, "offline.reschedule"):
        with _local_queue(ctx, state_dir) as (profile, queue):
            row = queue.reschedule(invoice_hash, due_at=due_at, expected_revision=revision)
        now = utc_timestamp(datetime.now(timezone.utc).isoformat())
        get_renderer(require_context(ctx)).success(
            command="offline.reschedule", profile=profile, data=_summary(row, now)
        )


@app.command("retry-cancelled")
def retry_cancelled(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Private workflow directory.")],
    invoice_hash: Annotated[str, typer.Option("--invoice-hash")],
) -> None:
    with workflow_errors(ctx, "offline.retry-cancelled"):
        with _local_queue(ctx, state_dir) as (profile, queue):
            row = queue.retry_cancelled(invoice_hash)
        now = utc_timestamp(datetime.now(timezone.utc).isoformat())
        get_renderer(require_context(ctx)).success(
            command="offline.retry-cancelled", profile=profile, data=_summary(row, now)
        )


@app.command("retry-unsubmitted")
def retry_unsubmitted(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Private workflow directory.")],
    invoice_hash: Annotated[str, typer.Option("--invoice-hash")],
    timeout: Annotated[float, typer.Option("--timeout", min=1, max=600)] = 60,
) -> None:
    with workflow_errors(ctx, "offline.retry-unsubmitted"):
        profile, options, kind, context, directory = workflow_config(ctx, state_dir)
        with (
            offline_store(directory) as store,
            workflow_client(profile, options, kind, context) as client,
        ):
            queue = client.invoices.offline(store, namespace=profile)
            row = queue.retry_if_unsubmitted(invoice_hash, timeout=timeout)
        now = utc_timestamp(datetime.now(timezone.utc).isoformat())
        get_renderer(require_context(ctx)).success(
            command="offline.retry-unsubmitted", profile=profile, data=_summary(row, now)
        )
