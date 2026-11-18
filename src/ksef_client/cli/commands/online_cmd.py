"""Operate an online submission across CLI invocations using the application's invoice ID."""

from __future__ import annotations

import math
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated

import typer

from ksef_client._offline_invoice_store import MAX_OFFLINE_XML_BYTES
from ksef_client.config import KsefClientOptions
from ksef_client.exceptions import KsefSyncConflictError
from ksef_client.online_invoices import (
    OnlineInvoice,
    OnlineInvoiceQueue,
    OnlineInvoices,
    OnlineInvoiceStatus,
    SQLiteOnlineInvoiceStore,
)
from ksef_client.operations import environment_key
from ksef_client.request_control import wait_seconds

from ..context import require_context
from ..errors import CliError
from ..exit_codes import ExitCode
from ..files import private_directory, write_private_file
from ..output import get_renderer
from ..sdk.adapters import _resolve_output_path
from ._workflow import workflow_client, workflow_config, workflow_errors, workflow_key

app = typer.Typer(help="Track online invoices and their individual UPO by your own invoice ID.")
StateDir = Annotated[
    Path, typer.Option("--state-dir", help="Private workflow directory. Reuse it after a restart.")
]
LocalId = Annotated[
    str, typer.Option("--id", "--local-id", help="Your stable application invoice ID.")
]
Timeout = Annotated[
    float, typer.Option("--timeout", min=1, max=600, help="Time budget for this step in seconds.")
]


def _store(directory: Path, *, create: bool = False) -> SQLiteOnlineInvoiceStore:
    database = directory / "online.db"
    if not create and not database.is_file():
        raise CliError(
            "No online submissions in this profile.",
            ExitCode.CONFIG_ERROR,
            "Register an XML with ksef online enqueue.",
        )
    return SQLiteOnlineInvoiceStore.open(database, key=workflow_key("KSEF_ONLINE_STATE_KEY"))


@contextmanager
def _local(
    ctx: typer.Context, root: Path, *, create: bool = False
) -> Iterator[tuple[str, OnlineInvoiceQueue]]:
    profile, options, kind, context, directory = workflow_config(ctx, root)
    with _store(directory, create=create) as store:
        yield profile, _queue(store, profile, options, kind, context)


def _queue(
    store: SQLiteOnlineInvoiceStore,
    profile: str,
    options: KsefClientOptions,
    kind: str,
    context: str,
) -> OnlineInvoiceQueue:
    return OnlineInvoiceQueue(
        store,
        namespace=profile,
        environment=environment_key(options.normalized_base_url()),
        context_key=f"{kind}:{context}",
    )


@contextmanager
def _connected(ctx: typer.Context, root: Path) -> Iterator[tuple[str, OnlineInvoices]]:
    profile, options, kind, context, directory = workflow_config(ctx, root)
    with _store(directory) as store, workflow_client(profile, options, kind, context) as client:
        yield profile, client.invoices.online(store, namespace=profile)


def _show(
    ctx: typer.Context, command: str, profile: str, row: OnlineInvoice, *, saved: Path | None = None
) -> None:
    get_renderer(require_context(ctx)).success(
        command=command,
        profile=profile,
        data={
            "local_id": row.local_id,
            "status": row.status.value,
            "revision": row.revision,
            "session_ref": row.session_reference,
            "invoice_ref": row.invoice_reference,
            "ksef_number": row.ksef_number,
            "ksef_status": row.ksef_status,
            **({"upo_path": str(saved)} if saved else {}),
        },
    )


def _find(queue: OnlineInvoiceQueue, local_id: str) -> OnlineInvoice:
    row = queue.status(local_id)
    if row is None:
        raise CliError(
            "Unknown invoice ID in this profile.",
            ExitCode.VALIDATION_ERROR,
            "Check --id and --state-dir or register the XML with online enqueue.",
        )
    return row


@app.command()
def enqueue(
    ctx: typer.Context,
    state_dir: StateDir,
    local_id: LocalId,
    xml: Annotated[Path, typer.Option("--xml", "--invoice", help="Original invoice XML file.")],
) -> None:
    """Register the XML under an ID. Repeating the same ID and XML is safe."""
    with (
        workflow_errors(ctx, "online.enqueue"),
        _local(ctx, state_dir, create=True) as (profile, queue),
    ):
        _show(ctx, "online.enqueue", profile, _register(queue, local_id, xml))


def _register(queue: OnlineInvoiceQueue, local_id: str, xml: Path) -> OnlineInvoice:
    with xml.open("rb") as source:
        content = source.read(MAX_OFFLINE_XML_BYTES + 1)
    try:
        return queue.enqueue(local_id, content)
    except KsefSyncConflictError as exc:
        raise CliError(
            "This ID or XML is already bound to a different submission.",
            ExitCode.VALIDATION_ERROR,
            "Use online status to inspect the original submission.",
        ) from exc


def tracked_send(
    ctx: typer.Context,
    state_dir: Path,
    local_id: str,
    xml: Path,
    *,
    wait_status: bool,
    wait_upo: bool,
    poll_interval: float,
    max_attempts: int,
    save_upo: str | None,
    overwrite: bool,
) -> None:
    """Send through the same persistent worker used by online run and resume by ID."""
    if save_upo and not wait_upo:
        raise CliError("--save-upo requires --wait-upo.", ExitCode.VALIDATION_ERROR)
    if (wait_upo or wait_status) and (
        not math.isfinite(poll_interval) or poll_interval <= 0 or max_attempts < 1
    ):
        raise CliError(
            "Polling requires a positive interval and number of attempts.",
            ExitCode.VALIDATION_ERROR,
        )
    done = {
        OnlineInvoiceStatus.COMPLETE,
        OnlineInvoiceStatus.REJECTED,
        OnlineInvoiceStatus.DUPLICATE,
        OnlineInvoiceStatus.RETRYABLE,
    }
    if not wait_upo:
        done.add(OnlineInvoiceStatus.ACCEPTED)
    profile, options, kind, context, directory = workflow_config(ctx, state_dir)
    saved = None
    with _store(directory, create=True) as store:
        queue = _queue(store, profile, options, kind, context)
        row = _register(queue, local_id, xml)
        submit = {OnlineInvoiceStatus.SESSION_OPEN, OnlineInvoiceStatus.SUBMISSION_UNKNOWN}
        if (
            row.status is OnlineInvoiceStatus.QUEUED
            or row.status in submit
            or ((wait_status or wait_upo) and row.status not in done)
        ):
            with workflow_client(profile, options, kind, context) as client:
                worker = client.invoices.online(store, namespace=profile)
                if row.status is OnlineInvoiceStatus.QUEUED:
                    row = worker.advance(local_id)
                if row.status in submit:
                    row = worker.advance(local_id)
                if wait_status or wait_upo:
                    for attempt in range(max_attempts):
                        if row.status in done:
                            break
                        if attempt:
                            wait_seconds(poll_interval)
                        row = worker.advance(local_id)
                    if row.status not in done:
                        raise CliError(
                            "Invoice processing is still pending. Progress was saved.",
                            ExitCode.RETRY_EXHAUSTED,
                            "Continue with ksef online run using the same ID.",
                        )
        if (wait_status or wait_upo) and row.status not in {
            OnlineInvoiceStatus.ACCEPTED,
            OnlineInvoiceStatus.COMPLETE,
        }:
            raise CliError(
                f"KSeF did not accept this invoice (status {row.ksef_status}, {row.status.value}).",
                ExitCode.API_ERROR,
                "Inspect the saved result with ksef online status.",
            )
        if save_upo:
            saved = _resolve_output_path(
                save_upo,
                default_filename=f"upo-{row.session_reference}-{row.invoice_reference}.xml",
            )
            private_directory(saved.absolute().parent)
            write_private_file(saved, queue.read_upo(local_id), overwrite=overwrite)
    _show(ctx, "send.online", profile, row, saved=saved)


@app.command()
def run(ctx: typer.Context, state_dir: StateDir, local_id: LocalId, timeout: Timeout = 60) -> None:
    """Advance one submission step. Run again with the same ID after a restart or pending result."""
    with workflow_errors(ctx, "online.run"), _connected(ctx, state_dir) as (profile, worker):
        _show(ctx, "online.run", profile, worker.advance(local_id, timeout=timeout))


@app.command()
def status(ctx: typer.Context, state_dir: StateDir, local_id: LocalId) -> None:
    """Show the saved status and KSeF references for one invoice, including after logout."""
    with workflow_errors(ctx, "online.status"), _local(ctx, state_dir) as (profile, queue):
        _show(ctx, "online.status", profile, _find(queue, local_id))


@app.command()
def upo(
    ctx: typer.Context,
    state_dir: StateDir,
    local_id: LocalId,
    out: Annotated[Path, typer.Option("--out", help="New file for the verified individual UPO.")],
) -> None:
    """Save the individual UPO stored for this ID."""
    with workflow_errors(ctx, "online.upo"), _local(ctx, state_dir) as (profile, queue):
        if _find(queue, local_id).status is not OnlineInvoiceStatus.COMPLETE:
            raise CliError(
                "The individual UPO is not available yet.",
                ExitCode.VALIDATION_ERROR,
                "Check online status and use online run to advance a pending invoice.",
            )
        write_private_file(out, queue.read_upo(local_id))
        get_renderer(require_context(ctx)).success(
            command="online.upo", profile=profile, data={"saved": str(out)}
        )


@app.command("retry-unsubmitted")
def retry_unsubmitted(
    ctx: typer.Context, state_dir: StateDir, local_id: LocalId, timeout: Timeout = 60
) -> None:
    """Allow another attempt only when KSeF confirms the previous session was empty."""
    with (
        workflow_errors(ctx, "online.retry-unsubmitted"),
        _connected(ctx, state_dir) as (profile, worker),
    ):
        _show(
            ctx,
            "online.retry-unsubmitted",
            profile,
            worker.retry_if_unsubmitted(local_id, timeout=timeout),
        )


@app.command("retry-cancelled")
def retry_cancelled(ctx: typer.Context, state_dir: StateDir, local_id: LocalId) -> None:
    """Requeue an invoice after KSeF has confirmed cancellation (550)."""
    with workflow_errors(ctx, "online.retry-cancelled"), _local(ctx, state_dir) as (profile, queue):
        _show(ctx, "online.retry-cancelled", profile, queue.retry_cancelled(local_id))
