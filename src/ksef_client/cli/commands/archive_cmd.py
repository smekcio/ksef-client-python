from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Annotated

import typer

from ksef_client import FileInvoiceXmlStore, SQLiteInvoiceSyncStore
from ksef_client.invoice_export_sync import InvoiceExportSyncReport, inspect_archive_progress
from ksef_client.models import InvoiceQuerySubjectType
from ksef_client.operations import environment_key

from ..context import require_context
from ..output import get_renderer
from . import archive_delivery
from ._workflow import workflow_client, workflow_config, workflow_errors, workflow_key

app = typer.Typer(help="Synchronize verified KSeF exports into a local archive.")
app.command("next")(archive_delivery.next_invoice)
app.command("ack")(archive_delivery.acknowledge)
app.command("retry")(archive_delivery.retry)


@app.command("sync")
def sync(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Private workflow directory.")],
    since: Annotated[str, typer.Option("--since", help="Start timestamp (ISO 8601 with zone).")],
    until: Annotated[
        str | None, typer.Option("--until", help="Fixed historical end timestamp.")
    ] = None,
    role: Annotated[
        InvoiceQuerySubjectType, typer.Option("--role")
    ] = InvoiceQuerySubjectType.SUBJECT2,
    timeout: Annotated[float, typer.Option("--timeout", min=1, max=600)] = 60,
    max_documents: Annotated[int, typer.Option("--max-documents", min=1, max=10000)] = 500,
) -> None:
    with workflow_errors(ctx, "archive.sync"):
        profile, options, kind, context, directory = workflow_config(ctx, state_dir)
        state_key = workflow_key("KSEF_EXPORT_STATE_KEY")
        with (
            workflow_client(profile, options, kind, context) as client,
            FileInvoiceXmlStore(directory / "xml") as storage,
            SQLiteInvoiceSyncStore.open(
                directory / "invoices.db",
                enqueue_xml=True,
                xml_storage_id=storage.storage_id,
            ) as store,
        ):
            workflow = client.exports.sync_archive(
                namespace=profile,
                sync_key="archive",
                since=since,
                work_dir=directory / "export-work",
                state_key=state_key,
                subject_type=role,
            )
            report = workflow.run_once(
                store, storage, until=until, timeout=timeout, max_documents=max_documents
            )
        get_renderer(require_context(ctx)).success(
            command="archive.sync", profile=profile, data={**asdict(report), "role": role.value}
        )


@app.command("status")
def status(
    ctx: typer.Context,
    state_dir: Annotated[Path, typer.Option("--state-dir", help="Private workflow directory.")],
    role: Annotated[
        InvoiceQuerySubjectType, typer.Option("--role")
    ] = InvoiceQuerySubjectType.SUBJECT2,
) -> None:
    with workflow_errors(ctx, "archive.status"):
        profile, options, kind, context, directory = workflow_config(ctx, state_dir)
        database = directory / "invoices.db"
        if database.is_file():
            state_key = workflow_key("KSEF_EXPORT_STATE_KEY")
            with SQLiteInvoiceSyncStore.open(database) as store:
                report = inspect_archive_progress(
                    store,
                    namespace=profile,
                    environment=environment_key(options.normalized_base_url()),
                    context_key=f"{kind}:{context}",
                    sync_key="archive",
                    state_key=state_key,
                    subject_type=role,
                )
        else:
            report = InvoiceExportSyncReport(None, None, status="uninitialized")
        get_renderer(require_context(ctx)).success(
            command="archive.status", profile=profile, data={**asdict(report), "role": role.value}
        )
