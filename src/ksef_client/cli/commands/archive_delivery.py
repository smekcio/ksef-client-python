from __future__ import annotations

import json
import tempfile
import uuid
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

import typer

from ksef_client import FileInvoiceXmlStore, SQLiteInvoiceSyncStore
from ksef_client.invoice_delivery import (
    IncomingInvoiceDelivery,
    InvoiceDeliveryReceipt,
    KsefInvoiceDeliveryLeaseLostError,
)
from ksef_client.invoice_export_sync import _archive_scope
from ksef_client.invoice_sync_state import InvoiceSyncScope
from ksef_client.models import InvoiceQuerySubjectType
from ksef_client.operations import environment_key
from ksef_client.streaming_export import publish_directory, safe_file

from ..context import require_context
from ..errors import CliError
from ..exit_codes import ExitCode
from ..files import private_directory, write_private_file
from ..output import get_renderer
from ._workflow import workflow_config, workflow_errors

StateDir = Annotated[
    Path, typer.Option("--state-dir", help="Same private directory as archive sync.")
]
ReceiptFile = Annotated[
    Path, typer.Option("--receipt", help="Private receipt.json returned by archive next.")
]


def _archive(ctx: typer.Context, root: Path) -> tuple[str, InvoiceSyncScope, Path]:
    profile, options, kind, context, directory = workflow_config(ctx, root)
    database = directory / "invoices.db"
    if not database.is_file():
        raise CliError(
            "No invoice archive in this profile.",
            ExitCode.CONFIG_ERROR,
            "Run ksef archive sync with the same --state-dir first.",
        )
    scope = _archive_scope(
        profile,
        environment_key(options.normalized_base_url()),
        f"{kind}:{context}",
        "archive",
        InvoiceQuerySubjectType.SUBJECT2,
    )
    return profile, scope, directory


def _publish(delivery: IncomingInvoiceDelivery, out: Path) -> Path:
    parent = out.absolute()
    private_directory(parent)
    destination = parent / f"invoice-{uuid.uuid4().hex}"
    with tempfile.TemporaryDirectory(prefix=".ksef-delivery-", dir=parent) as tmp:
        stage = Path(tmp)
        write_private_file(stage / "invoice.xml", delivery.xml, overwrite=True)
        for name, data in (
            ("metadata.json", delivery.metadata.to_dict()),
            ("receipt.json", delivery.receipt.to_dict()),
        ):
            write_private_file(stage / name, json.dumps(data).encode("utf-8"), overwrite=True)
        publish_directory(stage, destination)
    return destination


def next_invoice(
    ctx: typer.Context,
    state_dir: StateDir,
    consumer: Annotated[
        str, typer.Option("--consumer", help="Stable name of the receiving application.")
    ],
    out: Annotated[
        Path, typer.Option("--out", help="Parent directory for a new private delivery folder.")
    ],
    lease_seconds: Annotated[
        int,
        typer.Option(
            "--lease-seconds",
            min=1,
            max=86400,
            help="Time to acknowledge or release this delivery.",
        ),
    ] = 300,
) -> None:
    """Claim one verified purchase invoice and save its XML, metadata and receipt."""
    with workflow_errors(ctx, "archive.next"):
        profile, scope, directory = _archive(ctx, state_dir)
        renderer = get_renderer(require_context(ctx))
        xml_directory = directory / "xml"
        if not xml_directory.is_dir():
            raise CliError(
                "The original XML archive directory is unavailable.",
                ExitCode.IO_ERROR,
                "Restore the XML directory from the same archive.",
            )
        with (
            FileInvoiceXmlStore(xml_directory) as storage,
            SQLiteInvoiceSyncStore.open(
                directory / "invoices.db", enqueue_xml=True, xml_storage_id=storage.storage_id
            ) as store,
        ):
            delivery = store.claim_invoice_delivery(
                scope, storage, consumer=consumer, lease_seconds=lease_seconds
            )
            if delivery is None:
                renderer.success(command="archive.next", profile=profile, data={"available": False})
                return
            try:
                target = _publish(delivery, out)
            except Exception:
                # A failed hand-off can be picked up without waiting for lease expiry.
                with suppress(KsefInvoiceDeliveryLeaseLostError):
                    store.retry_invoice_delivery(delivery)
                raise
        renderer.success(
            command="archive.next",
            profile=profile,
            data={
                "available": True,
                "event_id": delivery.event_id,
                "consumer": delivery.consumer,
                "ksef_number": delivery.key.ksef_number,
                "expires_at": datetime.fromtimestamp(delivery.expires_at, timezone.utc).isoformat(),
                "xml": str(target / "invoice.xml"),
                "metadata": str(target / "metadata.json"),
                "receipt": str(target / "receipt.json"),
            },
        )


def _finish(ctx: typer.Context, state_dir: Path, receipt_path: Path, delay: int | None) -> None:
    command = "archive.ack" if delay is None else "archive.retry"
    with workflow_errors(ctx, command):
        profile, scope, directory = _archive(ctx, state_dir)
        with safe_file(receipt_path).open("rb") as source:
            raw = source.read(64 * 1024 + 1)
        try:
            if len(raw) > 64 * 1024:
                raise ValueError
            receipt = InvoiceDeliveryReceipt.from_dict(json.loads(raw))
        except (ValueError, RecursionError):
            raise CliError(
                "Invalid delivery receipt.",
                ExitCode.VALIDATION_ERROR,
                "Use the receipt.json returned by archive next.",
            ) from None
        key = receipt.key
        if (key.namespace, key.environment, key.context_key) != (
            scope.namespace,
            scope.environment,
            scope.context_key,
        ):
            raise CliError(
                "Receipt belongs to a different profile or authentication context.",
                ExitCode.VALIDATION_ERROR,
            )
        try:
            with SQLiteInvoiceSyncStore.open(directory / "invoices.db") as store:
                if delay is None:
                    store.acknowledge_invoice_delivery(receipt)
                else:
                    store.retry_invoice_delivery(receipt, delay_seconds=delay)
        except KsefInvoiceDeliveryLeaseLostError:
            raise CliError(
                "This delivery attempt is no longer current.",
                ExitCode.VALIDATION_ERROR,
                "Claim the next available invoice with archive next.",
            ) from None
        get_renderer(require_context(ctx)).success(
            command=command,
            profile=profile,
            data={
                "consumer": receipt.consumer,
                "ksef_number": key.ksef_number,
                "acknowledged": delay is None,
                **({"delay_seconds": delay} if delay is not None else {}),
            },
        )


def acknowledge(ctx: typer.Context, state_dir: StateDir, receipt: ReceiptFile) -> None:
    """Confirm successful processing. Repeating the same successful acknowledgement is safe."""
    _finish(ctx, state_dir, receipt, None)


def retry(
    ctx: typer.Context,
    state_dir: StateDir,
    receipt: ReceiptFile,
    delay: Annotated[int, typer.Option("--delay-seconds", min=0, max=86400)] = 0,
) -> None:
    """Release an active delivery for another attempt, optionally after a delay."""
    _finish(ctx, state_dir, receipt, delay)
