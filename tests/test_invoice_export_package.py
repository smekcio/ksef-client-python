import base64
import hashlib
import json
from dataclasses import replace

import pytest

from ksef_client import models as m
from ksef_client._invoice_export_package import ValidatedInvoicePackage, validate_invoice_package
from ksef_client._invoice_export_state import ExportCheckpoint, ExportProgress
from ksef_client.exceptions import KsefDocumentValidationError, KsefSyncConflictError
from ksef_client.invoice_sync_state import InvoiceSyncScope
from ksef_client.invoice_xml_storage import FileInvoiceXmlStore
from ksef_client.invoice_xml_types import InvoiceXmlKey, KsefXmlIntegrityError
from ksef_client.operations import OperationState
from ksef_client.sqlite_store import SQLiteInvoiceSyncStore
from ksef_client.streaming_export import ExportFiles
from tests.test_invoice_xml_sync import NUMBER, NUMBER2

START = "2025-01-01T00:00:00Z"
LAST = "2025-01-02T00:00:00.1234567Z"
END = "2025-01-03T00:00:00Z"
XML = b"<invoice/>"
HASH = base64.b64encode(hashlib.sha256(XML).digest()).decode()


def package(directory, *, truncated=False, numbers=(NUMBER, NUMBER2), last=LAST):
    filenames = tuple(f"{number}.xml" for number in numbers)
    for name in filenames:
        (directory / name).write_bytes(XML)
    metadata = directory / "_metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "invoices": [
                    {"ksefNumber": number, "invoiceHash": HASH, "permanentStorageDate": LAST}
                    for number in numbers
                ]
            }
        ),
        encoding="utf-8",
    )
    descriptor = m.InvoicePackage(
        compression_type=m.CompressionType.ZIP,
        invoice_count=len(numbers),
        is_truncated=truncated,
        size=0,
        parts=[],
        last_permanent_storage_date=last,
        permanent_storage_hwm_date=END,
    )
    return ExportFiles(directory, (*filenames, metadata.name), metadata, descriptor)


@pytest.mark.parametrize("truncated", [False, True])
def test_package_preserves_each_invoice_at_inclusive_boundary(tmp_path, truncated):
    files = package(tmp_path, truncated=truncated)
    result = validate_invoice_package(files, start=START, end=END, max_metadata_bytes=4096)
    assert result.truncated is truncated
    assert result.continuation == (LAST if truncated else END)
    assert {invoice.number for invoice in result.invoices} == {NUMBER, NUMBER2}
    assert all(invoice.read_xml(len(XML)) == XML for invoice in result.invoices)


def test_truncated_package_requires_proven_boundary(tmp_path):
    files = package(tmp_path, truncated=True, last=END)
    with pytest.raises(KsefDocumentValidationError):
        validate_invoice_package(files, start=START, end=END, max_metadata_bytes=4096)


def test_duplicate_number_is_rejected(tmp_path):
    files = package(tmp_path, numbers=(NUMBER, NUMBER))
    with pytest.raises(KsefDocumentValidationError):
        validate_invoice_package(files, start=START, end=END, max_metadata_bytes=4096)


def test_xml_read_checks_size_and_content_hash(tmp_path):
    files = package(tmp_path)
    result = validate_invoice_package(files, start=START, end=END, max_metadata_bytes=4096)
    invoice = result.invoices[0]
    with pytest.raises(KsefDocumentValidationError, match="size limit"):
        invoice.read_xml(len(XML) - 1)
    (tmp_path / f"{NUMBER}.xml").write_bytes(b"<changed/>")
    with pytest.raises(KsefXmlIntegrityError):
        invoice.read_xml(4096)


def test_empty_export_can_confirm_server_hwm(tmp_path):
    files = package(tmp_path, numbers=())
    files = replace(files, files=(), metadata_path=None)
    result = validate_invoice_package(files, start=START, end=END, max_metadata_bytes=4096)
    assert not result.invoices
    assert result.continuation == END


@pytest.mark.parametrize("hwm", [None, "2024-12-31T00:00:00Z"])
def test_empty_export_without_usable_hwm_cannot_confirm_coverage(tmp_path, hwm):
    files = package(tmp_path, numbers=())
    files = replace(
        files,
        files=(),
        metadata_path=None,
        package=replace(files.package, permanent_storage_hwm_date=hwm),
    )
    with pytest.raises(KsefDocumentValidationError, match="coverage boundary"):
        validate_invoice_package(files, start=START, end=END, max_metadata_bytes=4096)


def test_rejects_duplicate_json_keys(tmp_path):
    files = package(tmp_path, numbers=())
    assert files.metadata_path is not None
    files.metadata_path.write_bytes(b'{"invoices":[],"invoices":[]}')
    with pytest.raises(KsefDocumentValidationError, match="metadata"):
        validate_invoice_package(files, start=START, end=END, max_metadata_bytes=4096)


def test_truncated_package_does_not_advance_committed_hwm():
    progress = ExportProgress(START, committed_hwm=START)
    truncated = ValidatedInvoicePackage((), LAST, True)
    progress = progress.finish(truncated, window_end=END, new_at_boundary=1)
    assert progress.committed_hwm == START
    assert progress.bounds(None) == (LAST, END)
    with pytest.raises(KsefDocumentValidationError, match="cannot advance"):
        progress.finish(truncated, window_end=END, new_at_boundary=0)
    progress = progress.finish(
        ValidatedInvoicePackage((), END, False), window_end=END, new_at_boundary=0
    )
    assert progress.committed_hwm == END
    assert progress.continuation is None


def test_long_history_bounds_each_request_to_one_hundred_utc_days():
    progress = ExportProgress("2025-01-02T00:30:00+01:00")
    assert progress.bounds("2026-01-01T00:00:00Z") == (
        "2025-01-01T23:30:00Z",
        "2025-04-11T00:00:00Z",
    )


def test_commit_export_records_ready_xml_and_rejects_stale_progress(tmp_path):
    database = tmp_path / "archive.db"
    scope = InvoiceSyncScope("company", "a" * 64, "Nip:test", "archive", "b" * 64)
    key = InvoiceXmlKey(scope.namespace, scope.environment, scope.context_key, NUMBER)
    metadata = {"ksefNumber": NUMBER, "invoiceHash": HASH, "permanentStorageDate": LAST}
    with FileInvoiceXmlStore(tmp_path / "xml") as storage:
        receipt = storage.put_verified(key, XML, HASH)
        opts = {"enqueue_xml": True, "xml_storage_id": storage.storage_id}
        with SQLiteInvoiceSyncStore.open(database, **opts) as store:
            assert store._load_export(scope) is None
            assert store._commit_export(
                scope,
                0,
                {"index": 1},
                storage_id=storage.storage_id,
                documents=[(metadata, receipt)],
            ) == (1, 1)
        with SQLiteInvoiceSyncStore.open(database, **opts) as store:
            assert store._load_export(scope) == (1, b'{"index":1}')
            assert store.list_xml([scope])[0]["status"] == "ready"
            assert store.claim_xml([scope], lease_seconds=120) is None
            with pytest.raises(KsefSyncConflictError):
                store._commit_export(scope, 0, {}, storage_id=storage.storage_id)
            assert store._commit_export(
                scope,
                1,
                {"index": 2},
                storage_id=storage.storage_id,
                documents=[(metadata, receipt)],
            ) == (2, 0)


def test_export_checkpoint_encrypts_operation_and_resumes_partial_import():
    operation = OperationState("export", "a" * 64, "Nip:private", "export-1", {"key": "secret"})
    checkpoint = ExportCheckpoint(ExportProgress(START), END, operation, 5, 3, "a" * 64)
    key = b"k" * 32
    encoded = json.dumps(checkpoint.encode(key)).encode()
    assert b"secret" not in encoded
    assert b"export-1" not in encoded
    assert ExportCheckpoint.decode(encoded, key) == checkpoint
    with pytest.raises(KsefDocumentValidationError, match="unreadable"):
        ExportCheckpoint.decode(encoded, b"x" * 32)
    invalid = dict(checkpoint.encode(key), version=2)
    with pytest.raises(KsefDocumentValidationError, match="unreadable"):
        ExportCheckpoint.decode(json.dumps(invalid).encode(), key)
