import base64
import json
import os
import sqlite3
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from tests.test_invoice_export_package import END, NUMBER, START, XML, package
from tests.test_invoice_export_sync import Client, Export

from ksef_client import Ksef
from ksef_client.cli import app
from ksef_client.cli.commands import archive_cmd, archive_delivery
from ksef_client.cli.exit_codes import ExitCode
from ksef_client.facade import Exports
from ksef_client.invoice_xml_types import KsefXmlStorageError
from ksef_client.operations import environment_key


@pytest.fixture
def archive(runner, tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()

    class OneInvoiceExport(Export):
        def download_to(self, destination, **kwargs):
            destination.mkdir()
            return package(destination, numbers=(NUMBER,))

    class OneInvoiceClient(Client):
        def start(self, filters, **kwargs):
            return OneInvoiceExport(self, super().start(filters, **kwargs).resume_state())

    client = OneInvoiceClient(package(source, numbers=(NUMBER,)).package)
    client.environment = environment_key("https://api-demo.ksef.mf.gov.pl/v2")
    client.context_key = "Nip:123"
    client.exports.sync_archive = Exports(cast(Ksef, client)).sync_archive
    monkeypatch.setenv("KSEF_EXPORT_STATE_KEY", base64.b64encode(bytes(range(32))).decode())
    monkeypatch.setattr("ksef_client.invoice_export_sync.ExportOperation", OneInvoiceExport)
    monkeypatch.setattr(archive_cmd, "workflow_client", lambda *args: nullcontext(client))
    root = tmp_path / "private"

    def invoke(command, *args, code=0, human=False):
        result = runner.invoke(
            app,
            [*([] if human else ["--json"]), "archive", command, "--state-dir", str(root), *args],
        )
        assert result.exit_code == code, (result.output, result.exception)
        if human:
            return result.output
        payload = json.loads(result.output)
        return payload["data"] if code == 0 else payload["errors"][0]

    invoke("next", "--consumer", "x", "--out", str(tmp_path), code=ExitCode.CONFIG_ERROR)
    invoke("sync", "--since", START, "--until", END)
    # The next three commands must work after logout and without the export encryption key.
    monkeypatch.delenv("KSEF_EXPORT_STATE_KEY")
    monkeypatch.setattr(
        archive_cmd, "workflow_client", lambda *args: pytest.fail("unexpected login")
    )
    return invoke, root


def test_independent_consumers_and_cross_process_ack_retry(archive, tmp_path):
    invoke, root = archive
    common = ["--consumer", "imports", "--out", str(tmp_path / "hand-off")]
    claimed = invoke("next", *common)
    assert claimed["available"] and Path(claimed["xml"]).read_bytes() == XML
    assert json.loads(Path(claimed["metadata"]).read_bytes())["ksefNumber"] == NUMBER
    if os.name == "posix":
        assert all(
            Path(claimed[key]).stat().st_mode & 0o077 == 0 for key in ("xml", "metadata", "receipt")
        )
    receipt = json.loads(Path(claimed["receipt"]).read_bytes())
    assert receipt["token"] not in json.dumps(claimed)
    assert invoke("next", *common) == {"available": False}
    assert "No purchase invoice" in invoke("next", *common, human=True)
    other = invoke("next", "--consumer", "audit", "--out", str(tmp_path / "hand-off"))
    assert other["event_id"] == claimed["event_id"] and other["receipt"] != claimed["receipt"]
    invoke("retry", "--receipt", claimed["receipt"], "--delay-seconds", "60")
    assert not invoke("next", *common)["available"]
    with sqlite3.connect(next(root.rglob("invoices.db"))) as db:
        db.execute("UPDATE incoming_invoice_delivery SET available_at=0 WHERE consumer='imports'")
    repeated = invoke("next", *common)
    assert repeated["event_id"] == claimed["event_id"]
    assert repeated["receipt"] != claimed["receipt"]
    assert (
        "no longer current"
        in invoke("ack", "--receipt", claimed["receipt"], code=ExitCode.VALIDATION_ERROR)["message"]
    )
    assert invoke("ack", "--receipt", repeated["receipt"])["acknowledged"]
    assert invoke("ack", "--receipt", repeated["receipt"])["acknowledged"]
    assert not invoke("next", *common)["available"]
    assert "acknowledged" in invoke("ack", "--receipt", other["receipt"], human=True)
    assert "archive ack --receipt" in invoke(
        "next", "--consumer", "files", "--out", str(tmp_path), human=True
    )
    replay = invoke("next", "--consumer", "notifications", "--out", str(tmp_path))
    assert "released" in invoke("retry", "--receipt", replay["receipt"], human=True)


def test_failed_publication_releases_claim_and_preserves_existing_output(
    archive, tmp_path, monkeypatch
):
    invoke, _ = archive
    target = tmp_path / "delivery"
    target.mkdir()
    sentinel = target / "invoice.xml"
    sentinel.write_bytes(b"existing")
    common = ["--consumer", "imports", "--out", str(target)]

    def fail(*args, **kwargs):
        raise OSError("disk full")

    with monkeypatch.context() as patch:
        patch.setattr(archive_delivery, "publish_directory", fail)
        invoke("next", *common, code=ExitCode.IO_ERROR)
    assert list(target.iterdir()) == [sentinel]
    assert invoke("next", *common)["available"] and sentinel.read_bytes() == b"existing"


def test_rejects_damaged_and_foreign_receipts(archive, tmp_path):
    invoke, _ = archive
    claim = invoke("next", "--consumer", "test", "--out", str(tmp_path))
    wrong = tmp_path / "wrong.json"
    data = json.loads(Path(claim["receipt"]).read_bytes())
    wrong.write_text(
        json.dumps({**data, "key": {**data["key"], "namespace": "other"}}), encoding="utf-8"
    )
    assert (
        "different profile"
        in invoke("ack", "--receipt", str(wrong), code=ExitCode.VALIDATION_ERROR)["message"]
    )
    for content in (
        b"{",
        b" " * 65537,
        b'{"version":true}',
        b'{"version":1,' + json.dumps(data).encode()[1:],
        json.dumps({**data, "token": "invalid"}).encode(),
        json.dumps({**data, "key": []}).encode(),
    ):
        wrong.write_bytes(content)
        assert (
            "Invalid delivery receipt"
            in invoke("retry", "--receipt", str(wrong), code=ExitCode.VALIDATION_ERROR)["message"]
        )
    invoke("ack", "--receipt", claim["receipt"])


def test_claim_requires_original_xml_store_but_ack_can_finish_without_it(archive, tmp_path):
    invoke, root = archive
    common = ["--consumer", "imports", "--out", str(tmp_path)]
    claim = invoke("next", *common)
    xml_dir = next(root.rglob("invoices.db")).parent / "xml"
    xml_dir.rename(xml_dir.with_name("archived-xml"))
    assert "original XML" in invoke("next", *common, code=ExitCode.IO_ERROR)["message"]
    assert not xml_dir.exists()
    assert invoke("ack", "--receipt", claim["receipt"])["acknowledged"]


def test_expired_receipt_cannot_finish_a_new_delivery(archive, tmp_path, monkeypatch):
    invoke, _ = archive
    now = 1000
    monkeypatch.setattr("ksef_client.sqlite_store.time", SimpleNamespace(time=lambda: now))
    args = ["--consumer", "ledger", "--out", str(tmp_path), "--lease-seconds", "2"]
    first = invoke("next", *args)
    now += 2
    invoke("ack", "--receipt", first["receipt"], code=ExitCode.VALIDATION_ERROR)
    second = invoke("next", *args)
    assert second["event_id"] == first["event_id"] and second["receipt"] != first["receipt"]
    invoke("retry", "--receipt", first["receipt"], code=ExitCode.VALIDATION_ERROR)
    assert invoke("ack", "--receipt", second["receipt"])["acknowledged"]


@pytest.mark.parametrize("change", ["during_read", "expired", "fenced", "rename_retry"])
def test_lease_is_rechecked_at_publication(archive, tmp_path, monkeypatch, change):
    invoke, root = archive
    now = 1000
    monkeypatch.setattr("ksef_client.sqlite_store.time", SimpleNamespace(time=lambda: now))
    out = tmp_path / "worker-output"
    args = ["--consumer", "worker", "--out", str(out), "--lease-seconds", "2"]
    write_file = archive_delivery.write_private_file
    rename = Path.rename
    read_xml = archive_delivery.FileInvoiceXmlStore.read

    def read(storage, *args, **kwargs):
        nonlocal now
        xml = read_xml(storage, *args, **kwargs)
        if change == "during_read":
            now += 2
        return xml

    def stage(path, content, **options):
        nonlocal now
        write_file(path, content, **options)
        if path.name == "receipt.json":
            if change == "expired":
                now += 2
            elif change == "fenced":
                with archive_delivery.SQLiteInvoiceSyncStore.open(
                    next(root.rglob("invoices.db"))
                ) as store:
                    store.fence_workers()

    def retry_rename(path, target):
        nonlocal now
        if change == "rename_retry" and path.name.startswith(".ksef-delivery-"):
            now += 2
            raise PermissionError("busy")
        return rename(path, target)

    with monkeypatch.context() as patch:
        patch.setattr(archive_delivery, "write_private_file", stage)
        patch.setattr(archive_delivery.FileInvoiceXmlStore, "read", read)
        patch.setattr(Path, "rename", retry_rename)
        err = invoke("next", *args, code=ExitCode.RETRY_EXHAUSTED)
    assert "reservation" in err["message"]
    assert not out.exists() or list(out.iterdir()) == []
    current = invoke("next", *args)
    assert invoke("ack", "--receipt", current["receipt"])["acknowledged"]


def test_missing_store_identity_is_not_replaced_by_a_read(archive, tmp_path):
    invoke, root = archive
    marker = next(root.rglob("invoices.db")).parent / "xml" / ".storage-id"
    original = marker.with_name("saved-id")
    marker.rename(original)
    args = ["--consumer", "imports", "--out", str(tmp_path)]
    invoke("next", *args, code=ExitCode.IO_ERROR)
    assert not marker.exists()
    original.rename(marker)
    assert invoke("next", *args)["available"]


def test_archive_database_must_have_a_single_journal_location(archive, tmp_path):
    _, root = archive
    database = next(root.rglob("invoices.db"))
    alias = tmp_path / "second.db"
    os.link(database, alias)
    with pytest.raises(KsefXmlStorageError):
        archive_delivery.SQLiteInvoiceSyncStore.open(alias)
