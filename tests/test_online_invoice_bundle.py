import asyncio
import hashlib
import json
import os
import zipfile

import pytest

from ksef_client.exceptions import KsefDocumentValidationError
from ksef_client.online_invoices import OnlineInvoiceQueue, SQLiteOnlineInvoiceStore
from tests.test_offline_invoice_state import NUMBER, remote_invoice
from tests.test_offline_invoice_store import KEY, XML
from tests.test_online_invoices import LOCAL_ID, Server, call, individual_upo, online


@pytest.mark.parametrize("use_async", [False, True])
def test_bundle_preserves_exact_saved_state_across_restarts(tmp_path, use_async, monkeypatch):
    server = Server()
    db = tmp_path / "online.db"
    server.lose_send = False

    def pdf(xml, *, ksef_number):
        assert xml == XML and ksef_number == NUMBER
        return b"%PDF-example"

    monkeypatch.setattr("ksef_client.invoice_pdf.render_invoice_pdf", pdf)

    async def run():
        async with online(server, db, use_async) as worker:
            with pytest.raises(KsefDocumentValidationError, match="missing"):
                await call(worker.bundle, LOCAL_ID)
            await call(worker.enqueue, LOCAL_ID, XML)
            queued = await call(worker.bundle, LOCAL_ID)
            assert queued.upo_status == "pending" and queued.upo is None
            assert queued.invoice.ksef_number is None and queued.xml == XML
            await call(worker.advance, LOCAL_ID)
            await call(worker.advance, LOCAL_ID)
            server.result = remote_invoice(200, number=NUMBER)
            await call(worker.advance, LOCAL_ID)
            pending = await call(worker.bundle, LOCAL_ID)
            assert pending.invoice.ksef_number == NUMBER and pending.upo_status == "pending"
            with pytest.raises(OSError, match="lost close"):
                await call(worker.advance, LOCAL_ID)
            await call(worker.advance, LOCAL_ID)

        async with online(server, db, use_async, namespace="other") as worker:
            with pytest.raises(KsefDocumentValidationError, match="missing"):
                await call(worker.bundle, LOCAL_ID)

        async with online(server, db, use_async) as worker:
            complete = await call(worker.bundle, LOCAL_ID)
            assert complete.upo_status == "available"
            assert complete.upo == server.upo
            assert server.open_count == server.send_count == server.close_count == 1

        for snapshot in (pending, complete):
            target = tmp_path / (snapshot.upo_status + ".zip")
            snapshot.save(target)
            assert LOCAL_ID not in repr(snapshot) and NUMBER not in repr(snapshot)
            assert XML.decode() not in repr(snapshot)
            if os.name == "posix":
                assert target.stat().st_mode & 0o077 == 0
            with zipfile.ZipFile(target) as archive:
                expected = {"invoice.xml": XML, "invoice.pdf": b"%PDF-example"}
                if snapshot is complete:
                    expected["upo.xml"] = server.upo
                assert set(archive.namelist()) == {*expected, "manifest.json"}
                manifest = json.loads(archive.read("manifest.json"))
                for name, content in expected.items():
                    assert archive.read(name) == content
                assert manifest == {
                    "version": 1,
                    "local_id": LOCAL_ID,
                    "status": snapshot.invoice.status.value,
                    "revision": snapshot.invoice.revision,
                    "ksef_status": 200,
                    "ksef_number": NUMBER,
                    "upo_status": snapshot.upo_status,
                    "sha256": {
                        name: hashlib.sha256(content).hexdigest()
                        for name, content in expected.items()
                    },
                }
            before = target.read_bytes()
            with pytest.raises(FileExistsError):
                snapshot.save(target)
            assert target.read_bytes() == before
            assert not list(tmp_path.glob(".ksef-*"))

    asyncio.run(run())


@pytest.mark.parametrize("response", [440, 450, 550])
def test_bundle_identifies_terminal_attempt_without_upo(tmp_path, response):
    async def run():
        server = Server()
        server.lose_send = False
        async with online(server, tmp_path / "db", False) as worker:
            await call(worker.enqueue, LOCAL_ID, XML)
            await call(worker.advance, LOCAL_ID)
            await call(worker.advance, LOCAL_ID)
            server.result = remote_invoice(response)
            server.session_code = 200
            await call(worker.advance, LOCAL_ID)
            result = await call(worker.bundle, LOCAL_ID)
            assert result.upo_status == "unavailable" and result.upo is None
            assert result.invoice.ksef_number is None and result.invoice.ksef_status == response

    asyncio.run(run())


def test_bundle_checks_content_before_exporting(tmp_path, monkeypatch):
    server = Server()
    with SQLiteOnlineInvoiceStore.open(tmp_path / "db", key=KEY) as store:
        queue = OnlineInvoiceQueue(
            store, namespace="test", environment=server.environment, context_key=server.context_key
        )
        queue.enqueue(LOCAL_ID, XML)
        with monkeypatch.context() as patch:
            patch.setattr(store, "read_xml", lambda *_: b"<other/>")
            with pytest.raises(KsefDocumentValidationError, match="XML"):
                queue.bundle(LOCAL_ID)
        scope = queue._scope
        row = store._load_online(scope, LOCAL_ID)
        assert row is not None
        opened = store._advance(scope, row, row.progress.open_session("session-1"))
        pending = store._advance(scope, opened, opened.progress.begin_submission())
        accepted = store._advance(
            scope, pending, pending.progress.observe(remote_invoice(200, number=NUMBER))
        )
        store._advance(
            scope, accepted, accepted.progress.confirm_upo(), upo=individual_upo(session="other")
        )
        with pytest.raises(KsefDocumentValidationError, match="does not identify"):
            queue.bundle(LOCAL_ID)
