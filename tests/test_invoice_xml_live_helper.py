from __future__ import annotations

import asyncio
import json
import time
from contextlib import nullcontext
from types import SimpleNamespace

from ksef_client.rate_limiting import KsefRateLimitWaitTimeout
from tests import invoice_xml_live_worker as worker
from tests.test_invoice_sync import START
from tests.test_invoice_xml_sync import NUMBER, XML, environment


def test_live_helper_completes_both_phases_with_real_sdk_adapters(tmp_path, monkeypatch):
    async def run():
        async with environment(tmp_path, False) as (initial, _, __, server):
            api = initial.xml.client
            client = SimpleNamespace(
                context_key="Nip:test",
                api=SimpleNamespace(invoices=api),
                invoices=SimpleNamespace(
                    sync_documents=lambda **kwargs: api.sync_documents(
                        context_key="Nip:test", **kwargs
                    )
                ),
                online_session=lambda: nullcontext(
                    SimpleNamespace(
                        send_invoice=lambda content: SimpleNamespace(
                            wait=lambda **kwargs: SimpleNamespace(ksef_number=NUMBER)
                        )
                    )
                ),
            )
            monkeypatch.chdir(tmp_path)
            (tmp_path / "state.json").write_text(
                json.dumps(
                    {
                        "since": START,
                        "soft_deadline": time.monotonic() + 60,
                    }
                )
            )
            monkeypatch.setattr(worker, "verify", lambda: None)
            monkeypatch.setattr(
                worker,
                "_load_test_token_config",
                lambda: SimpleNamespace(
                    token="test",
                    base_url="https://example.test/v2",
                    context_type="Nip",
                    context_value="test",
                ),
            )
            monkeypatch.setattr(worker.Ksef, "connect", lambda **kwargs: nullcontext(client))
            monkeypatch.setattr(worker, "_build_invoice_xml", lambda **kwargs: XML)

            def unexpected_wait(*args):
                raise AssertionError("Helper waited despite an observable invoice")

            monkeypatch.setattr(worker, "wait_seconds", unexpected_wait)
            worker.run("metadata")
            assert server.downloads == 0
            worker.run("xml")
            assert server.downloads == 1
            assert json.loads((tmp_path / "state.json").read_text())["complete"]

    asyncio.run(run())


def test_live_diagnostic_preserves_only_bounded_codes_and_counts(tmp_path):
    path = tmp_path / "safe.json"
    xml = SimpleNamespace(
        observed=1,
        not_enqueued=0,
        pending=0,
        leased=0,
        retry_wait=1,
        blocked=0,
        ready=0,
        reason_counts=(("not_available", 1), ("private-token", 1)),
    )
    report = SimpleNamespace(xml=xml, metadata_complete=True)
    worker.diagnostic(stage="xml", report=report, path=path)
    worker.diagnostic(error=KsefRateLimitWaitTimeout("private-response"), path=path)
    value = worker.diagnostic(path=path)
    assert value["stage"] == "xml" and value["failure"] == "deadline"
    assert value["retry_wait"] == 1 and value["metadata_complete"]
    assert value["reasons"] == ["not_available"]
    assert "private" not in json.dumps(value)
    path.write_text("not-json")
    assert worker.diagnostic(path=path)["stage"] == "unknown"
