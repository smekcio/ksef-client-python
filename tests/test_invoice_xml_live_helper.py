from __future__ import annotations

import asyncio
import json
import time
from contextlib import nullcontext
from types import SimpleNamespace

import httpx
import pytest

from ksef_client.rate_limiting import KsefRateLimitWaitTimeout
from tests import invoice_xml_live_worker as worker
from tests.test_invoice_sync import H1, START, row
from tests.test_invoice_xml_sync import HASH, NUMBER, NUMBER2, XML, XmlServer, environment


@pytest.mark.parametrize("blocked", [False, True])
@pytest.mark.parametrize("extra", [False, True])
@pytest.mark.parametrize("delayed", [False, True])
@pytest.mark.parametrize("submitted_number", [NUMBER, NUMBER[:26] + "-" + NUMBER[26:]])
def test_live_helper_completes_both_phases_with_real_sdk_adapters(
    tmp_path, monkeypatch, blocked, extra, delayed, submitted_number
):
    async def run():
        server = XmlServer()
        original = server.handle
        visible = not delayed
        waits = 0

        def handle(request):
            # Reproduce the live failure: exact-number metadata search stays empty
            # even when the date-range scan can already observe the invoice.
            if request.method == "POST" and (
                not visible or "ksefNumber" in json.loads(request.content)
            ):
                return httpx.Response(
                    200,
                    json={
                        "invoices": [],
                        "hasMore": False,
                        "isTruncated": False,
                        "permanentStorageHwmDate": H1 if visible else "2000-01-01T00:00:00Z",
                    },
                )
            return original(request)

        monkeypatch.setattr(server, "handle", handle)
        async with environment(tmp_path, False, server) as (initial, _, __, server):
            api = initial.xml.client
            if blocked:
                server.rows.append(row("invalid-ksef-number", hash_=HASH))
            if extra:
                server.rows.insert(0, row(NUMBER2, hash_=HASH))
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
                            wait=lambda **kwargs: SimpleNamespace(ksef_number=submitted_number)
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
                nonlocal visible, waits
                if visible:
                    raise AssertionError("Helper waited despite an observable invoice")
                safe = json.loads((tmp_path / "xml-live-diagnostic.json").read_text())
                assert safe["stage"] == "observe"
                assert safe["observation"] == "hwm_before_start"
                waits += 1
                visible = True

            monkeypatch.setattr(worker, "wait_seconds", unexpected_wait)
            if blocked:
                with pytest.raises(worker.KsefXmlRunError) as caught:
                    worker.run("metadata")
                assert caught.value.xml_report.blocked == 1
                safe = worker.diagnostic(error=caught.value)
                assert safe["stage"] == "metadata"
                assert safe["reasons"] == ["invalid_ksef_number"]
                assert server.downloads == 0
                assert waits == int(delayed)
                return
            worker.run("metadata")
            assert server.downloads == 0
            worker.run("xml")
            assert server.downloads == 1 + int(extra)
            assert all(payload.get("ksefNumber") is None for payload, _, __ in server.calls)
            assert json.loads((tmp_path / "state.json").read_text())["complete"]
            assert json.loads((tmp_path / "state.json").read_text())["number"] == NUMBER
            assert waits == int(delayed)

    asyncio.run(run())


def test_live_target_lookup_is_paginated_and_normalizes_legacy_alias(tmp_path):
    async def run():
        server = XmlServer(
            [row(f"000-invalid-{index:03}", hash_=HASH) for index in range(100)]
            + [row(NUMBER, hash_=HASH)]
        )
        async with environment(tmp_path, False, server) as (sync, store, _, __):
            sync.metadata.run_once(store)
            alias = NUMBER[:26] + "-" + NUMBER[26:]
            target = worker.target_job(store, sync.xml.scopes, alias)
            assert target is not None and target["ksef_number"] == NUMBER
            assert target["status"] == "pending"
            assert worker.target_job(store, sync.xml.scopes, NUMBER2) is None

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
