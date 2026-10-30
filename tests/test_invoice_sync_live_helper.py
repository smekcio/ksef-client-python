from __future__ import annotations

import asyncio
import json
import math
import sqlite3
from contextlib import contextmanager, nullcontext
from types import SimpleNamespace

import httpx
import pytest

from ksef_client.rate_limiting import KsefRateLimitWaitTimeout
from tests import invoice_sync_live_worker as worker
from tests.invoice_live_clock import virtual_time
from tests.invoice_sync_supervisor import LIVE_SCENARIO_SOFT_TIMEOUT
from tests.test_invoice_sync import H1, H2, START, row
from tests.test_invoice_xml_sync import HASH, NUMBER, NUMBER2, XML, XmlServer, environment


@pytest.mark.parametrize("legacy_alias", [False, True])
@pytest.mark.parametrize("cooldown_budget", [None, 1740, LIVE_SCENARIO_SOFT_TIMEOUT])
def test_metadata_live_helper_finalizes_session_before_discovery_and_resumes(
    tmp_path, monkeypatch, legacy_alias, cooldown_budget
):
    async def run():
        server = XmlServer([])
        events: list[str] = []
        current = "bootstrap"

        def alias(number):
            return number[:26] + "-" + number[26:] if legacy_alias else number

        @contextmanager
        def online_session():
            number = NUMBER if current == "bootstrap" else NUMBER2
            date = "2025-01-01T00:00:00Z" if current == "bootstrap" else H2

            def session_wait(**kwargs):
                assert events[-1] == "close"
                events.append("session_wait")

            def upo_wait(**kwargs):
                assert events[-1] == "session_wait"
                server.rows.append(row(alias(number), date=date, hash_=HASH))
                server.hwm = H1 if current == "bootstrap" else H2
                events.append("upo_wait")
                return SimpleNamespace(pages=[object()])

            yield SimpleNamespace(
                send_invoice=lambda content: SimpleNamespace(
                    wait=lambda **kwargs: SimpleNamespace(ksef_number=number)
                ),
                wait=session_wait,
                upo=lambda: SimpleNamespace(wait=upo_wait),
            )
            events.append("close")

        async with environment(tmp_path, False, server) as (initial, _, __, ___):
            api = initial.xml.client
            client = SimpleNamespace(
                context_key="Nip:test",
                api=SimpleNamespace(invoices=api),
                invoices=SimpleNamespace(
                    sync=lambda **kwargs: api.sync(context_key="Nip:test", **kwargs)
                ),
                online_session=online_session,
            )
            monkeypatch.chdir(tmp_path)
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

            def connect(**kwargs):
                # Apply the actual helper options, including real HTTP retry.
                api._http._options = kwargs["options"]
                return nullcontext(client)

            monkeypatch.setattr(worker.Ksef, "connect", connect)
            monkeypatch.setattr(worker, "_build_invoice_xml", lambda **kwargs: XML)
            monkeypatch.setattr(
                worker,
                "wait_seconds",
                lambda *args: pytest.fail(
                    "Discovery must observe metadata after session finalization"
                ),
            )
            with virtual_time(monkeypatch) as clock:
                state_path = tmp_path / "state.json"
                state_path.write_text(
                    json.dumps({"since": START, "soft_deadline": clock() + (cooldown_budget or 60)})
                )
                original = api._http._client._transport.handler
                cooldown_until = None
                limited = []
                requests = []

                def handle(request):
                    nonlocal cooldown_until
                    if request.method == "POST":
                        lower = json.loads(request.content)["dateRange"]["from"]
                        if (
                            cooldown_budget
                            and current == "incremental"
                            and worker._date(lower) == worker._date(H1)
                        ):
                            if cooldown_until is None:
                                cooldown_until = clock() + 3600
                            requests.append(clock())
                            if clock() < cooldown_until:
                                limited.append(clock())
                                return httpx.Response(
                                    429,
                                    stream=httpx.ByteStream(b'{"title":"limited"}'),
                                    headers={
                                        "Content-Type": "application/json",
                                        "Retry-After": str(math.ceil(cooldown_until - clock())),
                                    },
                                )
                    return original(request)

                api._http._client._transport.handler = handle
                worker.run("bootstrap")
                current = "incremental"
                if cooldown_budget == 1740:
                    with pytest.raises(KsefRateLimitWaitTimeout) as caught:
                        worker.run("incremental")
                    worker.diagnostic(
                        error=caught.value, path=tmp_path / "metadata-live-diagnostic.json"
                    )
                    safe = json.loads((tmp_path / "metadata-live-diagnostic.json").read_text())
                    assert safe["metadata_http_status"] == 429
                    assert safe["metadata_streams"] == [
                        {"status": "partial", "reason": "time_budget", "pages": 0, "records": 0}
                    ]
                    with sqlite3.connect(tmp_path / "sync.db") as connection:
                        assert (
                            connection.execute("SELECT count(*) FROM invoices").fetchone()[0] == 1
                        )
                        checkpoint = json.loads(
                            connection.execute(
                                "SELECT checkpoint_json FROM sync_checkpoints"
                            ).fetchone()[0]
                        )
                        assert checkpoint["phase"] == "active"
                    assert clock() < cooldown_until
                    assert len(limited) == 1
                    return
                worker.run("incremental")
                if cooldown_budget:
                    assert cooldown_until is not None and clock() >= cooldown_until
                    assert len(limited) == 1
                    assert all(attempt >= cooldown_until for attempt in requests[1:])
            assert events == ["close", "session_wait", "upo_wait"] * 2
            assert server.downloads == 0
            for phase in ("bootstrap", "incremental"):
                assert json.loads((tmp_path / (phase + "-evidence.json")).read_text())["complete"]
            safe = json.loads((tmp_path / "metadata-live-diagnostic.json").read_text())
            assert safe["phase"] == "incremental" and safe["stage"] == "ready"
            assert safe["metadata_streams"][0]["status"] == "completed"
            assert json.loads((tmp_path / "state.json").read_text())["a"] == NUMBER

    asyncio.run(run())
