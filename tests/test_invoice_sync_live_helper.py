from __future__ import annotations

import asyncio
import json
import time
from contextlib import contextmanager, nullcontext
from types import SimpleNamespace

import pytest

from tests import invoice_sync_live_worker as worker
from tests.test_invoice_sync import H1, H2, START, row
from tests.test_invoice_xml_sync import HASH, NUMBER, NUMBER2, XML, XmlServer, environment


@pytest.mark.parametrize("legacy_alias", [False, True])
def test_metadata_live_helper_finalizes_session_before_discovery_and_resumes(
    tmp_path, monkeypatch, legacy_alias
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
            (tmp_path / "state.json").write_text(
                json.dumps({"since": START, "soft_deadline": time.monotonic() + 60})
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
            monkeypatch.setattr(
                worker,
                "wait_seconds",
                lambda *args: pytest.fail(
                    "Discovery must observe metadata after session finalization"
                ),
            )
            worker.run("bootstrap")
            current = "incremental"
            worker.run("incremental")
            assert events == ["close", "session_wait", "upo_wait"] * 2
            assert server.downloads == 0
            for phase in ("bootstrap", "incremental"):
                assert json.loads((tmp_path / (phase + "-evidence.json")).read_text())["complete"]
            safe = json.loads((tmp_path / "metadata-live-diagnostic.json").read_text())
            assert safe["phase"] == "incremental" and safe["stage"] == "ready"
            assert safe["metadata_streams"][0]["status"] == "completed"
            assert json.loads((tmp_path / "state.json").read_text())["a"] == NUMBER

    asyncio.run(run())
