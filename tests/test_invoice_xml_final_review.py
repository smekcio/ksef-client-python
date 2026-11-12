from __future__ import annotations

import asyncio
import time
from dataclasses import replace

import httpx
import pytest

from ksef_client import RetryConfig
from ksef_client.rate_limiting import KsefRateLimitWaitTimeout, KsefRequestCancelledError
from ksef_client.utils.ksef_number import validate_ksef_number
from tests.test_invoice_sync import row
from tests.test_invoice_xml_sync import HASH, NUMBER, NUMBER2, XmlServer, call, environment


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("status", [429, 502, 503, 504])
@pytest.mark.parametrize("cancelled", [False, True, "native"])
def test_interrupted_http_retry_preserves_durable_cooldown(
    tmp_path, monkeypatch, asynchronous, status, cancelled
):
    interruption: BaseException
    if cancelled == "native":
        interruption = asyncio.CancelledError()
    elif cancelled:
        interruption = KsefRequestCancelledError("cancelled")
    else:
        interruption = KsefRateLimitWaitTimeout("deadline")

    def interrupt(*args, **kwargs):
        raise interruption

    async def interrupt_async(*args, **kwargs):
        raise interruption

    monkeypatch.setattr("ksef_client.http.wait_seconds", interrupt)
    monkeypatch.setattr("ksef_client.http.wait_seconds_async", interrupt_async)

    async def run():
        async with environment(tmp_path, asynchronous) as (sync, store, storage, server):
            await call(sync.metadata.run_once, store)
            sync.xml.client._http._options = replace(
                sync.xml.client._http._options, retry=RetryConfig(max_retries=1)
            )
            server.reply = lambda request: httpx.Response(
                status, stream=httpx.ByteStream(b"{}"), headers={"Retry-After": "86400"}
            )
            if cancelled:
                with pytest.raises(type(interruption)):
                    await call(sync.xml.run_once, store, storage)
            else:
                await call(sync.xml.run_once, store, storage, max_documents=1)
            record = (await call(store.list_xml, sync.xml.scopes))[0]
            assert record["status"] == "retry_wait"
            assert record["last_reason"] == (
                "rate_limited" if status == 429 else "transient_http"
            )
            assert record["failures"] == int(status != 429)
            assert record["next_attempt_at"] >= time.time() + 86390
            assert await call(store.claim_xml, sync.xml.scopes) is None

    asyncio.run(run())


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("position", [1, 3, 9])
def test_unicode_digits_are_quarantined_without_stalling_metadata(
    tmp_path, asynchronous, position
):
    number = NUMBER[:position] + "\u0665" + NUMBER[position + 1 :]
    assert not validate_ksef_number(number).is_valid

    async def run():
        server = XmlServer([row(number, hash_=HASH), row(NUMBER2, hash_=HASH)])
        async with environment(tmp_path, asynchronous, server) as (sync, store, storage, _):
            report = await call(sync.run_once, store, storage, raise_on_error=False)
            assert report.metadata_complete
            assert report.xml.blocked == report.xml.ready == 1
            records = await call(store.list_xml, sync.xml.scopes)
            invalid = next(record for record in records if record["ksef_number"] == number)
            assert invalid["last_reason"] == "invalid_ksef_number"
            assert invalid["attempts"] == 0
            assert server.downloads == 1

    asyncio.run(run())
