from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import traceback
from contextlib import suppress
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from ksef_client import KsefClientOptions, redact_sensitive
from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.exceptions import (
    KsefHttpError,
    KsefIncompletePaginationError,
    KsefInvalidPaginationCursorError,
)
from ksef_client.http import AsyncBaseHttpClient, BaseHttpClient
from ksef_client.invoice_search import _dump
from ksef_client.services.hwm import update_continuation_point
from tests.test_checkpoint_example import Search, sync_pages
from tests.test_invoice_search import filters, invoice, machine, response


def test_review_cursor_with_omitted_end_survives_100_day_factory_validation(monkeypatch):
    import ksef_client.clients.invoices as clients
    import ksef_client.invoice_search as searches

    class Future(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2027, 6, 1, tzinfo=timezone.utc)

    walk = machine(end=None)
    state = walk.load(None)
    state["request"]["dateRange"]["to"] = "2026-10-02T00:00:00Z"
    cursor = _dump(state)
    monkeypatch.setattr(clients, "datetime", Future)
    monkeypatch.setattr(searches, "datetime", Future)
    http = SimpleNamespace(_options=KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl"))
    client = InvoicesClient(http)
    cast(Any, client)._query_invoice_metadata_search_page = Mock(
        return_value=response([invoice(1)])
    )
    search = client.search_invoice_metadata(filters(end=None), context_key="Nip:test", page_size=10)
    assert search.page(cursor).items[0].ksef_number == "1"
    with pytest.raises(ValueError, match="100"):
        search.page()

    async def run():
        client = AsyncInvoicesClient(http)
        cast(Any, client)._query_invoice_metadata_search_page = AsyncMock(
            return_value=response([invoice(1)])
        )
        search = client.search_invoice_metadata(
            filters(end=None), context_key="Nip:test", page_size=10
        )
        assert (await search.page(cursor)).items[0].ksef_number == "1"

    asyncio.run(run())


@pytest.mark.parametrize("order", ["Asc", "Desc"])
def test_review_issue_date_truncation_never_creates_an_unreadable_cursor(order):
    data = filters("Issue").to_dict()
    data["dateRange"]["from"] = "2026-10-01T12:00:00Z"
    from ksef_client.invoice_search import _MetadataMachine

    walk = _MetadataMachine(
        data, environment="test", context_key="nip", page_size=10, sort_order=order
    )
    page = walk.advance(walk.load(None), response([invoice(1, "2026-10-01", "Issue")], True, True))
    state = walk.load(page.next_cursor)
    page = walk.advance(state, response([invoice(1, "2026-10-01", "Issue")]))
    assert page.next_cursor is None and page.items == []


def test_review_cursor_rejects_duplicate_json_members_and_overflow_dates():
    walk = machine()
    raw = json.dumps(walk.load(None))
    duplicate = raw[:-1] + ', "offset": 1}'
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(base64.urlsafe_b64encode(duplicate.encode()).decode())
    state = walk.load(None)
    state["request"]["dateRange"]["from"] = "0001-01-01T00:00:00+14:00"
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))
    with pytest.raises(KsefIncompletePaginationError, match="invalid_invoice_date"):
        walk.advance(walk.load(None), response([invoice(1, "0001-01-01T00:00:00+14:00")]))


def test_review_redaction_bounds_width_and_masks_credential_headers():
    value = redact_sensitive(
        {
            "Cookie": "DUMMY_SECRET",
            "Proxy-Authorization": "DUMMY_SECRET",
            "X-API-Key": "DUMMY_SECRET",
        }
    )
    assert "DUMMY_SECRET" not in str(value)
    encoded_length = len(json.dumps(redact_sensitive(list(range(100000)))))
    assert encoded_length < 20000


def test_review_redaction_does_not_return_objects_with_hostile_repr():
    class Hostile(str):
        def __repr__(self):
            return "DUMMY_SECRET"

    assert "DUMMY_SECRET" not in str(redact_sensitive({"value": Hostile("safe")}))


@pytest.mark.parametrize("asynchronous", [False, True])
def test_review_transport_traceback_never_echoes_raw_exception_credentials(asynchronous):
    url = "https://storage.example.com/part?sig=DUMMY_SECRET"
    error = httpx.ConnectError(f"Unable to connect to {url}")

    def check(caught):
        assert "DUMMY_SECRET" not in str(caught)
        assert "DUMMY_SECRET" not in "".join(
            traceback.format_exception(type(caught), caught, caught.__traceback__)
        )

    options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
    if not asynchronous:
        client = BaseHttpClient(options)
        try:
            with patch.object(client._client, "request", Mock(side_effect=error)):
                try:
                    client.request("GET", url, skip_auth=True)
                except Exception as caught:
                    check(caught)
                else:
                    pytest.fail("Expected a transport failure")
        finally:
            client.close()
    else:

        async def run():
            client = AsyncBaseHttpClient(options)
            try:
                with patch.object(client._client, "request", AsyncMock(side_effect=error)):
                    try:
                        await client.request("GET", url, skip_auth=True)
                    except Exception as caught:
                        check(caught)
                    else:
                        pytest.fail("Expected a transport failure")
            finally:
                await client.aclose()

        asyncio.run(run())


def test_review_checkpoint_atomicity_with_autocommit(tmp_path):
    with sqlite3.connect(tmp_path / "autocommit.sqlite", isolation_level=None) as con:
        con.executescript("""
            CREATE TABLE checkpoints(sync_key TEXT PRIMARY KEY, cursor TEXT, completed INTEGER);
            CREATE TRIGGER crash BEFORE INSERT ON checkpoints
            BEGIN SELECT RAISE(ABORT, 'crash'); END;
        """)
        with pytest.raises(sqlite3.IntegrityError, match="crash"):
            sync_pages(con, Search(), sync_key="job")
        assert con.execute("SELECT count(*) FROM invoices").fetchone()[0] == 0


def test_review_truncated_export_must_not_advance_to_hwm_without_a_last_record():
    points: dict[str, str | None] = {"seller": "2026-10-01"}
    with pytest.raises(ValueError):
        update_continuation_point(
            points, "seller", {"isTruncated": True, "permanentStorageHwmDate": "2026-10-02"}
        )
    assert points == {"seller": "2026-10-01"}


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"hasMore": False, "isTruncated": False},
        {"hasMore": "false", "isTruncated": False, "invoices": []},
        {"hasMore": False, "isTruncated": 0, "invoices": []},
        {"hasMore": False, "isTruncated": False, "invoices": [None]},
        {"hasMore": False, "isTruncated": False, "invoices": "wrong"},
        {"hasMore": False, "isTruncated": False, "invoices": [{"grossAmount": "bad"}]},
    ],
)
@pytest.mark.parametrize("asynchronous", [False, True])
def test_review_malformed_http_metadata_can_never_claim_completion(raw, asynchronous):
    from ksef_client.http import HttpResponse

    options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
    wire = HttpResponse(200, httpx.Headers(), json.dumps(raw).encode())
    if asynchronous:

        async def run():
            http = SimpleNamespace(_options=options, request=AsyncMock(return_value=wire))
            search = AsyncInvoicesClient(http).search_invoice_metadata(filters(), context_key="nip")
            with pytest.raises(KsefIncompletePaginationError, match="invalid_response") as caught:
                await search.page()
            assert caught.value.last_cursor

        asyncio.run(run())
    else:
        http = SimpleNamespace(_options=options, request=Mock(return_value=wire))
        search = InvoicesClient(http).search_invoice_metadata(filters(), context_key="nip")
        with pytest.raises(KsefIncompletePaginationError, match="invalid_response") as caught:
            search.page()
        assert caught.value.last_cursor


@pytest.mark.parametrize("asynchronous", [False, True])
def test_review_strict_http_metadata_accepts_valid_last_page(asynchronous):
    from ksef_client.http import HttpResponse

    options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
    raw = response([invoice(1)]).to_dict()
    wire = HttpResponse(200, httpx.Headers(), json.dumps(raw).encode())
    if asynchronous:

        async def run():
            http = SimpleNamespace(_options=options, request=AsyncMock(return_value=wire))
            page = (
                await AsyncInvoicesClient(http)
                .search_invoice_metadata(filters(), context_key="nip")
                .page()
            )
            assert len(page.items) == 1 and page.next_cursor is None

        asyncio.run(run())
    else:
        http = SimpleNamespace(_options=options, request=Mock(return_value=wire))
        page = InvoicesClient(http).search_invoice_metadata(filters(), context_key="nip").page()
        assert len(page.items) == 1 and page.next_cursor is None


def test_review_legacy_cursor_environment_is_migrated_without_exposing_credentials():
    walk = machine()
    state = walk.load(None)
    state["environment"] = "https://api-test.ksef.mf.gov.pl/v2"
    restored = walk.load(_dump(state))
    assert restored["environment"].startswith("sha256:")
    from ksef_client.invoice_search import _MetadataMachine

    sensitive = _MetadataMachine(
        filters().to_dict(),
        environment="https://user:DUMMY_SECRET@example.invalid",
        context_key="nip",
        page_size=10,
        sort_order="Asc",
    )
    state = sensitive.load(None)
    assert "DUMMY_SECRET" not in json.dumps(state)
    assert "DUMMY_SECRET" not in repr(
        KsefClientOptions(base_url="https://user:DUMMY_SECRET@example.invalid")
    )


def test_review_cursor_rejects_nonfinite_json_numbers_and_overlong_dates():
    walk = machine()
    raw = json.dumps(walk.load(None)).replace('"offset": 0', '"offset": NaN')
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(base64.urlsafe_b64encode(raw.encode()).decode())
    state = walk.load(None)
    state["request"]["dateRange"]["from"] = "2026-10-01T00:00:00." + "0" * 200 + "Z"
    with pytest.raises(KsefInvalidPaginationCursorError):
        walk.load(_dump(state))


def test_review_redaction_limits_and_safe_numeric_values():
    from dataclasses import make_dataclass

    deep: Any = "deep"
    for _ in range(25):
        deep = [deep]
    assert "<depth-limit>" in str(redact_sensitive(deep))
    assert redact_sensitive(float("nan")) == "<non-finite>"
    assert redact_sensitive(2**5000) == "<large-int>"
    assert str(redact_sensitive("x" * 10000)).endswith("<truncated>")
    assert "<truncated>" in redact_sensitive({str(i): i for i in range(101)})
    assert redact_sensitive({"x" * 1000: "DUMMY_SECRET"}) == {"<long-key>": "<redacted>"}
    many = make_dataclass("Many", [(f"f{i}", int, 1) for i in range(101)])()
    assert "<truncated>" in redact_sensitive(many)
    assert "<node-limit>" in str(redact_sensitive([[i for i in range(100)] for _ in range(100)]))


def test_review_sqlite_does_not_commit_an_existing_caller_transaction(tmp_path):
    with sqlite3.connect(tmp_path / "owned.sqlite") as con:
        con.execute("CREATE TABLE caller(value TEXT)")
        con.execute("INSERT INTO caller VALUES ('pending')")
        with pytest.raises(ValueError, match="idle"):
            sync_pages(con, Search(), sync_key="test")
        con.rollback()
        assert con.execute("SELECT count(*) FROM caller").fetchone()[0] == 0


@pytest.mark.parametrize("asynchronous", [False, True])
def test_review_non_json_error_body_is_available_only_explicitly(asynchronous):
    wire = httpx.Response(500, text="DUMMY_SECRET", headers={"Content-Type": "text/plain"})
    options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
    client = AsyncBaseHttpClient(options) if asynchronous else BaseHttpClient(options)
    try:
        with pytest.raises(KsefHttpError) as caught:
            client._raise_for_status(wire)
        assert "DUMMY_SECRET" not in str(caught.value)
        assert "DUMMY_SECRET" not in str(caught.value.to_dict())
        assert caught.value.response_body == "DUMMY_SECRET"
    finally:
        if isinstance(client, AsyncBaseHttpClient):
            asyncio.run(client.aclose())
        else:
            client.close()


def test_review_presigned_url_must_not_inject_automatic_basic_auth():
    from ksef_client.http import _validate_presigned_url_security

    with pytest.raises(ValueError, match="userinfo"):
        _validate_presigned_url_security(
            KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl"),
            "https://user:DUMMY_SECRET@storage.example.com/invoice",
        )


def test_review_malformed_cursor_fuzz_always_has_a_typed_failure():
    import random

    rng = random.Random(7123)
    walk = machine()
    values: list[Any] = [None, True, False, 1, -1, 1.2, "", "bad", [], {}, {"from": []}]
    keys = list(walk.load(None))
    for _ in range(300):
        state = walk.load(None)
        state[rng.choice(keys)] = rng.choice(values)
        with suppress(KsefInvalidPaginationCursorError):
            walk.load(_dump(state))
