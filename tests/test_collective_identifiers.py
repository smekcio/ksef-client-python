from __future__ import annotations

import unittest
from decimal import Decimal
from unittest.mock import AsyncMock, Mock, patch

from ksef_client import models as m
from ksef_client.clients.collective_identifiers import (
    AsyncCollectiveIdentifiersClient,
    CollectiveIdentifiersClient,
)
from ksef_client.utils.collective_identifier import (
    MAX_INVOICE_DESCRIPTION_LENGTH,
    MAX_INVOICES_PER_IDENTIFIER,
    expand_query_date_bound,
    make_collective_identifier_invoice,
    require_generate_invoices,
    require_page_size,
    require_query_date_range,
)

_KSEF = "5265877635-20250826-0100001AF629-AF"
_IZ = "1111111111-IZ202607-65ED02180000-E7"


def _invoice(ksef_number: str = _KSEF) -> m.CollectiveIdentifierInvoice:
    return make_collective_identifier_invoice(ksef_number)


def _query_item(number: str = _IZ) -> m.CollectiveIdentifiersQueryResponseItem:
    return m.CollectiveIdentifiersQueryResponseItem(
        collective_identifier_number=number,
        created_in_current_context=True,
        date_created="2026-07-01T00:00:00Z",
        invoice_count=1,
    )


def _invoice_item() -> m.CollectiveIdentifierInvoicesQueryResponseItem:
    return m.CollectiveIdentifierInvoicesQueryResponseItem(
        details_hidden=False,
        ksef_number=_KSEF,
    )


class CollectiveIdentifierDomainTests(unittest.TestCase):
    def test_factory_decimal_amount(self) -> None:
        item = make_collective_identifier_invoice(
            _KSEF,
            description="batch",
            amount=Decimal("150.00"),
            currency="PLN",
        )
        self.assertEqual(item.ksef_number, _KSEF)
        self.assertIsNotNone(item.payment)
        assert item.payment is not None
        self.assertEqual(item.payment.amount, 150.0)
        self.assertEqual(item.payment.currency, m.CurrencyCode.PLN)

    def test_factory_rejects_invalid_ksef(self) -> None:
        with self.assertRaises(ValueError):
            make_collective_identifier_invoice("bad-ksef")

    def test_factory_requires_amount_and_currency_together(self) -> None:
        with self.assertRaises(ValueError):
            make_collective_identifier_invoice(_KSEF, amount=Decimal("1.00"))
        with self.assertRaises(ValueError):
            make_collective_identifier_invoice(_KSEF, currency="PLN")

    def test_factory_rejects_long_description(self) -> None:
        with self.assertRaises(ValueError):
            make_collective_identifier_invoice(
                _KSEF,
                description="x" * (MAX_INVOICE_DESCRIPTION_LENGTH + 1),
            )

    def test_require_generate_invoices_empty_and_too_many(self) -> None:
        with self.assertRaises(ValueError):
            require_generate_invoices([])
        with self.assertRaises(ValueError):
            require_generate_invoices([_invoice() for _ in range(MAX_INVOICES_PER_IDENTIFIER + 1)])

    def test_require_generate_invoices_duplicates(self) -> None:
        with self.assertRaises(ValueError):
            require_generate_invoices([_invoice(), _invoice()])

    def test_query_date_range_limits(self) -> None:
        require_query_date_range("2026-01-01", "2026-04-11")
        with self.assertRaises(ValueError):
            require_query_date_range("2026-04-11", "2026-01-01")
        with self.assertRaises(ValueError):
            require_query_date_range("2026-01-01", "2026-04-12")

    def test_page_size_bounds(self) -> None:
        self.assertEqual(require_page_size(10), 10)
        self.assertEqual(require_page_size(200), 200)
        with self.assertRaises(ValueError):
            require_page_size(9)
        with self.assertRaises(ValueError):
            require_page_size(201)

    def test_factory_accepts_enum_currency_and_int_amount(self) -> None:
        item = make_collective_identifier_invoice(
            _KSEF,
            amount=150,
            currency=m.CurrencyCode.PLN,
        )
        assert item.payment is not None
        self.assertEqual(item.payment.amount, 150.0)
        self.assertEqual(item.payment.currency, m.CurrencyCode.PLN)

    def test_factory_rejects_invalid_amount(self) -> None:
        with self.assertRaises(ValueError):
            make_collective_identifier_invoice(_KSEF, amount="not-a-number", currency="PLN")

    def test_require_generate_invoices_rejects_long_description_on_model(self) -> None:
        invoice = m.CollectiveIdentifierInvoice(
            ksef_number=_KSEF,
            description="x" * (MAX_INVOICE_DESCRIPTION_LENGTH + 1),
        )
        with self.assertRaises(ValueError):
            require_generate_invoices([invoice])

    def test_query_date_range_invalid_and_naive_datetimes(self) -> None:
        with self.assertRaises(ValueError):
            require_query_date_range("", "2026-01-02")
        with self.assertRaises(ValueError):
            require_query_date_range("nope", "2026-01-02")
        require_query_date_range("2026-01-01T00:00:00", "2026-01-02T00:00:00")

    def test_expand_query_date_bound_passthrough(self) -> None:
        value = "2026-01-01T12:00:00Z"
        self.assertEqual(expand_query_date_bound(value, end_of_day=True), value)
        self.assertEqual(expand_query_date_bound(value, end_of_day=False), value)


class CollectiveIdentifiersClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = CollectiveIdentifiersClient(http_client=Mock())

    def test_generate_for_ksef_numbers_builds_payload(self) -> None:
        with patch.object(
            self.client, "_request_model", Mock(return_value=object())
        ) as request_model:
            self.client.generate_for_ksef_numbers(
                [_KSEF],
                access_token="token",
                descriptions=["batch"],
            )
        payload = request_model.call_args.kwargs["json"]
        self.assertIsInstance(payload, m.GenerateCollectiveIdentifierRequest)
        self.assertEqual(payload.invoices[0].ksef_number, _KSEF)
        self.assertEqual(payload.invoices[0].description, "batch")

    def test_generate_for_ksef_numbers_rejects_description_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            self.client.generate_for_ksef_numbers(
                [_KSEF],
                access_token="token",
                descriptions=["a", "b"],
            )

    def test_query_by_created_range_expands_dates(self) -> None:
        with patch.object(
            self.client, "_request_model", Mock(return_value=object())
        ) as request_model:
            self.client.query_by_created_range(
                "2026-01-01",
                "2026-01-31",
                access_token="token",
            )
        payload = request_model.call_args.kwargs["json"]
        self.assertEqual(payload.date_created_from, "2026-01-01T00:00:00Z")
        self.assertEqual(payload.date_created_to, "2026-01-31T23:59:59Z")

    def test_list_invoices_uses_get_single_iz_path(self) -> None:
        with patch.object(
            self.client, "_request_model", Mock(return_value=object())
        ) as request_model:
            self.client.list_invoices(_IZ, access_token="token", page_size=10)
        self.assertEqual(request_model.call_args.args[0], "GET")
        self.assertEqual(
            request_model.call_args.args[1],
            f"/collective-identifiers/{_IZ}/invoices",
        )

    def test_list_invoices_rejects_invalid_page_size(self) -> None:
        with self.assertRaises(ValueError):
            self.client.list_invoices(_IZ, access_token="token", page_size=5)

    def test_iter_query_follows_token_and_stops_on_repeat(self) -> None:
        first = _query_item("1111111111-IZ202607-65ED02180000-E7")
        second = _query_item("1111111111-IZ202607-65ED02180000-E7")
        pages = [
            m.CollectiveIdentifiersQueryResponse(
                collective_identifiers=[first],
                continuation_token="t1",
            ),
            m.CollectiveIdentifiersQueryResponse(
                collective_identifiers=[second],
                continuation_token="t1",
            ),
        ]
        with patch.object(self.client, "query", Mock(side_effect=pages)) as query:
            request = m.CollectiveIdentifiersQueryRequest(
                date_created_from="2026-01-01T00:00:00Z",
                date_created_to="2026-01-31T23:59:59Z",
            )
            items = list(self.client.iter_query(request, access_token="token"))
        self.assertEqual(items, [first, second])
        self.assertEqual(query.call_count, 2)

    def test_iter_invoices_stops_without_token(self) -> None:
        page = m.CollectiveIdentifierInvoicesQueryResponse(
            invoices=[_invoice_item()],
            continuation_token=None,
        )
        with patch.object(self.client, "list_invoices", Mock(return_value=page)):
            items = list(self.client.iter_invoices(_IZ, access_token="token"))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].ksef_number, _KSEF)

    def test_iter_invoices_stops_on_repeated_token(self) -> None:
        item = _invoice_item()
        pages = [
            m.CollectiveIdentifierInvoicesQueryResponse(
                invoices=[item],
                continuation_token="t1",
            ),
            m.CollectiveIdentifierInvoicesQueryResponse(
                invoices=[item],
                continuation_token="t1",
            ),
        ]
        with patch.object(self.client, "list_invoices", Mock(side_effect=pages)):
            items = list(self.client.iter_invoices(_IZ, access_token="token"))
        self.assertEqual(items, [item, item])

    def test_iter_by_ksef_number_follows_pages(self) -> None:
        item = m.CollectiveIdentifiersByKsefNumberQueryResponseItem(
            collective_identifier_number=_IZ,
            created_in_current_context=True,
            date_created="2026-07-01T00:00:00Z",
        )
        pages = [
            m.CollectiveIdentifiersByKsefNumberQueryResponse(
                collective_identifiers=[item],
                continuation_token="next",
            ),
            m.CollectiveIdentifiersByKsefNumberQueryResponse(
                collective_identifiers=[],
                continuation_token=None,
            ),
        ]
        with patch.object(self.client, "list_by_ksef_number", Mock(side_effect=pages)):
            items = list(self.client.iter_by_ksef_number(_KSEF, access_token="token"))
        self.assertEqual(items, [item])

    def test_query_validates_optional_collective_identifier(self) -> None:
        with self.assertRaises(ValueError):
            self.client.query(
                m.CollectiveIdentifiersQueryRequest(
                    date_created_from="2026-01-01T00:00:00Z",
                    date_created_to="2026-01-31T23:59:59Z",
                    collective_identifier_number="bad-iz",
                ),
                access_token="token",
            )
        with patch.object(self.client, "_request_model", Mock(return_value=object())):
            self.client.query(
                m.CollectiveIdentifiersQueryRequest(
                    date_created_from="2026-01-01T00:00:00Z",
                    date_created_to="2026-01-31T23:59:59Z",
                    collective_identifier_number=_IZ,
                ),
                access_token="token",
            )

    def test_query_by_created_range_with_filters(self) -> None:
        with patch.object(
            self.client, "_request_model", Mock(return_value=object())
        ) as request_model:
            self.client.query_by_created_range(
                "2026-01-01T00:00:00Z",
                "2026-01-31T23:59:59Z",
                access_token="token",
                collective_identifier_number=_IZ,
                created_in_current_context=True,
                invoice_count_from=1,
                invoice_count_to=10,
                continuation_token="next",
            )
        payload = request_model.call_args.kwargs["json"]
        self.assertEqual(payload.collective_identifier_number, _IZ)
        self.assertTrue(payload.created_in_current_context)
        self.assertEqual(
            request_model.call_args.kwargs["headers"],
            {"x-continuation-token": "next"},
        )

    def test_query_by_created_range_rejects_invalid_iz(self) -> None:
        with self.assertRaises(ValueError):
            self.client.query_by_created_range(
                "2026-01-01",
                "2026-01-31",
                access_token="token",
                collective_identifier_number="bad-iz",
            )

    def test_generate_for_ksef_numbers_without_descriptions(self) -> None:
        with patch.object(self.client, "_request_model", Mock(return_value=object())):
            self.client.generate_for_ksef_numbers([_KSEF], access_token="token")


class AsyncCollectiveIdentifiersClientTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.client = AsyncCollectiveIdentifiersClient(http_client=Mock())

    async def test_generate_for_ksef_numbers(self) -> None:
        with patch.object(
            self.client, "_request_model", AsyncMock(return_value=object())
        ) as request_model:
            await self.client.generate_for_ksef_numbers([_KSEF], access_token="token")
            await self.client.generate_for_ksef_numbers(
                [_KSEF],
                access_token="token",
                descriptions=["batch"],
            )
        payload = request_model.call_args.kwargs["json"]
        self.assertEqual(payload.invoices[0].description, "batch")

    async def test_generate_for_ksef_numbers_rejects_description_mismatch(self) -> None:
        with self.assertRaises(ValueError):
            await self.client.generate_for_ksef_numbers(
                [_KSEF],
                access_token="token",
                descriptions=["a", "b"],
            )

    async def test_query_by_created_range_and_iterators(self) -> None:
        query_item = _query_item()
        invoice_item = _invoice_item()
        by_ksef_item = m.CollectiveIdentifiersByKsefNumberQueryResponseItem(
            collective_identifier_number=_IZ,
            created_in_current_context=True,
            date_created="2026-07-01T00:00:00Z",
        )
        query_pages = [
            m.CollectiveIdentifiersQueryResponse(
                collective_identifiers=[query_item],
                continuation_token="t1",
            ),
            m.CollectiveIdentifiersQueryResponse(
                collective_identifiers=[query_item],
                continuation_token="t1",
            ),
        ]
        invoice_page = m.CollectiveIdentifierInvoicesQueryResponse(
            invoices=[invoice_item],
            continuation_token=None,
        )
        by_ksef_pages = [
            m.CollectiveIdentifiersByKsefNumberQueryResponse(
                collective_identifiers=[by_ksef_item],
                continuation_token="next",
            ),
            m.CollectiveIdentifiersByKsefNumberQueryResponse(
                collective_identifiers=[],
                continuation_token=None,
            ),
        ]
        with patch.object(
            self.client, "_request_model", AsyncMock(return_value=object())
        ) as request_model:
            await self.client.query_by_created_range(
                "2026-01-01",
                "2026-01-31",
                access_token="token",
                collective_identifier_number=_IZ,
                created_in_current_context=False,
                invoice_count_from=1,
                invoice_count_to=2,
            )
            await self.client.list_invoices(_IZ, access_token="token", page_size=10)
            await self.client.list_by_ksef_number(_KSEF, access_token="token", page_size=10)
        self.assertEqual(
            request_model.call_args_list[0].kwargs["json"].date_created_from,
            "2026-01-01T00:00:00Z",
        )

        request = m.CollectiveIdentifiersQueryRequest(
            date_created_from="2026-01-01T00:00:00Z",
            date_created_to="2026-01-31T23:59:59Z",
        )
        with patch.object(self.client, "query", AsyncMock(side_effect=query_pages)):
            items = [item async for item in self.client.iter_query(request, access_token="token")]
        self.assertEqual(items, [query_item, query_item])

        with patch.object(self.client, "list_invoices", AsyncMock(return_value=invoice_page)):
            invoices = [item async for item in self.client.iter_invoices(_IZ, access_token="token")]
        self.assertEqual(invoices, [invoice_item])

        invoice_repeat = [
            m.CollectiveIdentifierInvoicesQueryResponse(
                invoices=[invoice_item],
                continuation_token="dup",
            ),
            m.CollectiveIdentifierInvoicesQueryResponse(
                invoices=[invoice_item],
                continuation_token="dup",
            ),
        ]
        with patch.object(self.client, "list_invoices", AsyncMock(side_effect=invoice_repeat)):
            invoices = [item async for item in self.client.iter_invoices(_IZ, access_token="token")]
        self.assertEqual(invoices, [invoice_item, invoice_item])

        with patch.object(self.client, "list_by_ksef_number", AsyncMock(side_effect=by_ksef_pages)):
            found = [
                item async for item in self.client.iter_by_ksef_number(_KSEF, access_token="token")
            ]
        self.assertEqual(found, [by_ksef_item])

    async def test_generate_and_query_thin_methods(self) -> None:
        payload = m.GenerateCollectiveIdentifierRequest(invoices=[_invoice()])
        query = m.CollectiveIdentifiersQueryRequest(
            date_created_from="2026-01-01T00:00:00Z",
            date_created_to="2026-01-31T23:59:59Z",
            collective_identifier_number=_IZ,
        )
        with patch.object(self.client, "_request_model", AsyncMock(return_value=object())):
            await self.client.generate(payload, access_token="token")
            await self.client.query(query, access_token="token", continuation_token="c1")


if __name__ == "__main__":
    unittest.main()
