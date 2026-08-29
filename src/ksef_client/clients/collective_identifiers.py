from __future__ import annotations

from collections.abc import AsyncIterator, Iterator, Sequence
from typing import Any

from ..models import (
    CollectiveIdentifierInvoice,
    CollectiveIdentifierInvoicesQueryRequest,
    CollectiveIdentifierInvoicesQueryResponse,
    CollectiveIdentifierInvoicesQueryResponseItem,
    CollectiveIdentifiersByKsefNumberQueryResponse,
    CollectiveIdentifiersByKsefNumberQueryResponseItem,
    CollectiveIdentifiersQueryRequest,
    CollectiveIdentifiersQueryResponse,
    CollectiveIdentifiersQueryResponseItem,
    GenerateCollectiveIdentifierRequest,
    GenerateCollectiveIdentifierResponse,
)
from ..utils.collective_identifier import (
    PAGE_SIZE_INVOICES_MAX,
    PAGE_SIZE_MAX,
    expand_query_date_bound,
    make_collective_identifier_invoice,
    require_collective_identifier_number,
    require_generate_invoices,
    require_invoices_query_identifiers,
    require_page_size,
    require_query_date_range,
)
from ..utils.ksef_number import require_ksef_number
from .base import AsyncBaseApiClient, BaseApiClient


def _page_request(
    page_size: int | None,
    continuation_token: str | None,
    *,
    page_size_max: int = PAGE_SIZE_MAX,
) -> tuple[dict[str, Any] | None, dict[str, str] | None]:
    if page_size is not None:
        page_size = require_page_size(page_size, maximum=page_size_max)
    params: dict[str, Any] = {}
    if page_size is not None:
        params["pageSize"] = page_size
    headers: dict[str, str] = {}
    if continuation_token:
        headers["x-continuation-token"] = continuation_token
    return params or None, headers or None


def _validate_query_request(
    request_payload: CollectiveIdentifiersQueryRequest,
) -> CollectiveIdentifiersQueryRequest:
    require_query_date_range(
        request_payload.date_created_from,
        request_payload.date_created_to,
    )
    if request_payload.collective_identifier_number:
        require_collective_identifier_number(request_payload.collective_identifier_number)
    return request_payload


def _build_query_request(
    date_from: str,
    date_to: str,
    *,
    collective_identifier_number: str | None = None,
    created_in_current_context: bool | None = None,
    invoice_count_from: int | None = None,
    invoice_count_to: int | None = None,
) -> CollectiveIdentifiersQueryRequest:
    expanded_from = expand_query_date_bound(date_from, end_of_day=False)
    expanded_to = expand_query_date_bound(date_to, end_of_day=True)
    if collective_identifier_number:
        collective_identifier_number = require_collective_identifier_number(
            collective_identifier_number
        )
    require_query_date_range(expanded_from, expanded_to)
    return CollectiveIdentifiersQueryRequest(
        date_created_from=expanded_from,
        date_created_to=expanded_to,
        collective_identifier_number=collective_identifier_number,
        created_in_current_context=created_in_current_context,
        invoice_count_from=invoice_count_from,
        invoice_count_to=invoice_count_to,
    )


def _build_generate_request(
    ksef_numbers: Sequence[str],
    descriptions: Sequence[str | None] | None,
) -> GenerateCollectiveIdentifierRequest:
    numbers = list(ksef_numbers)
    if descriptions is not None and len(descriptions) != len(numbers):
        raise ValueError("descriptions length must match ksef_numbers")
    invoices: list[CollectiveIdentifierInvoice] = []
    for index, ksef_number in enumerate(numbers):
        description = None if descriptions is None else descriptions[index]
        invoices.append(make_collective_identifier_invoice(ksef_number, description=description))
    return GenerateCollectiveIdentifierRequest(invoices=require_generate_invoices(invoices))


class CollectiveIdentifiersClient(BaseApiClient):
    def generate(
        self,
        request_payload: GenerateCollectiveIdentifierRequest,
        *,
        access_token: str,
    ) -> GenerateCollectiveIdentifierResponse:
        require_generate_invoices(request_payload.invoices)
        return self._request_model(
            "POST",
            "/collective-identifiers",
            response_model=GenerateCollectiveIdentifierResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={201},
        )

    def generate_for_ksef_numbers(
        self,
        ksef_numbers: Sequence[str],
        *,
        access_token: str,
        descriptions: Sequence[str | None] | None = None,
    ) -> GenerateCollectiveIdentifierResponse:
        return self.generate(
            _build_generate_request(ksef_numbers, descriptions),
            access_token=access_token,
        )

    def query(
        self,
        request_payload: CollectiveIdentifiersQueryRequest,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersQueryResponse:
        _validate_query_request(request_payload)
        params, headers = _page_request(page_size, continuation_token)
        return self._request_model(
            "POST",
            "/collective-identifiers/query",
            response_model=CollectiveIdentifiersQueryResponse,
            json=request_payload,
            params=params,
            headers=headers,
            access_token=access_token,
        )

    def query_by_created_range(
        self,
        date_from: str,
        date_to: str,
        *,
        access_token: str,
        collective_identifier_number: str | None = None,
        created_in_current_context: bool | None = None,
        invoice_count_from: int | None = None,
        invoice_count_to: int | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersQueryResponse:
        return self.query(
            _build_query_request(
                date_from,
                date_to,
                collective_identifier_number=collective_identifier_number,
                created_in_current_context=created_in_current_context,
                invoice_count_from=invoice_count_from,
                invoice_count_to=invoice_count_to,
            ),
            access_token=access_token,
            page_size=page_size,
            continuation_token=continuation_token,
        )

    def iter_query(
        self,
        request_payload: CollectiveIdentifiersQueryRequest,
        *,
        access_token: str,
        page_size: int | None = None,
    ) -> Iterator[CollectiveIdentifiersQueryResponseItem]:
        continuation_token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            response = self.query(
                request_payload,
                access_token=access_token,
                page_size=page_size,
                continuation_token=continuation_token,
            )
            yield from response.collective_identifiers
            continuation_token = response.continuation_token
            if not continuation_token or continuation_token in seen_tokens:
                return
            seen_tokens.add(continuation_token)

    def list_invoices(
        self,
        collective_identifier_numbers: str | Sequence[str],
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifierInvoicesQueryResponse:
        numbers = require_invoices_query_identifiers(collective_identifier_numbers)
        params, headers = _page_request(
            page_size,
            continuation_token,
            page_size_max=PAGE_SIZE_INVOICES_MAX,
        )
        return self._request_model(
            "POST",
            "/collective-identifiers/invoices",
            response_model=CollectiveIdentifierInvoicesQueryResponse,
            json=CollectiveIdentifierInvoicesQueryRequest(
                collective_identifier_numbers=numbers,
            ),
            params=params,
            headers=headers,
            access_token=access_token,
        )

    def iter_invoices(
        self,
        collective_identifier_numbers: str | Sequence[str],
        *,
        access_token: str,
        page_size: int | None = None,
    ) -> Iterator[CollectiveIdentifierInvoicesQueryResponseItem]:
        continuation_token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            response = self.list_invoices(
                collective_identifier_numbers,
                access_token=access_token,
                page_size=page_size,
                continuation_token=continuation_token,
            )
            yield from response.invoices
            continuation_token = response.continuation_token
            if not continuation_token or continuation_token in seen_tokens:
                return
            seen_tokens.add(continuation_token)

    def list_by_ksef_number(
        self,
        ksef_number: str,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersByKsefNumberQueryResponse:
        ksef_number = require_ksef_number(ksef_number)
        params, headers = _page_request(page_size, continuation_token)
        return self._request_model(
            "GET",
            f"/collective-identifiers/ksef/{ksef_number}",
            response_model=CollectiveIdentifiersByKsefNumberQueryResponse,
            params=params,
            headers=headers,
            access_token=access_token,
        )

    def iter_by_ksef_number(
        self,
        ksef_number: str,
        *,
        access_token: str,
        page_size: int | None = None,
    ) -> Iterator[CollectiveIdentifiersByKsefNumberQueryResponseItem]:
        continuation_token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            response = self.list_by_ksef_number(
                ksef_number,
                access_token=access_token,
                page_size=page_size,
                continuation_token=continuation_token,
            )
            yield from response.collective_identifiers
            continuation_token = response.continuation_token
            if not continuation_token or continuation_token in seen_tokens:
                return
            seen_tokens.add(continuation_token)


class AsyncCollectiveIdentifiersClient(AsyncBaseApiClient):
    async def generate(
        self,
        request_payload: GenerateCollectiveIdentifierRequest,
        *,
        access_token: str,
    ) -> GenerateCollectiveIdentifierResponse:
        require_generate_invoices(request_payload.invoices)
        return await self._request_model(
            "POST",
            "/collective-identifiers",
            response_model=GenerateCollectiveIdentifierResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={201},
        )

    async def generate_for_ksef_numbers(
        self,
        ksef_numbers: Sequence[str],
        *,
        access_token: str,
        descriptions: Sequence[str | None] | None = None,
    ) -> GenerateCollectiveIdentifierResponse:
        return await self.generate(
            _build_generate_request(ksef_numbers, descriptions),
            access_token=access_token,
        )

    async def query(
        self,
        request_payload: CollectiveIdentifiersQueryRequest,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersQueryResponse:
        _validate_query_request(request_payload)
        params, headers = _page_request(page_size, continuation_token)
        return await self._request_model(
            "POST",
            "/collective-identifiers/query",
            response_model=CollectiveIdentifiersQueryResponse,
            json=request_payload,
            params=params,
            headers=headers,
            access_token=access_token,
        )

    async def query_by_created_range(
        self,
        date_from: str,
        date_to: str,
        *,
        access_token: str,
        collective_identifier_number: str | None = None,
        created_in_current_context: bool | None = None,
        invoice_count_from: int | None = None,
        invoice_count_to: int | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersQueryResponse:
        return await self.query(
            _build_query_request(
                date_from,
                date_to,
                collective_identifier_number=collective_identifier_number,
                created_in_current_context=created_in_current_context,
                invoice_count_from=invoice_count_from,
                invoice_count_to=invoice_count_to,
            ),
            access_token=access_token,
            page_size=page_size,
            continuation_token=continuation_token,
        )

    async def iter_query(
        self,
        request_payload: CollectiveIdentifiersQueryRequest,
        *,
        access_token: str,
        page_size: int | None = None,
    ) -> AsyncIterator[CollectiveIdentifiersQueryResponseItem]:
        continuation_token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            response = await self.query(
                request_payload,
                access_token=access_token,
                page_size=page_size,
                continuation_token=continuation_token,
            )
            for item in response.collective_identifiers:
                yield item
            continuation_token = response.continuation_token
            if not continuation_token or continuation_token in seen_tokens:
                return
            seen_tokens.add(continuation_token)

    async def list_invoices(
        self,
        collective_identifier_numbers: str | Sequence[str],
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifierInvoicesQueryResponse:
        numbers = require_invoices_query_identifiers(collective_identifier_numbers)
        params, headers = _page_request(
            page_size,
            continuation_token,
            page_size_max=PAGE_SIZE_INVOICES_MAX,
        )
        return await self._request_model(
            "POST",
            "/collective-identifiers/invoices",
            response_model=CollectiveIdentifierInvoicesQueryResponse,
            json=CollectiveIdentifierInvoicesQueryRequest(
                collective_identifier_numbers=numbers,
            ),
            params=params,
            headers=headers,
            access_token=access_token,
        )

    async def iter_invoices(
        self,
        collective_identifier_numbers: str | Sequence[str],
        *,
        access_token: str,
        page_size: int | None = None,
    ) -> AsyncIterator[CollectiveIdentifierInvoicesQueryResponseItem]:
        continuation_token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            response = await self.list_invoices(
                collective_identifier_numbers,
                access_token=access_token,
                page_size=page_size,
                continuation_token=continuation_token,
            )
            for item in response.invoices:
                yield item
            continuation_token = response.continuation_token
            if not continuation_token or continuation_token in seen_tokens:
                return
            seen_tokens.add(continuation_token)

    async def list_by_ksef_number(
        self,
        ksef_number: str,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersByKsefNumberQueryResponse:
        ksef_number = require_ksef_number(ksef_number)
        params, headers = _page_request(page_size, continuation_token)
        return await self._request_model(
            "GET",
            f"/collective-identifiers/ksef/{ksef_number}",
            response_model=CollectiveIdentifiersByKsefNumberQueryResponse,
            params=params,
            headers=headers,
            access_token=access_token,
        )

    async def iter_by_ksef_number(
        self,
        ksef_number: str,
        *,
        access_token: str,
        page_size: int | None = None,
    ) -> AsyncIterator[CollectiveIdentifiersByKsefNumberQueryResponseItem]:
        continuation_token: str | None = None
        seen_tokens: set[str] = set()
        while True:
            response = await self.list_by_ksef_number(
                ksef_number,
                access_token=access_token,
                page_size=page_size,
                continuation_token=continuation_token,
            )
            for item in response.collective_identifiers:
                yield item
            continuation_token = response.continuation_token
            if not continuation_token or continuation_token in seen_tokens:
                return
            seen_tokens.add(continuation_token)
