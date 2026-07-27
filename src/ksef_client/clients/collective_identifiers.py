from __future__ import annotations

from typing import Any

from ..models import (
    CollectiveIdentifierInvoicesQueryResponse,
    CollectiveIdentifiersByKsefNumberQueryResponse,
    CollectiveIdentifiersQueryRequest,
    CollectiveIdentifiersQueryResponse,
    GenerateCollectiveIdentifierRequest,
    GenerateCollectiveIdentifierResponse,
)
from ..utils.collective_identifier import require_collective_identifier_number
from ..utils.ksef_number import require_ksef_number
from .base import AsyncBaseApiClient, BaseApiClient


class CollectiveIdentifiersClient(BaseApiClient):
    def generate(
        self,
        request_payload: GenerateCollectiveIdentifierRequest,
        *,
        access_token: str,
    ) -> GenerateCollectiveIdentifierResponse:
        return self._request_model(
            "POST",
            "/collective-identifiers",
            response_model=GenerateCollectiveIdentifierResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={201},
        )

    def query(
        self,
        request_payload: CollectiveIdentifiersQueryRequest,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersQueryResponse:
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size

        headers: dict[str, str] = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return self._request_model(
            "POST",
            "/collective-identifiers/query",
            response_model=CollectiveIdentifiersQueryResponse,
            json=request_payload,
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )

    def list_invoices(
        self,
        collective_identifier_number: str,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifierInvoicesQueryResponse:
        collective_identifier_number = require_collective_identifier_number(
            collective_identifier_number
        )
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size

        headers: dict[str, str] = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return self._request_model(
            "GET",
            f"/collective-identifiers/{collective_identifier_number}/invoices",
            response_model=CollectiveIdentifierInvoicesQueryResponse,
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )

    def list_by_ksef_number(
        self,
        ksef_number: str,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersByKsefNumberQueryResponse:
        ksef_number = require_ksef_number(ksef_number)
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size

        headers: dict[str, str] = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return self._request_model(
            "GET",
            f"/collective-identifiers/ksef/{ksef_number}",
            response_model=CollectiveIdentifiersByKsefNumberQueryResponse,
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )


class AsyncCollectiveIdentifiersClient(AsyncBaseApiClient):
    async def generate(
        self,
        request_payload: GenerateCollectiveIdentifierRequest,
        *,
        access_token: str,
    ) -> GenerateCollectiveIdentifierResponse:
        return await self._request_model(
            "POST",
            "/collective-identifiers",
            response_model=GenerateCollectiveIdentifierResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={201},
        )

    async def query(
        self,
        request_payload: CollectiveIdentifiersQueryRequest,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersQueryResponse:
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size

        headers: dict[str, str] = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return await self._request_model(
            "POST",
            "/collective-identifiers/query",
            response_model=CollectiveIdentifiersQueryResponse,
            json=request_payload,
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )

    async def list_invoices(
        self,
        collective_identifier_number: str,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifierInvoicesQueryResponse:
        collective_identifier_number = require_collective_identifier_number(
            collective_identifier_number
        )
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size

        headers: dict[str, str] = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return await self._request_model(
            "GET",
            f"/collective-identifiers/{collective_identifier_number}/invoices",
            response_model=CollectiveIdentifierInvoicesQueryResponse,
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )

    async def list_by_ksef_number(
        self,
        ksef_number: str,
        *,
        access_token: str,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> CollectiveIdentifiersByKsefNumberQueryResponse:
        ksef_number = require_ksef_number(ksef_number)
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size

        headers: dict[str, str] = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return await self._request_model(
            "GET",
            f"/collective-identifiers/ksef/{ksef_number}",
            response_model=CollectiveIdentifiersByKsefNumberQueryResponse,
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )
