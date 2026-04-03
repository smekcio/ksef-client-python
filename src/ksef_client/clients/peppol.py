from __future__ import annotations

from typing import Any

from ..models import QueryPeppolProvidersResponse
from .base import AsyncBaseApiClient, BaseApiClient


class PeppolClient(BaseApiClient):
    def list_providers(
        self, *, page_offset: int | None = None, page_size: int | None = None
    ) -> QueryPeppolProvidersResponse:
        params: dict[str, Any] = {}
        if page_offset is not None:
            params["pageOffset"] = page_offset
        if page_size is not None:
            params["pageSize"] = page_size
        return self._request_model(
            "GET",
            "/peppol/query",
            response_model=QueryPeppolProvidersResponse,
            params=params or None,
            skip_auth=True,
        )


class AsyncPeppolClient(AsyncBaseApiClient):
    async def list_providers(
        self, *, page_offset: int | None = None, page_size: int | None = None
    ) -> QueryPeppolProvidersResponse:
        params: dict[str, Any] = {}
        if page_offset is not None:
            params["pageOffset"] = page_offset
        if page_size is not None:
            params["pageSize"] = page_size
        return await self._request_model(
            "GET",
            "/peppol/query",
            response_model=QueryPeppolProvidersResponse,
            params=params or None,
            skip_auth=True,
        )
