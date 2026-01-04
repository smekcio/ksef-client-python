from __future__ import annotations

from typing import Any, Optional

from .base import BaseApiClient, AsyncBaseApiClient


class PeppolClient(BaseApiClient):
    def list_providers(self, *, page_offset: Optional[int] = None, page_size: Optional[int] = None) -> Any:
        params: dict[str, Any] = {}
        if page_offset is not None:
            params["pageOffset"] = page_offset
        if page_size is not None:
            params["pageSize"] = page_size
        return self._request_json(
            "GET",
            "/peppol/query",
            params=params or None,
            skip_auth=True,
        )


class AsyncPeppolClient(AsyncBaseApiClient):
    async def list_providers(self, *, page_offset: Optional[int] = None, page_size: Optional[int] = None) -> Any:
        params: dict[str, Any] = {}
        if page_offset is not None:
            params["pageOffset"] = page_offset
        if page_size is not None:
            params["pageSize"] = page_size
        return await self._request_json(
            "GET",
            "/peppol/query",
            params=params or None,
            skip_auth=True,
        )
