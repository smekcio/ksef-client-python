from __future__ import annotations

from typing import Any

from .base import AsyncBaseApiClient, BaseApiClient


class LimitsClient(BaseApiClient):
    def get_context_limits(self, access_token: str) -> Any:
        return self._request_json("GET", "/limits/context", access_token=access_token)

    def get_subject_limits(self, access_token: str) -> Any:
        return self._request_json("GET", "/limits/subject", access_token=access_token)


class AsyncLimitsClient(AsyncBaseApiClient):
    async def get_context_limits(self, access_token: str) -> Any:
        return await self._request_json("GET", "/limits/context", access_token=access_token)

    async def get_subject_limits(self, access_token: str) -> Any:
        return await self._request_json("GET", "/limits/subject", access_token=access_token)
