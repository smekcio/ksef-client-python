from __future__ import annotations

from typing import Any

from .base import AsyncBaseApiClient, BaseApiClient


class RateLimitsClient(BaseApiClient):
    def get_rate_limits(self, access_token: str) -> Any:
        return self._request_json("GET", "/rate-limits", access_token=access_token)


class AsyncRateLimitsClient(AsyncBaseApiClient):
    async def get_rate_limits(self, access_token: str) -> Any:
        return await self._request_json("GET", "/rate-limits", access_token=access_token)
