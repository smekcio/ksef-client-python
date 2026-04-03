from __future__ import annotations

from ..models import EffectiveApiRateLimits
from .base import AsyncBaseApiClient, BaseApiClient


class RateLimitsClient(BaseApiClient):
    def get_rate_limits(self, access_token: str) -> EffectiveApiRateLimits:
        return self._request_model(
            "GET",
            "/rate-limits",
            response_model=EffectiveApiRateLimits,
            access_token=access_token,
        )


class AsyncRateLimitsClient(AsyncBaseApiClient):
    async def get_rate_limits(self, access_token: str) -> EffectiveApiRateLimits:
        return await self._request_model(
            "GET",
            "/rate-limits",
            response_model=EffectiveApiRateLimits,
            access_token=access_token,
        )
