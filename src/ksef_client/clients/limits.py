from __future__ import annotations

from ..models import EffectiveContextLimits, EffectiveSubjectLimits
from .base import AsyncBaseApiClient, BaseApiClient


class LimitsClient(BaseApiClient):
    def get_context_limits(self, access_token: str) -> EffectiveContextLimits:
        return self._request_model(
            "GET",
            "/limits/context",
            response_model=EffectiveContextLimits,
            access_token=access_token,
        )

    def get_subject_limits(self, access_token: str) -> EffectiveSubjectLimits:
        return self._request_model(
            "GET",
            "/limits/subject",
            response_model=EffectiveSubjectLimits,
            access_token=access_token,
        )


class AsyncLimitsClient(AsyncBaseApiClient):
    async def get_context_limits(self, access_token: str) -> EffectiveContextLimits:
        return await self._request_model(
            "GET",
            "/limits/context",
            response_model=EffectiveContextLimits,
            access_token=access_token,
        )

    async def get_subject_limits(self, access_token: str) -> EffectiveSubjectLimits:
        return await self._request_model(
            "GET",
            "/limits/subject",
            response_model=EffectiveSubjectLimits,
            access_token=access_token,
        )
