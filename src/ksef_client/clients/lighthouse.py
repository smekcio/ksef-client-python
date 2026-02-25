from __future__ import annotations

from typing import Any

from ..models import LighthouseMessage, LighthouseStatusResponse
from .base import AsyncBaseApiClient, BaseApiClient


class LighthouseClient(BaseApiClient):
    def __init__(self, http_client: Any, base_url: str) -> None:
        super().__init__(http_client)
        self._base_url = base_url.rstrip("/")

    def _require_base_url(self) -> str:
        if self._base_url:
            return self._base_url
        raise ValueError("Unknown KSeF environment; set base_lighthouse_url explicitly.")

    def get_status(self) -> LighthouseStatusResponse:
        payload = self._request_json("GET", f"{self._require_base_url()}/status")
        if not isinstance(payload, dict):
            payload = {}
        return LighthouseStatusResponse.from_dict(payload)

    def get_messages(self) -> list[LighthouseMessage]:
        payload = self._request_json("GET", f"{self._require_base_url()}/messages")
        if not isinstance(payload, list):
            return []
        return [LighthouseMessage.from_dict(item) for item in payload if isinstance(item, dict)]


class AsyncLighthouseClient(AsyncBaseApiClient):
    def __init__(self, http_client: Any, base_url: str) -> None:
        super().__init__(http_client)
        self._base_url = base_url.rstrip("/")

    def _require_base_url(self) -> str:
        if self._base_url:
            return self._base_url
        raise ValueError("Unknown KSeF environment; set base_lighthouse_url explicitly.")

    async def get_status(self) -> LighthouseStatusResponse:
        payload = await self._request_json("GET", f"{self._require_base_url()}/status")
        if not isinstance(payload, dict):
            payload = {}
        return LighthouseStatusResponse.from_dict(payload)

    async def get_messages(self) -> list[LighthouseMessage]:
        payload = await self._request_json("GET", f"{self._require_base_url()}/messages")
        if not isinstance(payload, list):
            return []
        return [LighthouseMessage.from_dict(item) for item in payload if isinstance(item, dict)]
