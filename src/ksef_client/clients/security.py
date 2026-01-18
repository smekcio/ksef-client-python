from __future__ import annotations

from typing import Any

from .base import AsyncBaseApiClient, BaseApiClient


class SecurityClient(BaseApiClient):
    def get_public_key_certificates(self) -> Any:
        return self._request_json("GET", "/security/public-key-certificates", skip_auth=True)

    async def get_public_key_certificates(self) -> Any:
        return await self._request_json("GET", "/security/public-key-certificates", skip_auth=True)
