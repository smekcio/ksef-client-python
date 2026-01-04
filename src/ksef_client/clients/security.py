from __future__ import annotations

from typing import Any

from .base import BaseApiClient, AsyncBaseApiClient


class SecurityClient(BaseApiClient):
    def get_public_key_certificates(self) -> Any:
        return self._request_json("GET", "/security/public-key-certificates", skip_auth=True)

    def get_public_key_pem(self) -> str:
        content = self._request_bytes(
            "GET",
            "/public-keys/publicKey.pem",
            headers={"Accept": "application/x-pem-file"},
            skip_auth=True,
            expected_status={200},
        )
        return content.decode("utf-8")


class AsyncSecurityClient(AsyncBaseApiClient):
    async def get_public_key_certificates(self) -> Any:
        return await self._request_json("GET", "/security/public-key-certificates", skip_auth=True)

    async def get_public_key_pem(self) -> str:
        content = await self._request_bytes(
            "GET",
            "/public-keys/publicKey.pem",
            headers={"Accept": "application/x-pem-file"},
            skip_auth=True,
            expected_status={200},
        )
        return content.decode("utf-8")
