from __future__ import annotations

from typing import Any

from .base import AsyncBaseApiClient, BaseApiClient


class TokensClient(BaseApiClient):
    def generate_token(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/tokens",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def list_tokens(
        self,
        *,
        access_token: str,
        statuses: list[str] | None = None,
        description: str | None = None,
        author_identifier: str | None = None,
        author_identifier_type: str | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> Any:
        params: dict[str, Any] = {}
        if statuses:
            params["status"] = statuses
        if description:
            params["description"] = description
        if author_identifier:
            params["authorIdentifier"] = author_identifier
        if author_identifier_type:
            params["authorIdentifierType"] = author_identifier_type
        if page_size is not None:
            params["pageSize"] = page_size

        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return self._request_json(
            "GET",
            "/tokens",
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )

    def get_token_status(self, reference_number: str, *, access_token: str) -> Any:
        return self._request_json(
            "GET",
            f"/tokens/{reference_number}",
            access_token=access_token,
        )

    def revoke_token(self, reference_number: str, *, access_token: str) -> None:
        self._request_json(
            "DELETE",
            f"/tokens/{reference_number}",
            access_token=access_token,
            expected_status={204},
        )


class AsyncTokensClient(AsyncBaseApiClient):
    async def generate_token(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/tokens",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def list_tokens(
        self,
        *,
        access_token: str,
        statuses: list[str] | None = None,
        description: str | None = None,
        author_identifier: str | None = None,
        author_identifier_type: str | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> Any:
        params: dict[str, Any] = {}
        if statuses:
            params["status"] = statuses
        if description:
            params["description"] = description
        if author_identifier:
            params["authorIdentifier"] = author_identifier
        if author_identifier_type:
            params["authorIdentifierType"] = author_identifier_type
        if page_size is not None:
            params["pageSize"] = page_size

        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token

        return await self._request_json(
            "GET",
            "/tokens",
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )

    async def get_token_status(self, reference_number: str, *, access_token: str) -> Any:
        return await self._request_json(
            "GET",
            f"/tokens/{reference_number}",
            access_token=access_token,
        )

    async def revoke_token(self, reference_number: str, *, access_token: str) -> None:
        await self._request_json(
            "DELETE",
            f"/tokens/{reference_number}",
            access_token=access_token,
            expected_status={204},
        )
