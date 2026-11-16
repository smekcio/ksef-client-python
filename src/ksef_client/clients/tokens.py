from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ..models import (
    GenerateTokenRequest,
    GenerateTokenRequestRev2,
    GenerateTokenResponse,
    GenerateTokenResponseRev2,
    QueryTokensResponse,
    QueryTokensResponseRev2,
    TokenAuthorIdentifierTypeFilterRev2,
    TokenStatusFilterRev2,
    TokenStatusResponse,
    TokenStatusResponseRev2,
)
from .base import AsyncBaseApiClient, BaseApiClient, _require_reference_number


def _rev2_filters(
    statuses: Sequence[TokenStatusFilterRev2 | str] | None,
    description: str | None,
    author_identifier: str | None,
    author_identifier_type: TokenAuthorIdentifierTypeFilterRev2 | str | None,
    valid_from: str | None,
    valid_to: str | None,
    page_size: int | None,
) -> dict[str, Any]:
    if isinstance(statuses, str) and statuses:
        statuses = (statuses,)
    values = {
        "status": [
            status.value if isinstance(status, TokenStatusFilterRev2) else status
            for status in statuses
        ]
        if statuses
        else None,
        "description": description,
        "authorIdentifier": author_identifier,
        "authorIdentifierType": (
            author_identifier_type.value
            if isinstance(author_identifier_type, TokenAuthorIdentifierTypeFilterRev2)
            else author_identifier_type
        ),
        "validFrom": valid_from,
        "validTo": valid_to,
        "pageSize": page_size,
    }
    return {key: value for key, value in values.items() if value is not None}


class TokensClient(BaseApiClient):
    def generate_token(
        self, request_payload: GenerateTokenRequest, *, access_token: str | None = None
    ) -> GenerateTokenResponse:
        return self._request_model(
            "POST",
            "/tokens",
            response_model=GenerateTokenResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def list_tokens(
        self,
        *,
        access_token: str | None = None,
        statuses: list[str] | None = None,
        description: str | None = None,
        author_identifier: str | None = None,
        author_identifier_type: str | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> QueryTokensResponse:
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

        return self._request_model(
            "GET",
            "/tokens",
            response_model=QueryTokensResponse,
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )

    def get_token_status(
        self, reference_number: str, *, access_token: str | None = None
    ) -> TokenStatusResponse:
        return self._request_model(
            "GET",
            f"/tokens/{reference_number}",
            response_model=TokenStatusResponse,
            access_token=access_token,
        )

    def generate_token_rev2(
        self, request_payload: GenerateTokenRequestRev2, *, access_token: str | None = None
    ) -> GenerateTokenResponseRev2:
        return self._request_model(
            "POST",
            "/tokens/rev2",
            response_model=GenerateTokenResponseRev2,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def list_tokens_rev2(
        self,
        *,
        statuses: Sequence[TokenStatusFilterRev2 | str] | None = None,
        description: str | None = None,
        author_identifier: str | None = None,
        author_identifier_type: TokenAuthorIdentifierTypeFilterRev2 | str | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> QueryTokensResponseRev2:
        return self._request_model(
            "GET",
            "/tokens/rev2",
            response_model=QueryTokensResponseRev2,
            params=_rev2_filters(
                statuses,
                description,
                author_identifier,
                author_identifier_type,
                valid_from,
                valid_to,
                page_size,
            ),
            headers={"x-continuation-token": continuation_token} if continuation_token else None,
            access_token=access_token,
        )

    def get_token_status_rev2(
        self, reference_number: str, *, access_token: str | None = None
    ) -> TokenStatusResponseRev2:
        return self._request_model(
            "GET",
            f"/tokens/rev2/{_require_reference_number(reference_number)}",
            response_model=TokenStatusResponseRev2,
            access_token=access_token,
        )

    def approve_token(self, reference_number: str, *, access_token: str | None = None) -> None:
        self._request_json(
            "POST",
            f"/tokens/{_require_reference_number(reference_number)}/approve",
            access_token=access_token,
            expected_status={204},
        )

    def revoke_token(self, reference_number: str, *, access_token: str | None = None) -> None:
        self._request_json(
            "DELETE",
            f"/tokens/{reference_number}",
            access_token=access_token,
            expected_status={204},
        )


class AsyncTokensClient(AsyncBaseApiClient):
    async def generate_token(
        self, request_payload: GenerateTokenRequest, *, access_token: str | None = None
    ) -> GenerateTokenResponse:
        return await self._request_model(
            "POST",
            "/tokens",
            response_model=GenerateTokenResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def list_tokens(
        self,
        *,
        access_token: str | None = None,
        statuses: list[str] | None = None,
        description: str | None = None,
        author_identifier: str | None = None,
        author_identifier_type: str | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> QueryTokensResponse:
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

        return await self._request_model(
            "GET",
            "/tokens",
            response_model=QueryTokensResponse,
            params=params or None,
            headers=headers or None,
            access_token=access_token,
        )

    async def get_token_status(
        self, reference_number: str, *, access_token: str | None = None
    ) -> TokenStatusResponse:
        return await self._request_model(
            "GET",
            f"/tokens/{reference_number}",
            response_model=TokenStatusResponse,
            access_token=access_token,
        )

    async def generate_token_rev2(
        self, request_payload: GenerateTokenRequestRev2, *, access_token: str | None = None
    ) -> GenerateTokenResponseRev2:
        return await self._request_model(
            "POST",
            "/tokens/rev2",
            response_model=GenerateTokenResponseRev2,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def list_tokens_rev2(
        self,
        *,
        statuses: Sequence[TokenStatusFilterRev2 | str] | None = None,
        description: str | None = None,
        author_identifier: str | None = None,
        author_identifier_type: TokenAuthorIdentifierTypeFilterRev2 | str | None = None,
        valid_from: str | None = None,
        valid_to: str | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> QueryTokensResponseRev2:
        return await self._request_model(
            "GET",
            "/tokens/rev2",
            response_model=QueryTokensResponseRev2,
            params=_rev2_filters(
                statuses,
                description,
                author_identifier,
                author_identifier_type,
                valid_from,
                valid_to,
                page_size,
            ),
            headers={"x-continuation-token": continuation_token} if continuation_token else None,
            access_token=access_token,
        )

    async def get_token_status_rev2(
        self, reference_number: str, *, access_token: str | None = None
    ) -> TokenStatusResponseRev2:
        return await self._request_model(
            "GET",
            f"/tokens/rev2/{_require_reference_number(reference_number)}",
            response_model=TokenStatusResponseRev2,
            access_token=access_token,
        )

    async def approve_token(
        self, reference_number: str, *, access_token: str | None = None
    ) -> None:
        await self._request_json(
            "POST",
            f"/tokens/{_require_reference_number(reference_number)}/approve",
            access_token=access_token,
            expected_status={204},
        )

    async def revoke_token(self, reference_number: str, *, access_token: str | None = None) -> None:
        await self._request_json(
            "DELETE",
            f"/tokens/{reference_number}",
            access_token=access_token,
            expected_status={204},
        )
