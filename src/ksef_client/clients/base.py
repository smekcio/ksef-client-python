from __future__ import annotations

from typing import Any, Protocol

from ..http import HttpResponse


class _RequestClient(Protocol):
    def request(self, *args: Any, **kwargs: Any) -> HttpResponse: ...


class _AsyncRequestClient(Protocol):
    async def request(self, *args: Any, **kwargs: Any) -> HttpResponse: ...


class BaseApiClient:
    def __init__(self, http_client: _RequestClient) -> None:
        self._http = http_client

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> Any:
        response = self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        if response.content:
            return response.json()
        return None

    def _request_bytes(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> bytes:
        response = self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            data=data,
            access_token=access_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        return response.content

    def _request_raw(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ):
        return self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            data=data,
            access_token=access_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )


class AsyncBaseApiClient:
    def __init__(self, http_client: _AsyncRequestClient) -> None:
        self._http = http_client

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> Any:
        response = await self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            access_token=access_token,
            refresh_token=refresh_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        if response.content:
            return response.json()
        return None

    async def _request_bytes(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> bytes:
        response = await self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            data=data,
            access_token=access_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
        return response.content

    async def _request_raw(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ):
        return await self._http.request(
            method,
            path,
            params=params,
            headers=headers,
            json=json,
            data=data,
            access_token=access_token,
            skip_auth=skip_auth,
            expected_status=expected_status,
        )
