from __future__ import annotations

from typing import Any, Optional

from ..http import BaseHttpClient, AsyncBaseHttpClient


class BaseApiClient:
    def __init__(self, http_client: BaseHttpClient) -> None:
        self._http = http_client

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        json: Optional[dict[str, Any]] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        skip_auth: bool = False,
        expected_status: Optional[set[int]] = None,
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
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        json: Optional[dict[str, Any]] = None,
        data: Optional[bytes] = None,
        access_token: Optional[str] = None,
        skip_auth: bool = False,
        expected_status: Optional[set[int]] = None,
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
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        json: Optional[dict[str, Any]] = None,
        data: Optional[bytes] = None,
        access_token: Optional[str] = None,
        skip_auth: bool = False,
        expected_status: Optional[set[int]] = None,
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
    def __init__(self, http_client: AsyncBaseHttpClient) -> None:
        self._http = http_client

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        json: Optional[dict[str, Any]] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        skip_auth: bool = False,
        expected_status: Optional[set[int]] = None,
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
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        json: Optional[dict[str, Any]] = None,
        data: Optional[bytes] = None,
        access_token: Optional[str] = None,
        skip_auth: bool = False,
        expected_status: Optional[set[int]] = None,
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
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        json: Optional[dict[str, Any]] = None,
        data: Optional[bytes] = None,
        access_token: Optional[str] = None,
        skip_auth: bool = False,
        expected_status: Optional[set[int]] = None,
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
