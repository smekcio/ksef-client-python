from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .config import KsefClientOptions
from .exceptions import KsefApiError, KsefHttpError, KsefRateLimitError


def _merge_headers(base: dict[str, str], extra: Optional[dict[str, str]]) -> dict[str, str]:
    if not extra:
        return base
    merged = dict(base)
    merged.update(extra)
    return merged


@dataclass
class HttpResponse:
    status_code: int
    headers: httpx.Headers
    content: bytes

    def json(self) -> Any:
        return httpx.Response(self.status_code, headers=self.headers, content=self.content).json()


class BaseHttpClient:
    def __init__(
        self,
        options: KsefClientOptions,
        access_token: Optional[str] = None,
    ) -> None:
        self._options = options
        self._access_token = access_token
        self._client = httpx.Client(
            timeout=options.timeout_seconds,
            verify=options.verify_ssl,
            proxy=options.proxy,
            follow_redirects=options.follow_redirects,
        )

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        json: Optional[dict[str, Any]] = None,
        data: Optional[bytes] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        skip_auth: bool = False,
        expected_status: Optional[set[int]] = None,
    ) -> HttpResponse:
        url = path
        if not url.startswith("http://") and not url.startswith("https://"):
            url = self._options.normalized_base_url().rstrip("/") + "/" + path.lstrip("/")

        base_headers = {
            "User-Agent": self._options.user_agent,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if json is not None:
            base_headers["Content-Type"] = "application/json"

        if not skip_auth:
            token = access_token or self._access_token
            if refresh_token:
                token = refresh_token
            if token:
                base_headers["Authorization"] = f"Bearer {token}"

        base_headers = _merge_headers(base_headers, self._options.custom_headers)
        final_headers = _merge_headers(base_headers, headers)

        response = self._client.request(
            method=method,
            url=url,
            params=params,
            headers=final_headers,
            json=json,
            content=data,
        )

        if expected_status and response.status_code not in expected_status:
            self._raise_for_status(response)
        elif not expected_status and response.status_code >= 400:
            self._raise_for_status(response)

        return HttpResponse(response.status_code, response.headers, response.content)

    def _raise_for_status(self, response: httpx.Response) -> None:
        retry_after = response.headers.get("Retry-After")
        content_type = response.headers.get("Content-Type", "")
        body: Any = None
        if "application/json" in content_type:
            try:
                body = response.json()
            except ValueError:
                body = None

        if response.status_code == 429:
            raise KsefRateLimitError(
                status_code=response.status_code,
                message="Too Many Requests",
                response_body=body,
                retry_after=retry_after,
            )

        if body is not None:
            raise KsefApiError(
                status_code=response.status_code,
                message="API error",
                response_body=body,
                exception_response=body,
            )

        raise KsefHttpError(
            status_code=response.status_code,
            message=response.text,
            response_body=None,
        )


class AsyncBaseHttpClient:
    def __init__(
        self,
        options: KsefClientOptions,
        access_token: Optional[str] = None,
    ) -> None:
        self._options = options
        self._access_token = access_token
        self._client = httpx.AsyncClient(
            timeout=options.timeout_seconds,
            verify=options.verify_ssl,
            proxy=options.proxy,
            follow_redirects=options.follow_redirects,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        headers: Optional[dict[str, str]] = None,
        json: Optional[dict[str, Any]] = None,
        data: Optional[bytes] = None,
        access_token: Optional[str] = None,
        refresh_token: Optional[str] = None,
        skip_auth: bool = False,
        expected_status: Optional[set[int]] = None,
    ) -> HttpResponse:
        url = path
        if not url.startswith("http://") and not url.startswith("https://"):
            url = self._options.normalized_base_url().rstrip("/") + "/" + path.lstrip("/")

        base_headers = {
            "User-Agent": self._options.user_agent,
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        if json is not None:
            base_headers["Content-Type"] = "application/json"

        if not skip_auth:
            token = access_token or self._access_token
            if refresh_token:
                token = refresh_token
            if token:
                base_headers["Authorization"] = f"Bearer {token}"

        base_headers = _merge_headers(base_headers, self._options.custom_headers)
        final_headers = _merge_headers(base_headers, headers)

        response = await self._client.request(
            method=method,
            url=url,
            params=params,
            headers=final_headers,
            json=json,
            content=data,
        )

        if expected_status and response.status_code not in expected_status:
            self._raise_for_status(response)
        elif not expected_status and response.status_code >= 400:
            self._raise_for_status(response)

        return HttpResponse(response.status_code, response.headers, response.content)

    def _raise_for_status(self, response: httpx.Response) -> None:
        retry_after = response.headers.get("Retry-After")
        content_type = response.headers.get("Content-Type", "")
        body: Any = None
        if "application/json" in content_type:
            try:
                body = response.json()
            except ValueError:
                body = None

        if response.status_code == 429:
            raise KsefRateLimitError(
                status_code=response.status_code,
                message="Too Many Requests",
                response_body=body,
                retry_after=retry_after,
            )

        if body is not None:
            raise KsefApiError(
                status_code=response.status_code,
                message="API error",
                response_body=body,
                exception_response=body,
            )

        raise KsefHttpError(
            status_code=response.status_code,
            message=response.text,
            response_body=None,
        )
