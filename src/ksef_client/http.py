from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from .config import KsefClientOptions
from .exceptions import KsefApiError, KsefHttpError, KsefRateLimitError


def _merge_headers(base: dict[str, str], extra: dict[str, str] | None) -> dict[str, str]:
    if not extra:
        return base
    merged = dict(base)
    merged.update(extra)
    return merged


def _is_absolute_http_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def _host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    normalized_host = host.lower().rstrip(".")
    for allowed in allowed_hosts:
        normalized_allowed = allowed.lower().strip().rstrip(".")
        if not normalized_allowed:
            continue
        if normalized_host == normalized_allowed:
            return True
        try:
            ipaddress.ip_address(normalized_allowed)
            continue
        except ValueError:
            pass
        if normalized_host.endswith("." + normalized_allowed):
            return True
    return False


def _validate_presigned_url_security(options: KsefClientOptions, url: str) -> None:
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        raise ValueError("Rejected insecure presigned URL: host is missing.")

    normalized_host = host.lower().rstrip(".")
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        raise ValueError(
            "Rejected insecure presigned URL: localhost hosts are not allowed "
            "for skip_auth requests."
        )

    if options.strict_presigned_url_validation and parsed.scheme != "https":
        raise ValueError(
            "Rejected insecure presigned URL: https is required for skip_auth requests."
        )

    try:
        host_ip = ipaddress.ip_address(normalized_host)
    except ValueError:
        host_ip = None

    if host_ip is not None:
        if host_ip.is_loopback:
            raise ValueError(
                "Rejected insecure presigned URL: loopback addresses are not allowed "
                "for skip_auth requests."
            )
        if (
            not options.allow_private_network_presigned_urls
            and (host_ip.is_private or host_ip.is_link_local or host_ip.is_reserved)
        ):
            raise ValueError(
                "Rejected insecure presigned URL: private, link-local, and reserved "
                "IP hosts are blocked for skip_auth requests."
            )

    if options.allowed_presigned_hosts and not _host_allowed(
        normalized_host, options.allowed_presigned_hosts
    ):
        raise ValueError(
            "Rejected insecure presigned URL: host is not in allowed_presigned_hosts "
            "for skip_auth requests."
        )


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
        access_token: str | None = None,
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
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> HttpResponse:
        url = path
        if not _is_absolute_http_url(url):
            url = self._options.normalized_base_url().rstrip("/") + "/" + path.lstrip("/")
        elif skip_auth:
            _validate_presigned_url_security(self._options, url)

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

        if (
            expected_status
            and response.status_code not in expected_status
            or not expected_status
            and response.status_code >= 400
        ):
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
        access_token: str | None = None,
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
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
        data: bytes | None = None,
        access_token: str | None = None,
        refresh_token: str | None = None,
        skip_auth: bool = False,
        expected_status: set[int] | None = None,
    ) -> HttpResponse:
        url = path
        if not _is_absolute_http_url(url):
            url = self._options.normalized_base_url().rstrip("/") + "/" + path.lstrip("/")
        elif skip_auth:
            _validate_presigned_url_security(self._options, url)

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

        if (
            expected_status
            and response.status_code not in expected_status
            or not expected_status
            and response.status_code >= 400
        ):
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
