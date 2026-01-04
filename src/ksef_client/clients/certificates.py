from __future__ import annotations

from typing import Any, Optional

from .base import BaseApiClient, AsyncBaseApiClient


class CertificatesClient(BaseApiClient):
    def get_limits(self, access_token: str) -> Any:
        return self._request_json("GET", "/certificates/limits", access_token=access_token)

    def get_enrollment_data(self, access_token: str) -> Any:
        return self._request_json("GET", "/certificates/enrollments/data", access_token=access_token)

    def send_enrollment(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/certificates/enrollments",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def get_enrollment_status(self, reference_number: str, *, access_token: str) -> Any:
        return self._request_json(
            "GET",
            f"/certificates/enrollments/{reference_number}",
            access_token=access_token,
        )

    def query_certificates(
        self,
        request_payload: dict[str, Any],
        *,
        page_size: Optional[int] = None,
        page_offset: Optional[int] = None,
        access_token: str,
    ) -> Any:
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size
        if page_offset is not None:
            params["pageOffset"] = page_offset
        return self._request_json(
            "POST",
            "/certificates/query",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def retrieve_certificate(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            "/certificates/retrieve",
            json=request_payload,
            access_token=access_token,
        )

    def revoke_certificate(self, certificate_serial_number: str, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return self._request_json(
            "POST",
            f"/certificates/{certificate_serial_number}/revoke",
            json=request_payload,
            access_token=access_token,
        )


class AsyncCertificatesClient(AsyncBaseApiClient):
    async def get_limits(self, access_token: str) -> Any:
        return await self._request_json("GET", "/certificates/limits", access_token=access_token)

    async def get_enrollment_data(self, access_token: str) -> Any:
        return await self._request_json("GET", "/certificates/enrollments/data", access_token=access_token)

    async def send_enrollment(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/certificates/enrollments",
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def get_enrollment_status(self, reference_number: str, *, access_token: str) -> Any:
        return await self._request_json(
            "GET",
            f"/certificates/enrollments/{reference_number}",
            access_token=access_token,
        )

    async def query_certificates(
        self,
        request_payload: dict[str, Any],
        *,
        page_size: Optional[int] = None,
        page_offset: Optional[int] = None,
        access_token: str,
    ) -> Any:
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size
        if page_offset is not None:
            params["pageOffset"] = page_offset
        return await self._request_json(
            "POST",
            "/certificates/query",
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def retrieve_certificate(self, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            "/certificates/retrieve",
            json=request_payload,
            access_token=access_token,
        )

    async def revoke_certificate(self, certificate_serial_number: str, request_payload: dict[str, Any], *, access_token: str) -> Any:
        return await self._request_json(
            "POST",
            f"/certificates/{certificate_serial_number}/revoke",
            json=request_payload,
            access_token=access_token,
        )
