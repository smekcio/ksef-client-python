from __future__ import annotations

from typing import Any

from ..models import (
    CertificateEnrollmentDataResponse,
    CertificateEnrollmentStatusResponse,
    CertificateLimitsResponse,
    EnrollCertificateRequest,
    EnrollCertificateResponse,
    QueryCertificatesRequest,
    QueryCertificatesResponse,
    RetrieveCertificatesRequest,
    RetrieveCertificatesResponse,
    RevokeCertificateRequest,
)
from .base import AsyncBaseApiClient, BaseApiClient


class CertificatesClient(BaseApiClient):
    def get_limits(self, access_token: str) -> CertificateLimitsResponse:
        return self._request_model(
            "GET",
            "/certificates/limits",
            response_model=CertificateLimitsResponse,
            access_token=access_token,
        )

    def get_enrollment_data(self, access_token: str) -> CertificateEnrollmentDataResponse:
        return self._request_model(
            "GET",
            "/certificates/enrollments/data",
            response_model=CertificateEnrollmentDataResponse,
            access_token=access_token,
        )

    def send_enrollment(
        self, request_payload: EnrollCertificateRequest, *, access_token: str
    ) -> EnrollCertificateResponse:
        return self._request_model(
            "POST",
            "/certificates/enrollments",
            response_model=EnrollCertificateResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    def get_enrollment_status(
        self, reference_number: str, *, access_token: str
    ) -> CertificateEnrollmentStatusResponse:
        return self._request_model(
            "GET",
            f"/certificates/enrollments/{reference_number}",
            response_model=CertificateEnrollmentStatusResponse,
            access_token=access_token,
        )

    def query_certificates(
        self,
        request_payload: QueryCertificatesRequest,
        *,
        page_size: int | None = None,
        page_offset: int | None = None,
        access_token: str,
    ) -> QueryCertificatesResponse:
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size
        if page_offset is not None:
            params["pageOffset"] = page_offset
        return self._request_model(
            "POST",
            "/certificates/query",
            response_model=QueryCertificatesResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    def retrieve_certificate(
        self, request_payload: RetrieveCertificatesRequest, *, access_token: str
    ) -> RetrieveCertificatesResponse:
        return self._request_model(
            "POST",
            "/certificates/retrieve",
            response_model=RetrieveCertificatesResponse,
            json=request_payload,
            access_token=access_token,
        )

    def revoke_certificate(
        self,
        certificate_serial_number: str,
        request_payload: RevokeCertificateRequest,
        *,
        access_token: str,
    ) -> None:
        self._request_json(
            "POST",
            f"/certificates/{certificate_serial_number}/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={204},
        )


class AsyncCertificatesClient(AsyncBaseApiClient):
    async def get_limits(self, access_token: str) -> CertificateLimitsResponse:
        return await self._request_model(
            "GET",
            "/certificates/limits",
            response_model=CertificateLimitsResponse,
            access_token=access_token,
        )

    async def get_enrollment_data(self, access_token: str) -> CertificateEnrollmentDataResponse:
        return await self._request_model(
            "GET",
            "/certificates/enrollments/data",
            response_model=CertificateEnrollmentDataResponse,
            access_token=access_token,
        )

    async def send_enrollment(
        self, request_payload: EnrollCertificateRequest, *, access_token: str
    ) -> EnrollCertificateResponse:
        return await self._request_model(
            "POST",
            "/certificates/enrollments",
            response_model=EnrollCertificateResponse,
            json=request_payload,
            access_token=access_token,
            expected_status={202},
        )

    async def get_enrollment_status(
        self, reference_number: str, *, access_token: str
    ) -> CertificateEnrollmentStatusResponse:
        return await self._request_model(
            "GET",
            f"/certificates/enrollments/{reference_number}",
            response_model=CertificateEnrollmentStatusResponse,
            access_token=access_token,
        )

    async def query_certificates(
        self,
        request_payload: QueryCertificatesRequest,
        *,
        page_size: int | None = None,
        page_offset: int | None = None,
        access_token: str,
    ) -> QueryCertificatesResponse:
        params: dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size
        if page_offset is not None:
            params["pageOffset"] = page_offset
        return await self._request_model(
            "POST",
            "/certificates/query",
            response_model=QueryCertificatesResponse,
            params=params or None,
            json=request_payload,
            access_token=access_token,
        )

    async def retrieve_certificate(
        self, request_payload: RetrieveCertificatesRequest, *, access_token: str
    ) -> RetrieveCertificatesResponse:
        return await self._request_model(
            "POST",
            "/certificates/retrieve",
            response_model=RetrieveCertificatesResponse,
            json=request_payload,
            access_token=access_token,
        )

    async def revoke_certificate(
        self,
        certificate_serial_number: str,
        request_payload: RevokeCertificateRequest,
        *,
        access_token: str,
    ) -> None:
        await self._request_json(
            "POST",
            f"/certificates/{certificate_serial_number}/revoke",
            json=request_payload,
            access_token=access_token,
            expected_status={204},
        )
