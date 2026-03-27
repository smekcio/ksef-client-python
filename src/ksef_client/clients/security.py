from __future__ import annotations

from ..models import PublicKeyCertificate, PublicKeyCertificateUsage
from .base import AsyncBaseApiClient, BaseApiClient


def _normalize_certificate_usage(
    usage: PublicKeyCertificateUsage | str,
) -> PublicKeyCertificateUsage:
    if isinstance(usage, PublicKeyCertificateUsage):
        return usage
    try:
        return PublicKeyCertificateUsage(usage)
    except ValueError:
        normalized = usage.strip().upper().replace("-", "").replace("_", "")
        for candidate in PublicKeyCertificateUsage:
            if normalized == candidate.name.replace("_", ""):
                return candidate
    raise ValueError(f"Unsupported public key certificate usage: {usage}")


class SecurityClient(BaseApiClient):
    def get_public_key_certificates(self) -> list[PublicKeyCertificate]:
        return self._request_model_list(
            "GET",
            "/security/public-key-certificates",
            response_model=PublicKeyCertificate,
            skip_auth=True,
        )

    def get_public_key_certificate(
        self,
        usage: PublicKeyCertificateUsage | str,
    ) -> PublicKeyCertificate:
        normalized_usage = _normalize_certificate_usage(usage)
        for certificate in self.get_public_key_certificates():
            if normalized_usage in certificate.usage:
                return certificate
        raise ValueError(f"Missing KSeF public certificate for usage: {normalized_usage.value}")

    def get_public_key_certificate_pem(
        self,
        usage: PublicKeyCertificateUsage | str,
    ) -> str:
        return self.get_public_key_certificate(usage).certificate


class AsyncSecurityClient(AsyncBaseApiClient):
    async def get_public_key_certificates(self) -> list[PublicKeyCertificate]:
        return await self._request_model_list(
            "GET",
            "/security/public-key-certificates",
            response_model=PublicKeyCertificate,
            skip_auth=True,
        )

    async def get_public_key_certificate(
        self,
        usage: PublicKeyCertificateUsage | str,
    ) -> PublicKeyCertificate:
        normalized_usage = _normalize_certificate_usage(usage)
        for certificate in await self.get_public_key_certificates():
            if normalized_usage in certificate.usage:
                return certificate
        raise ValueError(f"Missing KSeF public certificate for usage: {normalized_usage.value}")

    async def get_public_key_certificate_pem(
        self,
        usage: PublicKeyCertificateUsage | str,
    ) -> str:
        return (await self.get_public_key_certificate(usage)).certificate
