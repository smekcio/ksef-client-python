from __future__ import annotations

from datetime import datetime, timezone

from ..models import PublicKeyCertificate, PublicKeyCertificateUsage
from .base import AsyncBaseApiClient, BaseApiClient


def _normalize_certificate_usage(
    usage: PublicKeyCertificateUsage | str,
) -> PublicKeyCertificateUsage:
    if isinstance(usage, PublicKeyCertificateUsage):
        return usage
    for candidate in PublicKeyCertificateUsage:
        if usage == candidate.value:
            return candidate
    normalized = usage.strip().upper().replace("-", "").replace("_", "")
    for candidate in PublicKeyCertificateUsage:
        if normalized == candidate.name.replace("_", ""):
            return candidate
    raise ValueError(f"Unsupported public key certificate usage: {usage}")


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_current_certificate(certificate: PublicKeyCertificate, now: datetime) -> bool:
    valid_from = _parse_datetime(certificate.valid_from)
    valid_to = _parse_datetime(certificate.valid_to)
    if valid_from is not None and valid_from > now:
        return False
    return not (valid_to is not None and valid_to < now)


def _certificate_sort_key(certificate: PublicKeyCertificate) -> tuple[bool, datetime]:
    valid_from = _parse_datetime(certificate.valid_from)
    if valid_from is None:
        return (False, datetime.min.replace(tzinfo=timezone.utc))
    return (True, valid_from)


def _select_public_key_certificate(
    certificates: list[PublicKeyCertificate],
    usage: PublicKeyCertificateUsage | str,
    *,
    now: datetime | None = None,
) -> PublicKeyCertificate:
    normalized_usage = _normalize_certificate_usage(usage)
    current_now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    candidates = [
        certificate
        for certificate in certificates
        if normalized_usage in certificate.usage
        and certificate.certificate
        and _is_current_certificate(certificate, current_now)
    ]
    if not candidates:
        raise ValueError(f"Missing KSeF public certificate for usage: {normalized_usage.value}")
    return max(candidates, key=_certificate_sort_key)


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
        return _select_public_key_certificate(self.get_public_key_certificates(), usage)

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
        return _select_public_key_certificate(await self.get_public_key_certificates(), usage)

    async def get_public_key_certificate_pem(
        self,
        usage: PublicKeyCertificateUsage | str,
    ) -> str:
        return (await self.get_public_key_certificate(usage)).certificate
