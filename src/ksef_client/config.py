from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from importlib import metadata


class KsefEnvironment(str, Enum):
    TEST = "https://api-test.ksef.mf.gov.pl"
    DEMO = "https://api-demo.ksef.mf.gov.pl"
    PROD = "https://api.ksef.mf.gov.pl"


class KsefQrEnvironment(str, Enum):
    TEST = "https://qr-test.ksef.mf.gov.pl"
    DEMO = "https://qr-demo.ksef.mf.gov.pl"
    PROD = "https://qr.ksef.mf.gov.pl"


class KsefLighthouseEnvironment(str, Enum):
    TEST = "https://api-latarnia-test.ksef.mf.gov.pl"
    PROD = "https://api-latarnia.ksef.mf.gov.pl"
    PRD = PROD


def _package_version() -> str:
    try:
        return metadata.version("ksef-client")
    except Exception:
        try:
            return metadata.version("ksef-client-python")
        except Exception:
            return "0.0.0"


def _default_user_agent() -> str:
    return f"ksef-client/{_package_version()}"


@dataclass(frozen=True)
class KsefClientOptions:
    base_url: str
    base_qr_url: str | None = None
    base_lighthouse_url: str | None = None
    timeout_seconds: float = 30.0
    proxy: str | None = None
    custom_headers: dict[str, str] | None = None
    follow_redirects: bool = False
    verify_ssl: bool = True
    require_export_part_hash: bool = True
    strict_presigned_url_validation: bool = True
    allowed_presigned_hosts: list[str] | None = None
    allow_private_network_presigned_urls: bool = False
    user_agent: str = field(default_factory=_default_user_agent)

    def normalized_base_url(self) -> str:
        url = self.base_url.rstrip("/")
        if url.endswith("/v2") or url.endswith("/api/v2"):
            return url
        return url + "/v2"

    def resolve_qr_base_url(self) -> str:
        if self.base_qr_url:
            return self.base_qr_url.rstrip("/")
        base = self.base_url.rstrip("/")
        if base.startswith(KsefEnvironment.TEST.value):
            return KsefQrEnvironment.TEST.value
        if base.startswith(KsefEnvironment.DEMO.value):
            return KsefQrEnvironment.DEMO.value
        if base.startswith(KsefEnvironment.PROD.value):
            return KsefQrEnvironment.PROD.value
        raise ValueError("Unknown KSeF environment; set base_qr_url explicitly.")

    def resolve_lighthouse_base_url(self) -> str:
        if self.base_lighthouse_url:
            return self.base_lighthouse_url.rstrip("/")
        base = self.base_url.rstrip("/")
        if base.startswith(KsefLighthouseEnvironment.TEST.value):
            return KsefLighthouseEnvironment.TEST.value
        if base.startswith(KsefLighthouseEnvironment.PROD.value):
            return KsefLighthouseEnvironment.PROD.value
        if base.startswith(KsefEnvironment.TEST.value):
            return KsefLighthouseEnvironment.TEST.value
        if base.startswith(KsefEnvironment.DEMO.value):
            return KsefLighthouseEnvironment.TEST.value
        if base.startswith(KsefEnvironment.PROD.value):
            return KsefLighthouseEnvironment.PROD.value
        raise ValueError("Unknown KSeF environment; set base_lighthouse_url explicitly.")
