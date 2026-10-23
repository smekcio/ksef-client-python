from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from importlib import metadata
from typing import TYPE_CHECKING, Any

from .retry import RetryConfig

if TYPE_CHECKING:
    from .profiles import Profile, ProfileStore


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
    proxy: str | None = field(default=None, repr=False)
    custom_headers: dict[str, str] | None = field(default=None, repr=False)
    #: Czy podążać za przekierowaniami żądań **uwierzytelnionych**. Żądania z
    #: `skip_auth=True` (pre-signed URL, wywołania bez nagłówka `Authorization`)
    #: nigdy nie podążają za przekierowaniem: walidacja bezpieczeństwa dotyczy
    #: wyłącznie adresu początkowego, więc przekierowanie wykonałoby żądanie pod
    #: adres wskazany przez serwer (także do sieci wewnętrznej) i zwróciło jego
    #: treść jako wynik. 3xx w takim żądaniu jest błędem (`KsefHttpError`).
    follow_redirects: bool = False
    verify_ssl: bool = True
    require_export_part_hash: bool = True
    strict_presigned_url_validation: bool = True
    allowed_presigned_hosts: list[str] | None = None
    allow_private_network_presigned_urls: bool = False
    system_warning_handler: Callable[[str], None] | None = None
    user_agent: str = field(default_factory=_default_user_agent)
    #: Konfiguracja automatycznego ponawiania żądań HTTP. ``None`` (domyślnie)
    #: oznacza brak retry — zachowanie identyczne z wersjami sprzed dodania pola.
    #: Retry jest opt-in, bo ponawianie ``POST`` (wysyłka faktury, redeem tokena)
    #: wymaga świadomej decyzji wołającego.
    retry: RetryConfig | None = None

    def __post_init__(self) -> None:
        if self.retry is not None and not isinstance(self.retry, RetryConfig):
            raise TypeError("retry must be a RetryConfig instance or None")

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

    @classmethod
    def from_profile(
        cls,
        profile: Profile | str,
        *,
        store: ProfileStore | None = None,
        **overrides: Any,
    ) -> KsefClientOptions:
        """Buduje opcje klienta z profilu (obiektu albo nazwy w magazynie).

        Profile są wspólne z CLI, więc konfiguracja utworzona przez
        ``ksef init`` działa bez powielania ustawień w kodzie.

        Args:
            profile: Obiekt :class:`~ksef_client.profiles.Profile` albo nazwa
                profilu do odczytania ze ``store``.
            store: Magazyn profili; ``None`` oznacza
                :meth:`~ksef_client.profiles.ProfileStore.default`.
            **overrides: Pola nadpisujące wartości z profilu (np.
                ``timeout_seconds=10``). Jawne ``base_url`` ma pierwszeństwo
                przed adresem z profilu.

        Returns:
            Opcje gotowe do przekazania do ``KsefClient``.

        Raises:
            ProfileError: Gdy nazwa nie istnieje albo plik profili jest
                uszkodzony.

        Example:
            ```python
            options = KsefClientOptions.from_profile("demo")
            client = KsefClient(options)
            ```
        """
        from .profiles import ProfileStore

        if isinstance(profile, str):
            resolved = (store or ProfileStore.default()).get(profile)
        else:
            resolved = profile
        options: dict[str, Any] = {"base_url": resolved.base_url}
        options.update(overrides)
        return cls(**options)
