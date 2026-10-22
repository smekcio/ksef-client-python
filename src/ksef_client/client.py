from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from .clients.auth import AsyncAuthClient, AuthClient
from .clients.certificates import AsyncCertificatesClient, CertificatesClient
from .clients.collective_identifiers import (
    AsyncCollectiveIdentifiersClient,
    CollectiveIdentifiersClient,
)
from .clients.invoices import AsyncInvoicesClient, InvoicesClient
from .clients.lighthouse import AsyncLighthouseClient, LighthouseClient
from .clients.limits import AsyncLimitsClient, LimitsClient
from .clients.peppol import AsyncPeppolClient, PeppolClient
from .clients.permissions import AsyncPermissionsClient, PermissionsClient
from .clients.rate_limits import AsyncRateLimitsClient, RateLimitsClient
from .clients.security import AsyncSecurityClient, SecurityClient
from .clients.sessions import AsyncSessionsClient, SessionsClient
from .clients.testdata import AsyncTestDataClient, TestDataClient
from .clients.tokens import AsyncTokensClient, TokensClient
from .config import KsefClientOptions
from .http import AsyncBaseHttpClient, BaseHttpClient
from .models import TokenInfo
from .token_manager import (
    DEFAULT_REFRESH_MARGIN_SECONDS,
    AsyncTokenManager,
    AsyncTokenRefreshingHttpClient,
    TokenManager,
    TokenRefreshingHttpClient,
)

if TYPE_CHECKING:
    from .services.workflows import AuthResult


class KsefClient:
    def __init__(
        self,
        options: KsefClientOptions,
        access_token: str | None = None,
        *,
        http_client: BaseHttpClient | None = None,
    ) -> None:
        if access_token is not None and http_client is not None:
            raise ValueError("Pass either access_token or http_client, not both")
        self._http = (
            http_client
            if http_client is not None
            else BaseHttpClient(options, access_token=access_token)
        )
        self._lighthouse_http = BaseHttpClient(options, access_token=None)
        lighthouse_base_url = ""
        try:
            lighthouse_base_url = options.resolve_lighthouse_base_url()
        except ValueError:
            lighthouse_base_url = ""
        self.auth = AuthClient(self._http)
        self.sessions = SessionsClient(self._http)
        self.invoices = InvoicesClient(self._http)
        self.lighthouse = LighthouseClient(
            self._lighthouse_http,
            lighthouse_base_url,
        )
        self.permissions = PermissionsClient(self._http)
        self.certificates = CertificatesClient(self._http)
        self.collective_identifiers = CollectiveIdentifiersClient(self._http)
        self.tokens = TokensClient(self._http)
        self.limits = LimitsClient(self._http)
        self.rate_limits = RateLimitsClient(self._http)
        self.security = SecurityClient(self._http)
        self.testdata = TestDataClient(self._http)
        self.peppol = PeppolClient(self._http)

    def close(self) -> None:
        try:
            self._http.close()
        finally:
            self._lighthouse_http.close()

    @property
    def http_client(self) -> BaseHttpClient:
        return self._http

    def __enter__(self) -> KsefClient:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class AsyncKsefClient:
    def __init__(
        self,
        options: KsefClientOptions,
        access_token: str | None = None,
        *,
        http_client: AsyncBaseHttpClient | None = None,
    ) -> None:
        if access_token is not None and http_client is not None:
            raise ValueError("Pass either access_token or http_client, not both")
        self._http = (
            http_client
            if http_client is not None
            else AsyncBaseHttpClient(options, access_token=access_token)
        )
        self._lighthouse_http = AsyncBaseHttpClient(options, access_token=None)
        lighthouse_base_url = ""
        try:
            lighthouse_base_url = options.resolve_lighthouse_base_url()
        except ValueError:
            lighthouse_base_url = ""
        self.auth = AsyncAuthClient(self._http)
        self.sessions = AsyncSessionsClient(self._http)
        self.invoices = AsyncInvoicesClient(self._http)
        self.lighthouse = AsyncLighthouseClient(
            self._lighthouse_http,
            lighthouse_base_url,
        )
        self.permissions = AsyncPermissionsClient(self._http)
        self.certificates = AsyncCertificatesClient(self._http)
        self.collective_identifiers = AsyncCollectiveIdentifiersClient(self._http)
        self.tokens = AsyncTokensClient(self._http)
        self.limits = AsyncLimitsClient(self._http)
        self.rate_limits = AsyncRateLimitsClient(self._http)
        self.security = AsyncSecurityClient(self._http)
        self.testdata = AsyncTestDataClient(self._http)
        self.peppol = AsyncPeppolClient(self._http)

    async def aclose(self) -> None:
        try:
            await self._http.aclose()
        finally:
            await self._lighthouse_http.aclose()

    @property
    def http_client(self) -> AsyncBaseHttpClient:
        return self._http

    async def __aenter__(self) -> AsyncKsefClient:
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()


class AuthenticatedClient(KsefClient):
    """Klient KSeF, który sam wstrzykuje i odświeża token dostępowy.

    Token nie jest już wymagany w żadnej metodzie klientów: gdy wołający go nie
    poda, :class:`~ksef_client.token_manager.TokenRefreshingHttpClient` pobiera
    go z :class:`~ksef_client.token_manager.TokenManager` (odświeżając proaktywnie
    60 s przed wygaśnięciem). Odpowiedź 401 na token z managera powoduje jedno
    odświeżenie i powtórzenie żądania.

    Jawne ``access_token=...`` w metodzie nadal działa i ma pierwszeństwo —
    dotychczasowy kod nie wymaga żadnych zmian.

    Args:
        options: Opcje klienta (mogą zawierać ``retry``).
        token_manager: Manager tokenów (np. z
            :meth:`AuthenticatedClient.from_auth_result`).
        http_client: Opcjonalny, własny transport — musi to być
            :class:`~ksef_client.token_manager.TokenRefreshingHttpClient`
            korzystający z tego samego ``token_manager``.

    Example:
        ```python
        with AuthenticatedClient.from_auth_result(options, auth_result) as client:
            session = client.sessions.open_session(...)   # bez access_token
        ```
    """

    def __init__(
        self,
        options: KsefClientOptions,
        token_manager: TokenManager,
        *,
        http_client: BaseHttpClient | None = None,
    ) -> None:
        if http_client is not None and not isinstance(http_client, TokenRefreshingHttpClient):
            raise ValueError(
                "http_client must be a TokenRefreshingHttpClient (it injects the managed token)"
            )
        if http_client is not None and http_client.token_manager is not token_manager:
            raise ValueError("http_client and token_manager must use the same TokenManager")
        super().__init__(
            options,
            http_client=http_client
            if http_client is not None
            else TokenRefreshingHttpClient(options, token_manager),
        )
        self.token_manager = token_manager
        token_manager.bind_auth_client(self.auth)

    @classmethod
    def from_auth_result(
        cls,
        options: KsefClientOptions,
        auth_result: AuthResult,
        *,
        refresh_margin_seconds: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        on_refresh: Callable[[TokenInfo], None] | None = None,
    ) -> AuthenticatedClient:
        """Buduje klienta z wyniku :class:`~ksef_client.services.AuthCoordinator`.

        Args:
            options: Opcje klienta.
            auth_result: Wynik uwierzytelnienia (``AuthResult`` z tokenami).
            refresh_margin_seconds: Zapas przed wygaśnięciem tokena.
            on_refresh: Callback po odświeżeniu (np. zapis tokena do keyringa).
        """
        manager = TokenManager.from_tokens(
            auth_result.tokens,
            refresh_margin_seconds=refresh_margin_seconds,
            on_refresh=on_refresh,
        )
        return cls(options, manager)


class AsyncAuthenticatedClient(AsyncKsefClient):
    """Asynchroniczny odpowiednik :class:`AuthenticatedClient`."""

    def __init__(
        self,
        options: KsefClientOptions,
        token_manager: AsyncTokenManager,
        *,
        http_client: AsyncBaseHttpClient | None = None,
    ) -> None:
        if http_client is not None and not isinstance(
            http_client, AsyncTokenRefreshingHttpClient
        ):
            raise ValueError(
                "http_client must be an AsyncTokenRefreshingHttpClient "
                "(it injects the managed token)"
            )
        if http_client is not None and http_client.token_manager is not token_manager:
            raise ValueError("http_client and token_manager must use the same AsyncTokenManager")
        super().__init__(
            options,
            http_client=http_client
            if http_client is not None
            else AsyncTokenRefreshingHttpClient(options, token_manager),
        )
        self.token_manager = token_manager
        token_manager.bind_auth_client(self.auth)

    @classmethod
    def from_auth_result(
        cls,
        options: KsefClientOptions,
        auth_result: AuthResult,
        *,
        refresh_margin_seconds: float = DEFAULT_REFRESH_MARGIN_SECONDS,
        on_refresh: Callable[[TokenInfo], Awaitable[None] | None] | None = None,
    ) -> AsyncAuthenticatedClient:
        """Buduje asynchronicznego klienta z wyniku ``AuthCoordinator``."""
        manager = AsyncTokenManager.from_tokens(
            auth_result.tokens,
            refresh_margin_seconds=refresh_margin_seconds,
            on_refresh=on_refresh,
        )
        return cls(options, manager)
