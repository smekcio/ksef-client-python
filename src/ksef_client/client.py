from __future__ import annotations

from .clients.auth import AsyncAuthClient, AuthClient
from .clients.certificates import AsyncCertificatesClient, CertificatesClient
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


class KsefClient:
    def __init__(self, options: KsefClientOptions, access_token: str | None = None) -> None:
        self._http = BaseHttpClient(options, access_token=access_token)
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
    def __init__(self, options: KsefClientOptions, access_token: str | None = None) -> None:
        self._http = AsyncBaseHttpClient(options, access_token=access_token)
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
