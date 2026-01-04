from __future__ import annotations

from typing import Optional

from .config import KsefClientOptions
from .http import BaseHttpClient, AsyncBaseHttpClient
from .clients.auth import AuthClient, AsyncAuthClient
from .clients.sessions import SessionsClient, AsyncSessionsClient
from .clients.invoices import InvoicesClient, AsyncInvoicesClient
from .clients.permissions import PermissionsClient, AsyncPermissionsClient
from .clients.certificates import CertificatesClient, AsyncCertificatesClient
from .clients.tokens import TokensClient, AsyncTokensClient
from .clients.limits import LimitsClient, AsyncLimitsClient
from .clients.rate_limits import RateLimitsClient, AsyncRateLimitsClient
from .clients.security import SecurityClient, AsyncSecurityClient
from .clients.testdata import TestDataClient, AsyncTestDataClient
from .clients.peppol import PeppolClient, AsyncPeppolClient


class KsefClient:
    def __init__(self, options: KsefClientOptions, access_token: Optional[str] = None) -> None:
        self._http = BaseHttpClient(options, access_token=access_token)
        self.auth = AuthClient(self._http)
        self.sessions = SessionsClient(self._http)
        self.invoices = InvoicesClient(self._http)
        self.permissions = PermissionsClient(self._http)
        self.certificates = CertificatesClient(self._http)
        self.tokens = TokensClient(self._http)
        self.limits = LimitsClient(self._http)
        self.rate_limits = RateLimitsClient(self._http)
        self.security = SecurityClient(self._http)
        self.testdata = TestDataClient(self._http)
        self.peppol = PeppolClient(self._http)

    def close(self) -> None:
        self._http.close()

    @property
    def http_client(self) -> BaseHttpClient:
        return self._http

    def __enter__(self) -> "KsefClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


class AsyncKsefClient:
    def __init__(self, options: KsefClientOptions, access_token: Optional[str] = None) -> None:
        self._http = AsyncBaseHttpClient(options, access_token=access_token)
        self.auth = AsyncAuthClient(self._http)
        self.sessions = AsyncSessionsClient(self._http)
        self.invoices = AsyncInvoicesClient(self._http)
        self.permissions = AsyncPermissionsClient(self._http)
        self.certificates = AsyncCertificatesClient(self._http)
        self.tokens = AsyncTokensClient(self._http)
        self.limits = AsyncLimitsClient(self._http)
        self.rate_limits = AsyncRateLimitsClient(self._http)
        self.security = AsyncSecurityClient(self._http)
        self.testdata = AsyncTestDataClient(self._http)
        self.peppol = AsyncPeppolClient(self._http)

    async def aclose(self) -> None:
        await self._http.aclose()

    @property
    def http_client(self) -> AsyncBaseHttpClient:
        return self._http

    async def __aenter__(self) -> "AsyncKsefClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()
