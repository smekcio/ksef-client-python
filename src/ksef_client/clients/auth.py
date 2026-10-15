from __future__ import annotations

from typing import Any

import httpx

from ..http import HttpResponse
from ..models import (
    AuthenticationChallengeResponse,
    AuthenticationInitResponse,
    AuthenticationListResponse,
    AuthenticationOperationStatusResponse,
    AuthenticationTokenRefreshResponse,
    AuthenticationTokensResponse,
    InitTokenAuthenticationRequest,
)
from .base import AsyncBaseApiClient, BaseApiClient, _parse_json_response

_KSEF_FEATURE_HEADER = "X-KSeF-Feature"
_ENFORCE_XADES_COMPLIANCE_FEATURE = "enforce-xades-compliance"

#: Status odpowiedzi inicjującej uwierzytelnianie XAdES.
#:
#: Ścieżkę podajemy w wywołaniach `_request_*` jako literał — statyczne kontrole
#: (`tests/test_openapi_coverage.py`, `tools/check_coverage.py`) czytają ją z AST.
_INIT_RESPONSE_STATUS = 202


def _parse_init_response(
    response_bytes: bytes,
    *,
    path: str,
    content_type: str | None = None,
) -> AuthenticationInitResponse | None:
    """Parsuje odpowiedź 202 inicjującą uwierzytelnianie (puste ciało → ``None``).

    Brak JSON-a zgłaszamy wspólnym helperem ``_parse_json_response``: wcześniej ręczne
    ``json.loads`` przepuszczało surowy ``JSONDecodeError`` bez informacji, którego
    endpointu dotyczy i co przyszło zamiast JSON-a (przy 202 z HTML-em proxy albo
    captive portalu).

    ``_request_bytes`` zwraca same bajty, więc ``Content-Type`` przekazuje wołający —
    odtwarzamy z niego odpowiedź, której oczekuje wspólny helper.
    """
    if not response_bytes:
        return None
    headers = httpx.Headers({"Content-Type": content_type} if content_type else {})
    response = HttpResponse(_INIT_RESPONSE_STATUS, headers, response_bytes)
    payload = _parse_json_response(response, path=path)
    if not isinstance(payload, dict):
        raise TypeError(f"Expected JSON object response for {path}, got {type(payload).__name__}")
    return AuthenticationInitResponse.from_dict(payload)


class AuthClient(BaseApiClient):
    #: `Content-Type` ostatniej odpowiedzi z `_request_bytes` (patrz nadpisanie niżej).
    _last_content_type: str | None = None

    def _request_bytes(self, *args: Any, **kwargs: Any) -> bytes:
        """Wariant bazowego ``_request_bytes``, który zachowuje też ``Content-Type``.

        ``submit_xades_auth_request`` musi umieć powiedzieć, co przyszło zamiast JSON-a
        (proxy, captive portal), a bazowa metoda zwraca wyłącznie treść odpowiedzi.
        Nagłówki odczytujemy więc tutaj — w miejscu, gdzie odpowiedź jest jeszcze cała.
        """
        response = self._request_raw(*args, **kwargs)
        self._last_content_type = response.headers.get("Content-Type")
        return response.content
    def get_active_sessions(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> AuthenticationListResponse:
        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token
        params = {}
        if page_size is not None:
            params["pageSize"] = page_size
        return self._request_model(
            "GET",
            "/auth/sessions",
            response_model=AuthenticationListResponse,
            headers=headers or None,
            params=params or None,
            access_token=access_token,
        )

    def revoke_current_session(self, access_token: str) -> None:
        self._request_json(
            "DELETE",
            "/auth/sessions/current",
            access_token=access_token,
            expected_status={204},
        )

    def revoke_session(self, reference_number: str, access_token: str) -> None:
        self._request_json(
            "DELETE",
            f"/auth/sessions/{reference_number}",
            access_token=access_token,
            expected_status={204},
        )

    def get_challenge(self) -> AuthenticationChallengeResponse:
        return self._request_model(
            "POST",
            "/auth/challenge",
            response_model=AuthenticationChallengeResponse,
            skip_auth=True,
        )

    def submit_xades_auth_request(
        self,
        signed_xml: str,
        *,
        verify_certificate_chain: bool | None = None,
        enforce_xades_compliance: bool = False,
    ) -> AuthenticationInitResponse | None:
        params = {}
        if verify_certificate_chain is not None:
            params["verifyCertificateChain"] = verify_certificate_chain
        headers = {
            "Content-Type": "application/xml",
            "Accept": "application/json",
        }
        if enforce_xades_compliance:
            headers[_KSEF_FEATURE_HEADER] = _ENFORCE_XADES_COMPLIANCE_FEATURE
        # Czyścimy zapamiętany `Content-Type`, żeby komunikat błędu nie opisywał
        # nagłówkiem z poprzedniej odpowiedzi tego klienta.
        self._last_content_type = None
        response_bytes = self._request_bytes(
            "POST",
            "/auth/xades-signature",
            params=params or None,
            headers=headers,
            data=signed_xml.encode("utf-8"),
            skip_auth=True,
            expected_status={_INIT_RESPONSE_STATUS},
        )
        return _parse_init_response(
            response_bytes, path="/auth/xades-signature", content_type=self._last_content_type
        )

    def submit_ksef_token_auth(
        self, request_payload: InitTokenAuthenticationRequest
    ) -> AuthenticationInitResponse:
        return self._request_model(
            "POST",
            "/auth/ksef-token",
            response_model=AuthenticationInitResponse,
            json=request_payload,
            skip_auth=True,
            expected_status={202},
        )

    def get_auth_status(
        self, reference_number: str, authentication_token: str
    ) -> AuthenticationOperationStatusResponse:
        return self._request_model(
            "GET",
            f"/auth/{reference_number}",
            response_model=AuthenticationOperationStatusResponse,
            access_token=authentication_token,
        )

    def redeem_token(self, authentication_token: str) -> AuthenticationTokensResponse:
        return self._request_model(
            "POST",
            "/auth/token/redeem",
            response_model=AuthenticationTokensResponse,
            access_token=authentication_token,
        )

    def refresh_access_token(self, refresh_token: str) -> AuthenticationTokenRefreshResponse:
        return self._request_model(
            "POST",
            "/auth/token/refresh",
            response_model=AuthenticationTokenRefreshResponse,
            refresh_token=refresh_token,
        )


class AsyncAuthClient(AsyncBaseApiClient):
    #: `Content-Type` ostatniej odpowiedzi z `_request_bytes` (patrz nadpisanie niżej).
    _last_content_type: str | None = None

    async def _request_bytes(self, *args: Any, **kwargs: Any) -> bytes:
        """Wariant bazowego ``_request_bytes`` z zachowanym ``Content-Type``.

        Patrz ``AuthClient._request_bytes`` — komunikat błędu ma powiedzieć, co
        przyszło zamiast JSON-a, a bazowa metoda zwraca wyłącznie treść.
        """
        response = await self._request_raw(*args, **kwargs)
        self._last_content_type = response.headers.get("Content-Type")
        return response.content

    async def get_active_sessions(
        self,
        *,
        page_size: int | None = None,
        continuation_token: str | None = None,
        access_token: str | None = None,
    ) -> AuthenticationListResponse:
        headers = {}
        if continuation_token:
            headers["x-continuation-token"] = continuation_token
        params = {}
        if page_size is not None:
            params["pageSize"] = page_size
        return await self._request_model(
            "GET",
            "/auth/sessions",
            response_model=AuthenticationListResponse,
            headers=headers or None,
            params=params or None,
            access_token=access_token,
        )

    async def revoke_current_session(self, access_token: str) -> None:
        await self._request_json(
            "DELETE",
            "/auth/sessions/current",
            access_token=access_token,
            expected_status={204},
        )

    async def revoke_session(self, reference_number: str, access_token: str) -> None:
        await self._request_json(
            "DELETE",
            f"/auth/sessions/{reference_number}",
            access_token=access_token,
            expected_status={204},
        )

    async def get_challenge(self) -> AuthenticationChallengeResponse:
        return await self._request_model(
            "POST",
            "/auth/challenge",
            response_model=AuthenticationChallengeResponse,
            skip_auth=True,
        )

    async def submit_xades_auth_request(
        self,
        signed_xml: str,
        *,
        verify_certificate_chain: bool | None = None,
        enforce_xades_compliance: bool = False,
    ) -> AuthenticationInitResponse | None:
        params = {}
        if verify_certificate_chain is not None:
            params["verifyCertificateChain"] = verify_certificate_chain
        headers = {
            "Content-Type": "application/xml",
            "Accept": "application/json",
        }
        if enforce_xades_compliance:
            headers[_KSEF_FEATURE_HEADER] = _ENFORCE_XADES_COMPLIANCE_FEATURE
        # Patrz `AuthClient.submit_xades_auth_request`.
        self._last_content_type = None
        response_bytes = await self._request_bytes(
            "POST",
            "/auth/xades-signature",
            params=params or None,
            headers=headers,
            data=signed_xml.encode("utf-8"),
            skip_auth=True,
            expected_status={_INIT_RESPONSE_STATUS},
        )
        return _parse_init_response(
            response_bytes, path="/auth/xades-signature", content_type=self._last_content_type
        )

    async def submit_ksef_token_auth(
        self, request_payload: InitTokenAuthenticationRequest
    ) -> AuthenticationInitResponse:
        return await self._request_model(
            "POST",
            "/auth/ksef-token",
            response_model=AuthenticationInitResponse,
            json=request_payload,
            skip_auth=True,
            expected_status={202},
        )

    async def get_auth_status(
        self, reference_number: str, authentication_token: str
    ) -> AuthenticationOperationStatusResponse:
        return await self._request_model(
            "GET",
            f"/auth/{reference_number}",
            response_model=AuthenticationOperationStatusResponse,
            access_token=authentication_token,
        )

    async def redeem_token(self, authentication_token: str) -> AuthenticationTokensResponse:
        return await self._request_model(
            "POST",
            "/auth/token/redeem",
            response_model=AuthenticationTokensResponse,
            access_token=authentication_token,
        )

    async def refresh_access_token(self, refresh_token: str) -> AuthenticationTokenRefreshResponse:
        return await self._request_model(
            "POST",
            "/auth/token/refresh",
            response_model=AuthenticationTokenRefreshResponse,
            refresh_token=refresh_token,
        )
