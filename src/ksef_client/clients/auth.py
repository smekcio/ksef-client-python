from __future__ import annotations

import json

from ..models import (
    AuthenticationChallengeResponse,
    AuthenticationInitResponse,
    AuthenticationListResponse,
    AuthenticationOperationStatusResponse,
    AuthenticationTokenRefreshResponse,
    AuthenticationTokensResponse,
    InitTokenAuthenticationRequest,
)
from .base import AsyncBaseApiClient, BaseApiClient

_KSEF_FEATURE_HEADER = "X-KSeF-Feature"
_ENFORCE_XADES_COMPLIANCE_FEATURE = "enforce-xades-compliance"


def _parse_init_response(response_bytes: bytes, *, path: str) -> AuthenticationInitResponse | None:
    if not response_bytes:
        return None
    payload = json.loads(response_bytes.decode("utf-8"))
    if not isinstance(payload, dict):
        raise TypeError(f"Expected JSON object response for {path}, got {type(payload).__name__}")
    return AuthenticationInitResponse.from_dict(payload)


class AuthClient(BaseApiClient):
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
        response_bytes = self._request_bytes(
            "POST",
            "/auth/xades-signature",
            params=params or None,
            headers=headers,
            data=signed_xml.encode("utf-8"),
            skip_auth=True,
            expected_status={202},
        )
        return _parse_init_response(response_bytes, path="/auth/xades-signature")

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
        response_bytes = await self._request_bytes(
            "POST",
            "/auth/xades-signature",
            params=params or None,
            headers=headers,
            data=signed_xml.encode("utf-8"),
            skip_auth=True,
            expected_status={202},
        )
        return _parse_init_response(response_bytes, path="/auth/xades-signature")

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
