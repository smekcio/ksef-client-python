from __future__ import annotations

import asyncio
import base64
import hashlib
import time
from collections.abc import Callable, Collection, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Protocol, cast

from ..clients.invoices import AsyncInvoicesClient, InvoicesClient
from ..http import HttpResponse
from ..models import (
    AuthenticationChallengeResponse,
    AuthenticationInitResponse,
    AuthenticationOperationStatusResponse,
    AuthenticationTokensResponse,
    AuthorizationPolicy,
    EncryptionInfo,
    FormCode,
    InitTokenAuthenticationRequest,
    InvoicePackage,
    InvoicePackagePart,
    OpenBatchSessionRequest,
    OpenBatchSessionResponse,
    OpenOnlineSessionRequest,
    OpenOnlineSessionResponse,
    PartUploadRequest,
    SendInvoiceRequest,
    SendInvoiceResponse,
)
from ..utils.zip_utils import unzip_bytes_safe
from .auth import build_auth_token_request_xml, build_ksef_token_auth_request, encrypt_ksef_token
from .batch import encrypt_batch_parts
from .crypto import (
    EncryptionData,
    build_encryption_data,
    build_send_invoice_request,
    decrypt_aes_cbc_pkcs7,
)
from .sessions import (
    AsyncBatchSessionHandle,
    AsyncOnlineSessionHandle,
    BatchSessionHandle,
    BatchSessionState,
    OnlineSessionHandle,
    OnlineSessionState,
    _indexed_parts,
)
from .xades import XadesKeyPair


class _RequestHttpClient(Protocol):
    def request(self, *args: Any, **kwargs: Any) -> HttpResponse: ...


class _AsyncRequestHttpClient(Protocol):
    async def request(self, *args: Any, **kwargs: Any) -> HttpResponse: ...


class _SessionsClient(Protocol):
    def open_online_session(
        self,
        request_payload: OpenOnlineSessionRequest,
        *,
        access_token: str | None = None,
        upo_v43: bool = False,
    ) -> OpenOnlineSessionResponse: ...

    def send_online_invoice(
        self,
        reference_number: str,
        request_payload: SendInvoiceRequest,
        *,
        access_token: str | None = None,
    ) -> SendInvoiceResponse: ...

    def close_online_session(
        self, reference_number: str, access_token: str | None = None
    ) -> None: ...

    def open_batch_session(
        self,
        request_payload: OpenBatchSessionRequest,
        *,
        access_token: str | None = None,
        upo_v43: bool = False,
    ) -> OpenBatchSessionResponse: ...

    def close_batch_session(
        self, reference_number: str, access_token: str | None = None
    ) -> None: ...


class _AsyncSessionsClient(Protocol):
    async def open_online_session(
        self,
        request_payload: OpenOnlineSessionRequest,
        *,
        access_token: str | None = None,
        upo_v43: bool = False,
    ) -> OpenOnlineSessionResponse: ...

    async def send_online_invoice(
        self,
        reference_number: str,
        request_payload: SendInvoiceRequest,
        *,
        access_token: str | None = None,
    ) -> SendInvoiceResponse: ...

    async def close_online_session(
        self, reference_number: str, access_token: str | None = None
    ) -> None: ...

    async def open_batch_session(
        self,
        request_payload: OpenBatchSessionRequest,
        *,
        access_token: str | None = None,
        upo_v43: bool = False,
    ) -> OpenBatchSessionResponse: ...

    async def close_batch_session(
        self, reference_number: str, access_token: str | None = None
    ) -> None: ...


class _AuthClient(Protocol):
    def get_challenge(self) -> AuthenticationChallengeResponse: ...

    def submit_xades_auth_request(
        self,
        signed_xml: str,
        *,
        verify_certificate_chain: bool | None = None,
        enforce_xades_compliance: bool = False,
    ) -> AuthenticationInitResponse | None: ...

    def submit_ksef_token_auth(
        self, request_payload: InitTokenAuthenticationRequest
    ) -> AuthenticationInitResponse: ...

    def get_auth_status(
        self, reference_number: str, authentication_token: str
    ) -> AuthenticationOperationStatusResponse: ...

    def redeem_token(self, authentication_token: str) -> AuthenticationTokensResponse: ...


class _AsyncAuthClient(Protocol):
    async def get_challenge(self) -> AuthenticationChallengeResponse: ...

    async def submit_xades_auth_request(
        self,
        signed_xml: str,
        *,
        verify_certificate_chain: bool | None = None,
        enforce_xades_compliance: bool = False,
    ) -> AuthenticationInitResponse | None: ...

    async def submit_ksef_token_auth(
        self, request_payload: InitTokenAuthenticationRequest
    ) -> AuthenticationInitResponse: ...

    async def get_auth_status(
        self, reference_number: str, authentication_token: str
    ) -> AuthenticationOperationStatusResponse: ...

    async def redeem_token(self, authentication_token: str) -> AuthenticationTokensResponse: ...


class BatchUploadHelper:
    def __init__(self, http_client: _RequestHttpClient) -> None:
        self._http = http_client

    def upload_parts(
        self,
        part_upload_requests: list[PartUploadRequest],
        parts: Sequence[bytes] | Sequence[tuple[int, bytes]],
        *,
        parallelism: int = 1,
        skip_ordinals: Collection[int] | None = None,
        progress_callback: Callable[[int], None] | None = None,
    ) -> None:
        if len(part_upload_requests) != len(parts):
            raise ValueError("parts length must match part_upload_requests length")

        skip_set = {int(ordinal) for ordinal in (skip_ordinals or [])}
        pairs = [
            (req, part)
            for req, part in _pair_requests_with_parts(part_upload_requests, parts)
            if req.ordinal_number not in skip_set
        ]

        def _send(req: PartUploadRequest, content: bytes) -> None:
            self._http.request(
                req.method,
                req.url,
                headers=req.headers or {},
                data=content,
                skip_auth=True,
                expected_status={200, 201},
            )

        if parallelism <= 1:
            for req, part in pairs:
                _send(req, part)
                if progress_callback is not None:
                    progress_callback(req.ordinal_number)
            return

        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            futures = {executor.submit(_send, req, part): req.ordinal_number for req, part in pairs}
            for fut in as_completed(futures):
                fut.result()
                if progress_callback is not None:
                    progress_callback(futures[fut])


class AsyncBatchUploadHelper:
    def __init__(self, http_client: _AsyncRequestHttpClient) -> None:
        self._http = http_client

    async def upload_parts(
        self,
        part_upload_requests: list[PartUploadRequest],
        parts: Sequence[bytes] | Sequence[tuple[int, bytes]],
        *,
        skip_ordinals: Collection[int] | None = None,
        progress_callback: Callable[[int], None] | None = None,
    ) -> None:
        if len(part_upload_requests) != len(parts):
            raise ValueError("parts length must match part_upload_requests length")

        skip_set = {int(ordinal) for ordinal in (skip_ordinals or [])}
        pairs = [
            (req, part)
            for req, part in _pair_requests_with_parts(part_upload_requests, parts)
            if req.ordinal_number not in skip_set
        ]

        async def _send(req: PartUploadRequest, content: bytes) -> None:
            await self._http.request(
                req.method,
                req.url,
                headers=req.headers or {},
                data=content,
                skip_auth=True,
                expected_status={200, 201},
            )

        async def _send_with_ordinal(req: PartUploadRequest, content: bytes) -> int:
            await _send(req, content)
            return req.ordinal_number

        tasks = [asyncio.create_task(_send_with_ordinal(req, part)) for req, part in pairs]
        for task in asyncio.as_completed(tasks):
            ordinal_number = await task
            if progress_callback is not None:
                progress_callback(ordinal_number)


@dataclass(frozen=True)
class AuthResult:
    reference_number: str
    authentication_token: str
    tokens: AuthenticationTokensResponse

    @property
    def access_token(self) -> str:
        return self.tokens.access_token.token

    @property
    def refresh_token(self) -> str:
        return self.tokens.refresh_token.token


class AuthCoordinator:
    def __init__(self, auth_client: _AuthClient) -> None:
        self._auth = auth_client

    def authenticate_with_xades_key_pair(
        self,
        *,
        key_pair: XadesKeyPair,
        context_identifier_type: str,
        context_identifier_value: str,
        subject_identifier_type: str,
        verify_certificate_chain: bool | None = None,
        enforce_xades_compliance: bool = False,
        authorization_policy_xml: str | None = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        return self.authenticate_with_xades(
            context_identifier_type=context_identifier_type,
            context_identifier_value=context_identifier_value,
            subject_identifier_type=subject_identifier_type,
            certificate_pem=key_pair.certificate_pem,
            private_key_pem=key_pair.private_key_pem,
            verify_certificate_chain=verify_certificate_chain,
            enforce_xades_compliance=enforce_xades_compliance,
            authorization_policy_xml=authorization_policy_xml,
            poll_interval_seconds=poll_interval_seconds,
            max_attempts=max_attempts,
        )

    def authenticate_with_xades(
        self,
        *,
        context_identifier_type: str,
        context_identifier_value: str,
        subject_identifier_type: str,
        certificate_pem: str,
        private_key_pem: str,
        verify_certificate_chain: bool | None = None,
        enforce_xades_compliance: bool = False,
        authorization_policy_xml: str | None = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        challenge = self._auth.get_challenge()
        xml = build_auth_token_request_xml(
            challenge=challenge.challenge,
            context_identifier_type=context_identifier_type,
            context_identifier_value=context_identifier_value,
            subject_identifier_type=subject_identifier_type,
            authorization_policy_xml=authorization_policy_xml,
        )
        from .xades import sign_xades_enveloped

        signed_xml = sign_xades_enveloped(xml, certificate_pem, private_key_pem)
        init_response = self._auth.submit_xades_auth_request(
            signed_xml,
            verify_certificate_chain=verify_certificate_chain,
            enforce_xades_compliance=enforce_xades_compliance,
        )
        if init_response is None:
            raise RuntimeError("submit_xades_auth_request returned empty response")
        auth_token = init_response.authentication_token.token
        self._poll_auth_status(
            init_response.reference_number, auth_token, poll_interval_seconds, max_attempts
        )
        return AuthResult(
            reference_number=init_response.reference_number,
            authentication_token=auth_token,
            tokens=self._auth.redeem_token(auth_token),
        )

    def authenticate_with_ksef_token(
        self,
        *,
        token: str,
        public_certificate: str,
        context_identifier_type: str,
        context_identifier_value: str,
        method: str = "rsa",
        ec_output_format: str = "java",
        authorization_policy: AuthorizationPolicy | None = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        challenge = self._auth.get_challenge()
        encrypted_token_b64 = encrypt_ksef_token(
            public_certificate=public_certificate,
            token=token,
            timestamp_ms=challenge.timestamp_ms,
            method=method,
            ec_output_format=ec_output_format,
        )
        init_response = self._auth.submit_ksef_token_auth(
            build_ksef_token_auth_request(
                challenge=challenge.challenge,
                context_identifier_type=context_identifier_type,
                context_identifier_value=context_identifier_value,
                encrypted_token_base64=encrypted_token_b64,
                authorization_policy=authorization_policy,
            )
        )
        if init_response is None:
            raise RuntimeError("submit_ksef_token_auth returned empty response")
        auth_token = init_response.authentication_token.token
        self._poll_auth_status(
            init_response.reference_number, auth_token, poll_interval_seconds, max_attempts
        )
        return AuthResult(
            reference_number=init_response.reference_number,
            authentication_token=auth_token,
            tokens=self._auth.redeem_token(auth_token),
        )

    def _poll_auth_status(
        self,
        reference_number: str,
        authentication_token: str,
        poll_interval_seconds: float,
        max_attempts: int,
    ) -> None:
        for _ in range(max_attempts):
            status = self._auth.get_auth_status(reference_number, authentication_token)
            status_info = status.status
            if status_info.code == 200:
                return
            if status_info.code != 100:
                details = ""
                if status_info.details:
                    details = f" Details: {', '.join(status_info.details)}"
                raise RuntimeError(
                    f"Authentication failed: {status_info.code} {status_info.description}{details}"
                )
            time.sleep(poll_interval_seconds)
        raise TimeoutError("Authentication did not complete within max_attempts")


class AsyncAuthCoordinator:
    def __init__(self, auth_client: _AsyncAuthClient) -> None:
        self._auth = auth_client

    async def authenticate_with_xades_key_pair(
        self,
        *,
        key_pair: XadesKeyPair,
        context_identifier_type: str,
        context_identifier_value: str,
        subject_identifier_type: str,
        verify_certificate_chain: bool | None = None,
        enforce_xades_compliance: bool = False,
        authorization_policy_xml: str | None = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        return await self.authenticate_with_xades(
            context_identifier_type=context_identifier_type,
            context_identifier_value=context_identifier_value,
            subject_identifier_type=subject_identifier_type,
            certificate_pem=key_pair.certificate_pem,
            private_key_pem=key_pair.private_key_pem,
            verify_certificate_chain=verify_certificate_chain,
            enforce_xades_compliance=enforce_xades_compliance,
            authorization_policy_xml=authorization_policy_xml,
            poll_interval_seconds=poll_interval_seconds,
            max_attempts=max_attempts,
        )

    async def authenticate_with_xades(
        self,
        *,
        context_identifier_type: str,
        context_identifier_value: str,
        subject_identifier_type: str,
        certificate_pem: str,
        private_key_pem: str,
        verify_certificate_chain: bool | None = None,
        enforce_xades_compliance: bool = False,
        authorization_policy_xml: str | None = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        challenge = await self._auth.get_challenge()
        xml = build_auth_token_request_xml(
            challenge=challenge.challenge,
            context_identifier_type=context_identifier_type,
            context_identifier_value=context_identifier_value,
            subject_identifier_type=subject_identifier_type,
            authorization_policy_xml=authorization_policy_xml,
        )
        from .xades import sign_xades_enveloped

        signed_xml = sign_xades_enveloped(xml, certificate_pem, private_key_pem)
        init_response = await self._auth.submit_xades_auth_request(
            signed_xml,
            verify_certificate_chain=verify_certificate_chain,
            enforce_xades_compliance=enforce_xades_compliance,
        )
        if init_response is None:
            raise RuntimeError("submit_xades_auth_request returned empty response")
        auth_token = init_response.authentication_token.token
        await self._poll_auth_status(
            init_response.reference_number, auth_token, poll_interval_seconds, max_attempts
        )
        return AuthResult(
            reference_number=init_response.reference_number,
            authentication_token=auth_token,
            tokens=await self._auth.redeem_token(auth_token),
        )

    async def authenticate_with_ksef_token(
        self,
        *,
        token: str,
        public_certificate: str,
        context_identifier_type: str,
        context_identifier_value: str,
        method: str = "rsa",
        ec_output_format: str = "java",
        authorization_policy: AuthorizationPolicy | None = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        challenge = await self._auth.get_challenge()
        encrypted_token_b64 = encrypt_ksef_token(
            public_certificate=public_certificate,
            token=token,
            timestamp_ms=challenge.timestamp_ms,
            method=method,
            ec_output_format=ec_output_format,
        )
        init_response = await self._auth.submit_ksef_token_auth(
            build_ksef_token_auth_request(
                challenge=challenge.challenge,
                context_identifier_type=context_identifier_type,
                context_identifier_value=context_identifier_value,
                encrypted_token_base64=encrypted_token_b64,
                authorization_policy=authorization_policy,
            )
        )
        if init_response is None:
            raise RuntimeError("submit_ksef_token_auth returned empty response")
        auth_token = init_response.authentication_token.token
        await self._poll_auth_status(
            init_response.reference_number, auth_token, poll_interval_seconds, max_attempts
        )
        return AuthResult(
            reference_number=init_response.reference_number,
            authentication_token=auth_token,
            tokens=await self._auth.redeem_token(auth_token),
        )

    async def _poll_auth_status(
        self,
        reference_number: str,
        authentication_token: str,
        poll_interval_seconds: float,
        max_attempts: int,
    ) -> None:
        for _ in range(max_attempts):
            status = await self._auth.get_auth_status(reference_number, authentication_token)
            status_info = status.status
            if status_info.code == 200:
                return
            if status_info.code != 100:
                details = ""
                if status_info.details:
                    details = f" Details: {', '.join(status_info.details)}"
                raise RuntimeError(
                    f"Authentication failed: {status_info.code} {status_info.description}{details}"
                )
            await asyncio.sleep(poll_interval_seconds)
        raise TimeoutError("Authentication did not complete within max_attempts")


OnlineSessionResult = OnlineSessionHandle


class OnlineSessionWorkflow:
    def __init__(self, sessions_client: _SessionsClient) -> None:
        self._sessions = sessions_client

    def open_session(
        self,
        *,
        form_code: FormCode,
        public_certificate: str,
        access_token: str,
        upo_v43: bool = False,
    ) -> OnlineSessionHandle:
        encryption = build_encryption_data(public_certificate)
        response = self._sessions.open_online_session(
            OpenOnlineSessionRequest(
                form_code=form_code,
                encryption=_require_encryption_info(encryption),
            ),
            access_token=access_token,
            upo_v43=upo_v43,
        )
        return OnlineSessionHandle(
            _sessions=self._sessions,
            reference_number=response.reference_number,
            form_code=form_code,
            valid_until=response.valid_until,
            encryption_data=encryption,
            _access_token=access_token,
            upo_v43=upo_v43,
        )

    def resume_session(
        self,
        state: OnlineSessionState,
        *,
        access_token: str | None = None,
    ) -> OnlineSessionHandle:
        return OnlineSessionHandle.from_state(
            state,
            sessions_client=self._sessions,
            access_token=access_token,
        )

    def send_invoice(
        self,
        *,
        session_reference_number: str,
        invoice_xml: bytes,
        encryption_data: EncryptionData,
        access_token: str,
        offline_mode: bool | None = None,
        hash_of_corrected_invoice: str | None = None,
    ) -> SendInvoiceResponse:
        request_payload = build_send_invoice_request(
            invoice_xml,
            encryption_data.key,
            encryption_data.iv,
            offline_mode=offline_mode,
            hash_of_corrected_invoice=hash_of_corrected_invoice,
        )
        return self._sessions.send_online_invoice(
            session_reference_number,
            request_payload,
            access_token=access_token,
        )

    def close_session(self, reference_number: str, access_token: str) -> None:
        self._sessions.close_online_session(reference_number, access_token)


class AsyncOnlineSessionWorkflow:
    def __init__(self, sessions_client: _AsyncSessionsClient) -> None:
        self._sessions = sessions_client

    async def open_session(
        self,
        *,
        form_code: FormCode,
        public_certificate: str,
        access_token: str,
        upo_v43: bool = False,
    ) -> AsyncOnlineSessionHandle:
        encryption = build_encryption_data(public_certificate)
        response = await self._sessions.open_online_session(
            OpenOnlineSessionRequest(
                form_code=form_code,
                encryption=_require_encryption_info(encryption),
            ),
            access_token=access_token,
            upo_v43=upo_v43,
        )
        return AsyncOnlineSessionHandle(
            _sessions=self._sessions,
            reference_number=response.reference_number,
            form_code=form_code,
            valid_until=response.valid_until,
            encryption_data=encryption,
            _access_token=access_token,
            upo_v43=upo_v43,
        )

    def resume_session(
        self,
        state: OnlineSessionState,
        *,
        access_token: str | None = None,
    ) -> AsyncOnlineSessionHandle:
        return AsyncOnlineSessionHandle.from_state(
            state,
            sessions_client=self._sessions,
            access_token=access_token,
        )

    async def send_invoice(
        self,
        *,
        session_reference_number: str,
        invoice_xml: bytes,
        encryption_data: EncryptionData,
        access_token: str,
        offline_mode: bool | None = None,
        hash_of_corrected_invoice: str | None = None,
    ) -> SendInvoiceResponse:
        request_payload = build_send_invoice_request(
            invoice_xml,
            encryption_data.key,
            encryption_data.iv,
            offline_mode=offline_mode,
            hash_of_corrected_invoice=hash_of_corrected_invoice,
        )
        return await self._sessions.send_online_invoice(
            session_reference_number,
            request_payload,
            access_token=access_token,
        )

    async def close_session(self, reference_number: str, access_token: str) -> None:
        await self._sessions.close_online_session(reference_number, access_token)


class BatchSessionWorkflow:
    def __init__(self, sessions_client: _SessionsClient, http_client: _RequestHttpClient) -> None:
        self._sessions = sessions_client
        self._upload_helper = BatchUploadHelper(http_client)

    def open_session(
        self,
        *,
        form_code: FormCode,
        zip_bytes: bytes,
        public_certificate: str,
        access_token: str,
        offline_mode: bool | None = None,
        upo_v43: bool = False,
    ) -> BatchSessionHandle:
        encryption = build_encryption_data(public_certificate)
        encrypted_parts, batch_file_info = encrypt_batch_parts(
            zip_bytes, encryption.key, encryption.iv
        )
        response = self._sessions.open_batch_session(
            OpenBatchSessionRequest(
                form_code=form_code,
                batch_file=batch_file_info,
                encryption=_require_encryption_info(encryption),
                offline_mode=offline_mode,
            ),
            access_token=access_token,
            upo_v43=upo_v43,
        )
        return BatchSessionHandle(
            _sessions=self._sessions,
            _uploader=self._upload_helper,
            reference_number=response.reference_number,
            form_code=form_code,
            batch_file=batch_file_info,
            part_upload_requests=response.part_upload_requests,
            encryption_data=encryption,
            _access_token=access_token,
            upo_v43=upo_v43,
            offline_mode=offline_mode,
            _encrypted_parts=_indexed_parts(encrypted_parts),
        )

    def resume_session(
        self,
        state: BatchSessionState,
        *,
        zip_bytes: bytes,
        access_token: str | None = None,
    ) -> BatchSessionHandle:
        return BatchSessionHandle.from_state(
            state,
            sessions_client=self._sessions,
            uploader=self._upload_helper,
            access_token=access_token,
            zip_bytes=zip_bytes,
        )

    def open_upload_and_close(
        self,
        *,
        form_code: FormCode,
        zip_bytes: bytes,
        public_certificate: str,
        access_token: str,
        offline_mode: bool | None = None,
        upo_v43: bool = False,
        parallelism: int = 1,
    ) -> str:
        session = self.open_session(
            form_code=form_code,
            zip_bytes=zip_bytes,
            public_certificate=public_certificate,
            access_token=access_token,
            offline_mode=offline_mode,
            upo_v43=upo_v43,
        )
        session.upload_parts(parallelism=parallelism)
        session.close(access_token=access_token)
        return session.reference_number


class AsyncBatchSessionWorkflow:
    def __init__(
        self, sessions_client: _AsyncSessionsClient, http_client: _AsyncRequestHttpClient
    ) -> None:
        self._sessions = sessions_client
        self._upload_helper = AsyncBatchUploadHelper(http_client)

    async def open_session(
        self,
        *,
        form_code: FormCode,
        zip_bytes: bytes,
        public_certificate: str,
        access_token: str,
        offline_mode: bool | None = None,
        upo_v43: bool = False,
    ) -> AsyncBatchSessionHandle:
        encryption = build_encryption_data(public_certificate)
        encrypted_parts, batch_file_info = encrypt_batch_parts(
            zip_bytes, encryption.key, encryption.iv
        )
        response = await self._sessions.open_batch_session(
            OpenBatchSessionRequest(
                form_code=form_code,
                batch_file=batch_file_info,
                encryption=_require_encryption_info(encryption),
                offline_mode=offline_mode,
            ),
            access_token=access_token,
            upo_v43=upo_v43,
        )
        return AsyncBatchSessionHandle(
            _sessions=self._sessions,
            _uploader=self._upload_helper,
            reference_number=response.reference_number,
            form_code=form_code,
            batch_file=batch_file_info,
            part_upload_requests=response.part_upload_requests,
            encryption_data=encryption,
            _access_token=access_token,
            upo_v43=upo_v43,
            offline_mode=offline_mode,
            _encrypted_parts=_indexed_parts(encrypted_parts),
        )

    def resume_session(
        self,
        state: BatchSessionState,
        *,
        zip_bytes: bytes,
        access_token: str | None = None,
    ) -> AsyncBatchSessionHandle:
        return AsyncBatchSessionHandle.from_state(
            state,
            sessions_client=self._sessions,
            uploader=self._upload_helper,
            access_token=access_token,
            zip_bytes=zip_bytes,
        )

    async def open_upload_and_close(
        self,
        *,
        form_code: FormCode,
        zip_bytes: bytes,
        public_certificate: str,
        access_token: str,
        offline_mode: bool | None = None,
        upo_v43: bool = False,
        parallelism: int = 1,
    ) -> str:
        _ = parallelism
        session = await self.open_session(
            form_code=form_code,
            zip_bytes=zip_bytes,
            public_certificate=public_certificate,
            access_token=access_token,
            offline_mode=offline_mode,
            upo_v43=upo_v43,
        )
        await session.upload_parts()
        await session.close(access_token=access_token)
        return session.reference_number


class ExportDownloadHelper:
    def __init__(self, http_client: _RequestHttpClient) -> None:
        self._http = http_client

    def download_parts(self, parts: list[InvoicePackagePart]) -> list[bytes]:
        results: list[bytes] = []
        for part in parts:
            content = self._http.request(part.method, part.url, skip_auth=True).content
            results.append(content)
        return results

    def download_parts_with_hash(
        self, parts: list[InvoicePackagePart]
    ) -> list[tuple[bytes, str | None]]:
        results: list[tuple[bytes, str | None]] = []
        for part in parts:
            response = self._http.request(part.method, part.url, skip_auth=True)
            results.append((response.content, response.headers.get("x-ms-meta-hash")))
        return results


class AsyncExportDownloadHelper:
    def __init__(self, http_client: _AsyncRequestHttpClient) -> None:
        self._http = http_client

    async def download_parts(self, parts: list[InvoicePackagePart]) -> list[bytes]:
        results: list[bytes] = []
        for part in parts:
            content = (await self._http.request(part.method, part.url, skip_auth=True)).content
            results.append(content)
        return results

    async def download_parts_with_hash(
        self, parts: list[InvoicePackagePart]
    ) -> list[tuple[bytes, str | None]]:
        results: list[tuple[bytes, str | None]] = []
        for part in parts:
            response = await self._http.request(part.method, part.url, skip_auth=True)
            results.append((response.content, response.headers.get("x-ms-meta-hash")))
        return results


@dataclass(frozen=True)
class PackageProcessingResult:
    metadata_summaries: list[dict[str, Any]]
    invoice_xml_files: dict[str, str]


def _require_encryption_info(encryption_data: EncryptionData) -> EncryptionInfo:
    if encryption_data.encryption_info is None:
        raise ValueError("EncryptionData.encryption_info is required for this workflow step.")
    return encryption_data.encryption_info


class ExportWorkflow:
    def __init__(
        self,
        invoices_client: InvoicesClient,
        http_client: _RequestHttpClient,
        require_export_part_hash: bool | None = None,
    ) -> None:
        self._invoices = invoices_client
        self._download_helper = ExportDownloadHelper(http_client)
        self._require_export_part_hash = _resolve_export_part_hash_requirement(
            http_client=http_client,
            explicit_value=require_export_part_hash,
        )

    def download_and_process_package(
        self,
        package: InvoicePackage,
        encryption_data: EncryptionData,
    ) -> PackageProcessingResult:
        encrypted_parts_with_hash = self._download_helper.download_parts_with_hash(package.parts)
        for index, (part_bytes, part_hash) in enumerate(encrypted_parts_with_hash, start=1):
            _validate_export_part_hash(
                part_bytes,
                part_hash,
                require_export_part_hash=self._require_export_part_hash,
                part_index=index,
            )
        encrypted_parts = [part_bytes for part_bytes, _ in encrypted_parts_with_hash]
        decrypted_parts = [
            decrypt_aes_cbc_pkcs7(part, encryption_data.key, encryption_data.iv)
            for part in encrypted_parts
        ]
        archive_bytes = b"".join(decrypted_parts)
        unzipped = unzip_bytes_safe(archive_bytes)

        metadata_summaries: list[dict[str, Any]] = []
        invoice_xml_files: dict[str, str] = {}

        for name, content in unzipped.items():
            if name.lower() == "_metadata.json":
                import json

                metadata = json.loads(content.decode("utf-8"))
                invoices = metadata.get("invoices") or metadata.get("invoiceList") or []
                metadata_summaries.extend(invoices)
            elif name.lower().endswith(".xml"):
                invoice_xml_files[name] = content.decode("utf-8")

        return PackageProcessingResult(metadata_summaries, invoice_xml_files)


class AsyncExportWorkflow:
    def __init__(
        self,
        invoices_client: AsyncInvoicesClient,
        http_client: _AsyncRequestHttpClient,
        require_export_part_hash: bool | None = None,
    ) -> None:
        self._invoices = invoices_client
        self._download_helper = AsyncExportDownloadHelper(http_client)
        self._require_export_part_hash = _resolve_export_part_hash_requirement(
            http_client=http_client,
            explicit_value=require_export_part_hash,
        )

    async def download_and_process_package(
        self,
        package: InvoicePackage,
        encryption_data: EncryptionData,
    ) -> PackageProcessingResult:
        encrypted_parts_with_hash = await self._download_helper.download_parts_with_hash(
            package.parts
        )
        for index, (part_bytes, part_hash) in enumerate(encrypted_parts_with_hash, start=1):
            _validate_export_part_hash(
                part_bytes,
                part_hash,
                require_export_part_hash=self._require_export_part_hash,
                part_index=index,
            )
        encrypted_parts = [part_bytes for part_bytes, _ in encrypted_parts_with_hash]
        decrypted_parts = [
            decrypt_aes_cbc_pkcs7(part, encryption_data.key, encryption_data.iv)
            for part in encrypted_parts
        ]
        archive_bytes = b"".join(decrypted_parts)
        unzipped = unzip_bytes_safe(archive_bytes)

        metadata_summaries: list[dict[str, Any]] = []
        invoice_xml_files: dict[str, str] = {}

        for name, content in unzipped.items():
            if name.lower() == "_metadata.json":
                import json

                metadata = json.loads(content.decode("utf-8"))
                invoices = metadata.get("invoices") or metadata.get("invoiceList") or []
                metadata_summaries.extend(invoices)
            elif name.lower().endswith(".xml"):
                invoice_xml_files[name] = content.decode("utf-8")

        return PackageProcessingResult(metadata_summaries, invoice_xml_files)


def _pair_requests_with_parts(
    part_upload_requests: list[PartUploadRequest],
    parts: Sequence[bytes] | Sequence[tuple[int, bytes]],
) -> list[tuple[PartUploadRequest, bytes]]:
    if parts and isinstance(parts[0], tuple):
        indexed_parts = cast(Sequence[tuple[int, bytes]], parts)
        part_map: dict[int, bytes] = {int(ordinal): data for ordinal, data in indexed_parts}
        ordered_requests = sorted(part_upload_requests, key=lambda request: request.ordinal_number)
        return [(request, part_map[request.ordinal_number]) for request in ordered_requests]
    ordered_requests = sorted(part_upload_requests, key=lambda request: request.ordinal_number)
    byte_parts = cast(Sequence[bytes], parts)
    return list(zip(ordered_requests, byte_parts, strict=True))


def _resolve_export_part_hash_requirement(
    *, http_client: _RequestHttpClient | _AsyncRequestHttpClient, explicit_value: bool | None
) -> bool:
    if explicit_value is not None:
        return explicit_value
    options = getattr(http_client, "_options", None)
    if options is None:
        return True
    return bool(getattr(options, "require_export_part_hash", True))


def _validate_export_part_hash(
    part_bytes: bytes,
    expected_hash: str | None,
    *,
    require_export_part_hash: bool,
    part_index: int,
) -> None:
    if expected_hash is None:
        if require_export_part_hash:
            raise ValueError(f"Missing export part hash for part #{part_index}.")
        return
    actual_hash = base64.b64encode(hashlib.sha256(part_bytes).digest()).decode("ascii")
    if expected_hash != actual_hash:
        raise ValueError(
            f"Export part hash mismatch for part #{part_index}: "
            f"expected '{expected_hash}', got '{actual_hash}'."
        )
