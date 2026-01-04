from __future__ import annotations

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from ..clients.auth import AuthClient, AsyncAuthClient
from ..clients.sessions import SessionsClient, AsyncSessionsClient
from ..clients.invoices import InvoicesClient, AsyncInvoicesClient
from ..http import BaseHttpClient, AsyncBaseHttpClient
from ..models import AuthenticationInitResponse, AuthenticationTokensResponse, StatusInfo
from .auth import build_auth_token_request_xml, build_ksef_token_auth_request, encrypt_ksef_token
from .crypto import EncryptionData, build_encryption_data, build_send_invoice_request, decrypt_aes_cbc_pkcs7
from .batch import encrypt_batch_parts
from ..utils.zip_utils import unzip_bytes_safe


class BatchUploadHelper:
    def __init__(self, http_client: BaseHttpClient) -> None:
        self._http = http_client

    def upload_parts(
        self,
        part_upload_requests: list[dict[str, Any]],
        parts: Sequence[bytes] | Sequence[Tuple[int, bytes]],
        *,
        parallelism: int = 1,
    ) -> None:
        if len(part_upload_requests) != len(parts):
            raise ValueError("parts length must match part_upload_requests length")

        pairs = _pair_requests_with_parts(part_upload_requests, parts)

        def _send(req: dict[str, Any], content: bytes) -> None:
            method = req.get("method", "PUT")
            url = req["url"]
            headers = req.get("headers") or {}
            self._http.request(
                method,
                url,
                headers=headers,
                data=content,
                skip_auth=True,
                expected_status={200, 201},
            )

        if parallelism <= 1:
            for req, part in pairs:
                _send(req, part)
            return

        with ThreadPoolExecutor(max_workers=parallelism) as executor:
            futures = [executor.submit(_send, req, part) for req, part in pairs]
            for fut in futures:
                fut.result()


class AsyncBatchUploadHelper:
    def __init__(self, http_client: AsyncBaseHttpClient) -> None:
        self._http = http_client

    async def upload_parts(
        self,
        part_upload_requests: list[dict[str, Any]],
        parts: Sequence[bytes] | Sequence[Tuple[int, bytes]],
    ) -> None:
        if len(part_upload_requests) != len(parts):
            raise ValueError("parts length must match part_upload_requests length")

        pairs = _pair_requests_with_parts(part_upload_requests, parts)

        async def _send(req: dict[str, Any], content: bytes) -> None:
            method = req.get("method", "PUT")
            url = req["url"]
            headers = req.get("headers") or {}
            await self._http.request(
                method,
                url,
                headers=headers,
                data=content,
                skip_auth=True,
                expected_status={200, 201},
            )

        tasks = [asyncio.create_task(_send(req, part)) for req, part in pairs]
        await asyncio.gather(*tasks)


class ExportDownloadHelper:
    def __init__(self, http_client: BaseHttpClient) -> None:
        self._http = http_client

    def download_parts(self, parts: list[dict[str, Any]]) -> list[bytes]:
        results: list[bytes] = []
        for part in parts:
            url = part["url"]
            method = part.get("method", "GET")
            content = self._http.request(method, url, skip_auth=True).content
            results.append(content)
        return results

    def download_parts_with_hash(self, parts: list[dict[str, Any]]) -> list[tuple[bytes, Optional[str]]]:
        results: list[tuple[bytes, Optional[str]]] = []
        for part in parts:
            url = part["url"]
            method = part.get("method", "GET")
            response = self._http.request(method, url, skip_auth=True)
            results.append((response.content, response.headers.get("x-ms-meta-hash")))
        return results


class AsyncExportDownloadHelper:
    def __init__(self, http_client: AsyncBaseHttpClient) -> None:
        self._http = http_client

    async def download_parts(self, parts: list[dict[str, Any]]) -> list[bytes]:
        results: list[bytes] = []
        for part in parts:
            url = part["url"]
            method = part.get("method", "GET")
            content = (await self._http.request(method, url, skip_auth=True)).content
            results.append(content)
        return results

    async def download_parts_with_hash(self, parts: list[dict[str, Any]]) -> list[tuple[bytes, Optional[str]]]:
        results: list[tuple[bytes, Optional[str]]] = []
        for part in parts:
            url = part["url"]
            method = part.get("method", "GET")
            response = await self._http.request(method, url, skip_auth=True)
            results.append((response.content, response.headers.get("x-ms-meta-hash")))
        return results


def _pair_requests_with_parts(
    part_upload_requests: list[dict[str, Any]],
    parts: Sequence[bytes] | Sequence[Tuple[int, bytes]],
) -> list[tuple[dict[str, Any], bytes]]:
    if parts and isinstance(parts[0], tuple):
        part_map = {int(ordinal): data for ordinal, data in parts}  # type: ignore[assignment]
        ordered_requests = sorted(part_upload_requests, key=lambda r: int(r.get("ordinalNumber", 0)))
        return [(req, part_map[int(req.get("ordinalNumber", 0))]) for req in ordered_requests]
    ordered_requests = sorted(part_upload_requests, key=lambda r: int(r.get("ordinalNumber", 0)))
    return list(zip(ordered_requests, parts))  # type: ignore[arg-type]


@dataclass(frozen=True)
class AuthResult:
    reference_number: str
    authentication_token: str
    tokens: AuthenticationTokensResponse


class AuthCoordinator:
    def __init__(self, auth_client: AuthClient) -> None:
        self._auth = auth_client

    def authenticate_with_xades(
        self,
        *,
        context_identifier_type: str,
        context_identifier_value: str,
        subject_identifier_type: str,
        certificate_pem: str,
        private_key_pem: str,
        verify_certificate_chain: Optional[bool] = None,
        authorization_policy_xml: Optional[str] = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        challenge = self._auth.get_challenge()
        xml = build_auth_token_request_xml(
            challenge=challenge["challenge"],
            context_identifier_type=context_identifier_type,
            context_identifier_value=context_identifier_value,
            subject_identifier_type=subject_identifier_type,
            authorization_policy_xml=authorization_policy_xml,
        )
        from .xades import sign_xades_enveloped

        signed_xml = sign_xades_enveloped(xml, certificate_pem, private_key_pem)
        init = self._auth.submit_xades_auth_request(
            signed_xml, verify_certificate_chain=verify_certificate_chain
        )
        init_response = AuthenticationInitResponse.from_dict(init)
        auth_token = init_response.authentication_token.token
        self._poll_auth_status(init_response.reference_number, auth_token, poll_interval_seconds, max_attempts)
        tokens = AuthenticationTokensResponse.from_dict(self._auth.redeem_token(auth_token))
        return AuthResult(
            reference_number=init_response.reference_number,
            authentication_token=auth_token,
            tokens=tokens,
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
        authorization_policy: Optional[dict[str, Any]] = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        challenge = self._auth.get_challenge()
        encrypted_token_b64 = encrypt_ksef_token(
            public_certificate=public_certificate,
            token=token,
            timestamp_ms=int(challenge["timestampMs"]),
            method=method,
            ec_output_format=ec_output_format,
        )
        request_payload = build_ksef_token_auth_request(
            challenge=challenge["challenge"],
            context_identifier_type=context_identifier_type,
            context_identifier_value=context_identifier_value,
            encrypted_token_base64=encrypted_token_b64,
            authorization_policy=authorization_policy,
        )
        init = self._auth.submit_ksef_token_auth(request_payload)
        init_response = AuthenticationInitResponse.from_dict(init)
        auth_token = init_response.authentication_token.token
        self._poll_auth_status(init_response.reference_number, auth_token, poll_interval_seconds, max_attempts)
        tokens = AuthenticationTokensResponse.from_dict(self._auth.redeem_token(auth_token))
        return AuthResult(
            reference_number=init_response.reference_number,
            authentication_token=auth_token,
            tokens=tokens,
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
            status_info = StatusInfo.from_dict(status.get("status", {}))
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
    def __init__(self, auth_client: AsyncAuthClient) -> None:
        self._auth = auth_client

    async def authenticate_with_xades(
        self,
        *,
        context_identifier_type: str,
        context_identifier_value: str,
        subject_identifier_type: str,
        certificate_pem: str,
        private_key_pem: str,
        verify_certificate_chain: Optional[bool] = None,
        authorization_policy_xml: Optional[str] = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        challenge = await self._auth.get_challenge()
        xml = build_auth_token_request_xml(
            challenge=challenge["challenge"],
            context_identifier_type=context_identifier_type,
            context_identifier_value=context_identifier_value,
            subject_identifier_type=subject_identifier_type,
            authorization_policy_xml=authorization_policy_xml,
        )
        from .xades import sign_xades_enveloped

        signed_xml = sign_xades_enveloped(xml, certificate_pem, private_key_pem)
        init = await self._auth.submit_xades_auth_request(
            signed_xml, verify_certificate_chain=verify_certificate_chain
        )
        init_response = AuthenticationInitResponse.from_dict(init)
        auth_token = init_response.authentication_token.token
        await self._poll_auth_status(init_response.reference_number, auth_token, poll_interval_seconds, max_attempts)
        tokens = AuthenticationTokensResponse.from_dict(await self._auth.redeem_token(auth_token))
        return AuthResult(
            reference_number=init_response.reference_number,
            authentication_token=auth_token,
            tokens=tokens,
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
        authorization_policy: Optional[dict[str, Any]] = None,
        poll_interval_seconds: float = 2.0,
        max_attempts: int = 30,
    ) -> AuthResult:
        challenge = await self._auth.get_challenge()
        encrypted_token_b64 = encrypt_ksef_token(
            public_certificate=public_certificate,
            token=token,
            timestamp_ms=int(challenge["timestampMs"]),
            method=method,
            ec_output_format=ec_output_format,
        )
        request_payload = build_ksef_token_auth_request(
            challenge=challenge["challenge"],
            context_identifier_type=context_identifier_type,
            context_identifier_value=context_identifier_value,
            encrypted_token_base64=encrypted_token_b64,
            authorization_policy=authorization_policy,
        )
        init = await self._auth.submit_ksef_token_auth(request_payload)
        init_response = AuthenticationInitResponse.from_dict(init)
        auth_token = init_response.authentication_token.token
        await self._poll_auth_status(init_response.reference_number, auth_token, poll_interval_seconds, max_attempts)
        tokens = AuthenticationTokensResponse.from_dict(await self._auth.redeem_token(auth_token))
        return AuthResult(
            reference_number=init_response.reference_number,
            authentication_token=auth_token,
            tokens=tokens,
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
            status_info = StatusInfo.from_dict(status.get("status", {}))
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


@dataclass(frozen=True)
class OnlineSessionResult:
    session_reference_number: str
    encryption_data: EncryptionData


class OnlineSessionWorkflow:
    def __init__(self, sessions_client: SessionsClient) -> None:
        self._sessions = sessions_client

    def open_session(
        self,
        *,
        form_code: dict[str, Any],
        public_certificate: str,
        access_token: str,
        upo_v43: bool = False,
    ) -> OnlineSessionResult:
        encryption = build_encryption_data(public_certificate)
        request_payload = {
            "formCode": form_code,
            "encryption": {
                "encryptedSymmetricKey": encryption.encryption_info.encrypted_symmetric_key,
                "initializationVector": encryption.encryption_info.initialization_vector,
            },
        }
        response = self._sessions.open_online_session(
            request_payload, access_token=access_token, upo_v43=upo_v43
        )
        return OnlineSessionResult(
            session_reference_number=response["referenceNumber"],
            encryption_data=encryption,
        )

    def send_invoice(
        self,
        *,
        session_reference_number: str,
        invoice_xml: bytes,
        encryption_data: EncryptionData,
        access_token: str,
        offline_mode: Optional[bool] = None,
        hash_of_corrected_invoice: Optional[str] = None,
    ) -> Any:
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
    def __init__(self, sessions_client: AsyncSessionsClient) -> None:
        self._sessions = sessions_client

    async def open_session(
        self,
        *,
        form_code: dict[str, Any],
        public_certificate: str,
        access_token: str,
        upo_v43: bool = False,
    ) -> OnlineSessionResult:
        encryption = build_encryption_data(public_certificate)
        request_payload = {
            "formCode": form_code,
            "encryption": {
                "encryptedSymmetricKey": encryption.encryption_info.encrypted_symmetric_key,
                "initializationVector": encryption.encryption_info.initialization_vector,
            },
        }
        response = await self._sessions.open_online_session(
            request_payload, access_token=access_token, upo_v43=upo_v43
        )
        return OnlineSessionResult(
            session_reference_number=response["referenceNumber"],
            encryption_data=encryption,
        )

    async def send_invoice(
        self,
        *,
        session_reference_number: str,
        invoice_xml: bytes,
        encryption_data: EncryptionData,
        access_token: str,
        offline_mode: Optional[bool] = None,
        hash_of_corrected_invoice: Optional[str] = None,
    ) -> Any:
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
    def __init__(self, sessions_client: SessionsClient, http_client: BaseHttpClient) -> None:
        self._sessions = sessions_client
        self._upload_helper = BatchUploadHelper(http_client)

    def open_upload_and_close(
        self,
        *,
        form_code: dict[str, Any],
        zip_bytes: bytes,
        public_certificate: str,
        access_token: str,
        offline_mode: Optional[bool] = None,
        upo_v43: bool = False,
        parallelism: int = 1,
    ) -> str:
        encryption = build_encryption_data(public_certificate)
        encrypted_parts, batch_file_info = encrypt_batch_parts(zip_bytes, encryption.key, encryption.iv)
        request_payload = {
            "formCode": form_code,
            "batchFile": batch_file_info,
            "encryption": {
                "encryptedSymmetricKey": encryption.encryption_info.encrypted_symmetric_key,
                "initializationVector": encryption.encryption_info.initialization_vector,
            },
        }
        if offline_mode is not None:
            request_payload["offlineMode"] = offline_mode
        response = self._sessions.open_batch_session(
            request_payload, access_token=access_token, upo_v43=upo_v43
        )
        part_upload_requests = response["partUploadRequests"]
        self._upload_helper.upload_parts(part_upload_requests, encrypted_parts, parallelism=parallelism)
        reference_number = response["referenceNumber"]
        self._sessions.close_batch_session(reference_number, access_token=access_token)
        return reference_number


class AsyncBatchSessionWorkflow:
    def __init__(self, sessions_client: AsyncSessionsClient, http_client: AsyncBaseHttpClient) -> None:
        self._sessions = sessions_client
        self._upload_helper = AsyncBatchUploadHelper(http_client)

    async def open_upload_and_close(
        self,
        *,
        form_code: dict[str, Any],
        zip_bytes: bytes,
        public_certificate: str,
        access_token: str,
        offline_mode: Optional[bool] = None,
        upo_v43: bool = False,
        parallelism: int = 1,
    ) -> str:
        encryption = build_encryption_data(public_certificate)
        encrypted_parts, batch_file_info = encrypt_batch_parts(zip_bytes, encryption.key, encryption.iv)
        request_payload = {
            "formCode": form_code,
            "batchFile": batch_file_info,
            "encryption": {
                "encryptedSymmetricKey": encryption.encryption_info.encrypted_symmetric_key,
                "initializationVector": encryption.encryption_info.initialization_vector,
            },
        }
        if offline_mode is not None:
            request_payload["offlineMode"] = offline_mode
        response = await self._sessions.open_batch_session(
            request_payload, access_token=access_token, upo_v43=upo_v43
        )
        part_upload_requests = response["partUploadRequests"]
        await self._upload_helper.upload_parts(part_upload_requests, encrypted_parts)
        reference_number = response["referenceNumber"]
        await self._sessions.close_batch_session(reference_number, access_token=access_token)
        return reference_number


@dataclass(frozen=True)
class PackageProcessingResult:
    metadata_summaries: list[dict[str, Any]]
    invoice_xml_files: dict[str, str]


class ExportWorkflow:
    def __init__(self, invoices_client: InvoicesClient, http_client: BaseHttpClient) -> None:
        self._invoices = invoices_client
        self._download_helper = ExportDownloadHelper(http_client)

    def download_and_process_package(
        self,
        package: dict[str, Any],
        encryption_data: EncryptionData,
    ) -> PackageProcessingResult:
        parts = package.get("parts") or []
        encrypted_parts = self._download_helper.download_parts(parts)
        decrypted_parts = [
            decrypt_aes_cbc_pkcs7(part, encryption_data.key, encryption_data.iv) for part in encrypted_parts
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
    def __init__(self, invoices_client: AsyncInvoicesClient, http_client: AsyncBaseHttpClient) -> None:
        self._invoices = invoices_client
        self._download_helper = AsyncExportDownloadHelper(http_client)

    async def download_and_process_package(
        self,
        package: dict[str, Any],
        encryption_data: EncryptionData,
    ) -> PackageProcessingResult:
        parts = package.get("parts") or []
        encrypted_parts = await self._download_helper.download_parts(parts)
        decrypted_parts = [
            decrypt_aes_cbc_pkcs7(part, encryption_data.key, encryption_data.iv) for part in encrypted_parts
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
