import base64
import hashlib
import json
import unittest
from dataclasses import dataclass
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import httpx

from ksef_client import models as m
from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.config import KsefClientOptions
from ksef_client.http import HttpResponse
from ksef_client.services import workflows
from ksef_client.services.crypto import encrypt_aes_cbc_pkcs7, generate_iv, generate_symmetric_key
from ksef_client.services.xades import XadesKeyPair
from ksef_client.utils.zip_utils import build_zip
from tests.helpers import generate_rsa_cert


def _sha256_b64(payload: bytes) -> str:
    return base64.b64encode(hashlib.sha256(payload).digest()).decode("ascii")


def _challenge_response() -> m.AuthenticationChallengeResponse:
    return m.AuthenticationChallengeResponse.from_dict(
        {
            "challenge": "c",
            "timestamp": "2026-03-27T12:00:00Z",
            "timestampMs": 123,
            "clientIp": "127.0.0.1",
        }
    )


def _auth_init_response() -> m.AuthenticationInitResponse:
    return m.AuthenticationInitResponse.from_dict(
        {
            "referenceNumber": "ref",
            "authenticationToken": {
                "token": "auth",
                "validUntil": "2026-03-27T12:00:00Z",
            },
        }
    )


def _auth_status_response(
    code: int, details: list[str] | None = None
) -> m.AuthenticationOperationStatusResponse:
    payload: dict[str, Any] = {
        "authenticationMethod": list(m.AuthenticationMethod)[0].value,
        "authenticationMethodInfo": {
            "category": list(m.AuthenticationMethodCategory)[0].value,
            "code": "auth.method.code",
            "displayName": "Auth method",
        },
        "startDate": "2026-03-27T12:00:00Z",
        "status": {"code": code, "description": "desc"},
    }
    if details is not None:
        payload["status"]["details"] = details
    return m.AuthenticationOperationStatusResponse.from_dict(payload)


def _auth_tokens_response() -> m.AuthenticationTokensResponse:
    return m.AuthenticationTokensResponse.from_dict(
        {
            "accessToken": {"token": "acc", "validUntil": "2026-03-27T12:00:00Z"},
            "refreshToken": {"token": "ref", "validUntil": "2026-03-28T12:00:00Z"},
        }
    )


def _open_online_session_response() -> m.OpenOnlineSessionResponse:
    return m.OpenOnlineSessionResponse.from_dict(
        {"referenceNumber": "ref", "validUntil": "2026-03-27T12:00:00Z"}
    )


def _send_invoice_response() -> m.SendInvoiceResponse:
    return m.SendInvoiceResponse.from_dict({"referenceNumber": "inv-ref"})


def _part_upload_request() -> m.PartUploadRequest:
    return m.PartUploadRequest.from_dict(
        {
            "ordinalNumber": 1,
            "url": "https://upload",
            "method": "PUT",
            "headers": {"x": "y"},
        }
    )


def _open_batch_session_response() -> m.OpenBatchSessionResponse:
    return m.OpenBatchSessionResponse.from_dict(
        {
            "referenceNumber": "ref",
            "partUploadRequests": [_part_upload_request().to_dict()],
        }
    )


def _package_part(url: str = "https://download") -> m.InvoicePackagePart:
    return m.InvoicePackagePart.from_dict(
        {
            "ordinalNumber": 1,
            "partName": "p1",
            "method": "GET",
            "url": url,
            "partSize": 1,
            "partHash": "h",
            "encryptedPartSize": 2,
            "encryptedPartHash": "eh",
            "expirationDate": "2026-03-27T12:00:00Z",
        }
    )


def _invoice_package(url: str = "https://download") -> m.InvoicePackage:
    return m.InvoicePackage.from_dict(
        {
            "invoiceCount": 1,
            "size": 1,
            "isTruncated": False,
            "parts": [_package_part(url).to_dict()],
        }
    )


def _empty_invoice_package() -> m.InvoicePackage:
    return m.InvoicePackage.from_dict(
        {
            "invoiceCount": 0,
            "size": 0,
            "isTruncated": False,
            "parts": [],
        }
    )


def _form_code() -> m.FormCode:
    return m.FormCode(system_code="FA", schema_version="1-0E", value="FA")


class RecordingHttp:
    def __init__(self, content: bytes = b"ok", headers: dict | None = None) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.response = HttpResponse(200, httpx.Headers(headers or {}), content)

    def request(self, *args, **kwargs) -> HttpResponse:
        self.calls.append((args, kwargs))
        return self.response


class RecordingAsyncHttp:
    def __init__(self, content: bytes = b"ok", headers: dict | None = None) -> None:
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.response = HttpResponse(200, httpx.Headers(headers or {}), content)

    async def request(self, *args, **kwargs) -> HttpResponse:
        self.calls.append((args, kwargs))
        return self.response


@dataclass
class StubAuthClient:
    codes: list[int]
    last_enforce_xades_compliance: bool = False
    last_ksef_token_payload: m.InitTokenAuthenticationRequest | None = None

    def get_challenge(self):
        return _challenge_response()

    def submit_xades_auth_request(
        self,
        signed_xml: str,
        verify_certificate_chain=None,
        enforce_xades_compliance: bool = False,
    ):
        self.last_enforce_xades_compliance = enforce_xades_compliance
        return _auth_init_response()

    def submit_ksef_token_auth(self, payload):
        self.last_ksef_token_payload = payload
        return _auth_init_response()

    def get_auth_status(self, reference_number, authentication_token):
        code = self.codes.pop(0)
        return _auth_status_response(code)

    def redeem_token(self, authentication_token):
        return _auth_tokens_response()


@dataclass
class StubAsyncAuthClient:
    codes: list[int]
    last_enforce_xades_compliance: bool = False
    last_ksef_token_payload: m.InitTokenAuthenticationRequest | None = None

    async def get_challenge(self):
        return _challenge_response()

    async def submit_xades_auth_request(
        self,
        signed_xml: str,
        verify_certificate_chain=None,
        enforce_xades_compliance: bool = False,
    ):
        self.last_enforce_xades_compliance = enforce_xades_compliance
        return _auth_init_response()

    async def submit_ksef_token_auth(self, payload):
        self.last_ksef_token_payload = payload
        return _auth_init_response()

    async def get_auth_status(self, reference_number, authentication_token):
        code = self.codes.pop(0)
        return _auth_status_response(code)

    async def redeem_token(self, authentication_token):
        return _auth_tokens_response()


class StubSessionsClient:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def open_online_session(
        self,
        payload: m.OpenOnlineSessionRequest,
        *,
        access_token: str | None = None,
        upo_v43: bool = False,
    ) -> m.OpenOnlineSessionResponse:
        self.calls.append(("open_online", payload, access_token, upo_v43))
        return _open_online_session_response()

    def send_online_invoice(
        self,
        reference_number: str,
        request_payload: m.SendInvoiceRequest,
        *,
        access_token: str | None = None,
    ) -> m.SendInvoiceResponse:
        self.calls.append(("send", reference_number, request_payload, access_token))
        return _send_invoice_response()

    def close_online_session(
        self,
        reference_number: str,
        access_token: str | None = None,
    ) -> None:
        self.calls.append(("close", reference_number, access_token))

    def open_batch_session(
        self,
        payload: m.OpenBatchSessionRequest,
        *,
        access_token: str | None = None,
        upo_v43: bool = False,
    ) -> m.OpenBatchSessionResponse:
        self.calls.append(("open_batch", payload, access_token, upo_v43))
        return _open_batch_session_response()

    def close_batch_session(
        self,
        reference_number: str,
        access_token: str | None = None,
    ) -> None:
        self.calls.append(("close_batch", reference_number, access_token))


class StubAsyncSessionsClient:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    async def open_online_session(
        self,
        payload: m.OpenOnlineSessionRequest,
        *,
        access_token: str | None = None,
        upo_v43: bool = False,
    ) -> m.OpenOnlineSessionResponse:
        self.calls.append(("open_online", payload, access_token, upo_v43))
        return _open_online_session_response()

    async def send_online_invoice(
        self,
        reference_number: str,
        request_payload: m.SendInvoiceRequest,
        *,
        access_token: str | None = None,
    ) -> m.SendInvoiceResponse:
        self.calls.append(("send", reference_number, request_payload, access_token))
        return _send_invoice_response()

    async def close_online_session(
        self,
        reference_number: str,
        access_token: str | None = None,
    ) -> None:
        self.calls.append(("close", reference_number, access_token))

    async def open_batch_session(
        self,
        payload: m.OpenBatchSessionRequest,
        *,
        access_token: str | None = None,
        upo_v43: bool = False,
    ) -> m.OpenBatchSessionResponse:
        self.calls.append(("open_batch", payload, access_token, upo_v43))
        return _open_batch_session_response()

    async def close_batch_session(
        self,
        reference_number: str,
        access_token: str | None = None,
    ) -> None:
        self.calls.append(("close_batch", reference_number, access_token))


class WorkflowsTests(unittest.TestCase):
    def test_pair_requests_with_parts(self):
        reqs = [
            m.PartUploadRequest.from_dict(
                {"ordinalNumber": 2, "url": "u2", "method": "PUT", "headers": {}}
            ),
            m.PartUploadRequest.from_dict(
                {"ordinalNumber": 1, "url": "u1", "method": "PUT", "headers": {}}
            ),
        ]
        parts = [(1, b"a"), (2, b"b")]
        paired = workflows._pair_requests_with_parts(reqs, parts)
        self.assertEqual(paired[0][1], b"a")

        paired_direct = workflows._pair_requests_with_parts(reqs, [b"a", b"b"])
        self.assertEqual(len(paired_direct), 2)

    def test_batch_upload_helper(self):
        http = RecordingHttp()
        helper = workflows.BatchUploadHelper(http)
        reqs = [_part_upload_request()]
        helper.upload_parts(reqs, [b"data"], parallelism=1)
        self.assertEqual(len(http.calls), 1)

        with self.assertRaises(ValueError):
            helper.upload_parts(reqs, [b"a", b"b"], parallelism=1)

        helper.upload_parts(reqs, [b"data"], parallelism=2)
        self.assertEqual(len(http.calls), 2)

    def test_export_download_helper(self):
        http = RecordingHttp(content=b"part", headers={"x-ms-meta-hash": "hash"})
        helper = workflows.ExportDownloadHelper(http)
        parts = [_package_part()]
        data = helper.download_parts(parts)
        self.assertEqual(data, [b"part"])
        data_with_hash = helper.download_parts_with_hash(parts)
        self.assertEqual(data_with_hash[0][1], "hash")

    def test_auth_coordinator_success_and_errors(self):
        auth = StubAuthClient([100, 200])
        coord = workflows.AuthCoordinator(auth)
        rsa_cert = generate_rsa_cert()
        with patch("ksef_client.services.xades.sign_xades_enveloped", return_value="signed"):
            result = coord.authenticate_with_xades(
                context_identifier_type="nip",
                context_identifier_value="123",
                subject_identifier_type="certificateSubject",
                certificate_pem=rsa_cert.certificate_pem,
                private_key_pem=rsa_cert.private_key_pem,
                poll_interval_seconds=0,
                max_attempts=2,
            )
        self.assertEqual(result.authentication_token, "auth")
        self.assertFalse(auth.last_enforce_xades_compliance)

        auth_with_feature = StubAuthClient([200])
        coord_with_feature = workflows.AuthCoordinator(auth_with_feature)
        with patch("ksef_client.services.xades.sign_xades_enveloped", return_value="signed"):
            coord_with_feature.authenticate_with_xades(
                context_identifier_type="nip",
                context_identifier_value="123",
                subject_identifier_type="certificateSubject",
                certificate_pem=rsa_cert.certificate_pem,
                private_key_pem=rsa_cert.private_key_pem,
                enforce_xades_compliance=True,
                poll_interval_seconds=0,
                max_attempts=1,
            )
        self.assertTrue(auth_with_feature.last_enforce_xades_compliance)

        with patch("ksef_client.services.xades.sign_xades_enveloped", return_value="signed"):
            coord_pair = workflows.AuthCoordinator(StubAuthClient([100, 200]))
            result_pair = coord_pair.authenticate_with_xades_key_pair(
                key_pair=XadesKeyPair(
                    certificate_pem=rsa_cert.certificate_pem,
                    private_key_pem=rsa_cert.private_key_pem,
                ),
                context_identifier_type="nip",
                context_identifier_value="123",
                subject_identifier_type="certificateSubject",
                poll_interval_seconds=0,
                max_attempts=2,
            )
        self.assertEqual(result_pair.authentication_token, "auth")

        auth_error = StubAuthClient([400])
        coord_error = workflows.AuthCoordinator(auth_error)
        with self.assertRaises(RuntimeError):
            coord_error._poll_auth_status("ref", "auth", 0, 1)

        class StubAuthClientWithDetails(StubAuthClient):
            def get_auth_status(self, reference_number, authentication_token):
                return _auth_status_response(400, ["d1", "d2"])

        coord_details = workflows.AuthCoordinator(StubAuthClientWithDetails([400]))
        with self.assertRaises(RuntimeError) as exc:
            coord_details._poll_auth_status("ref", "auth", 0, 1)
        self.assertIn("Details: d1, d2", str(exc.exception))

        auth_timeout = StubAuthClient([100, 100])
        coord_timeout = workflows.AuthCoordinator(auth_timeout)
        with patch("time.sleep", return_value=None), self.assertRaises(TimeoutError):
            coord_timeout._poll_auth_status("ref", "auth", 0, 2)

    def test_auth_coordinator_ksef_token(self):
        auth = StubAuthClient([200])
        coord = workflows.AuthCoordinator(auth)
        with patch("ksef_client.services.workflows.encrypt_ksef_token", return_value="enc"):
            result = coord.authenticate_with_ksef_token(
                token="token",
                public_certificate="cert",
                public_key_id="key-id",
                context_identifier_type="nip",
                context_identifier_value="123",
                poll_interval_seconds=0,
                max_attempts=1,
            )
        self.assertEqual(result.tokens.access_token.token, "acc")
        self.assertEqual(result.access_token, "acc")
        self.assertEqual(result.refresh_token, "ref")
        self.assertIsNotNone(auth.last_ksef_token_payload)
        assert auth.last_ksef_token_payload is not None
        self.assertEqual(auth.last_ksef_token_payload.public_key_id, "key-id")

        class StubAuthClientNoneXades(StubAuthClient):
            def submit_xades_auth_request(
                self,
                signed_xml: str,
                verify_certificate_chain=None,
                enforce_xades_compliance: bool = False,
            ):
                return None

        rsa_cert = generate_rsa_cert()
        coord_none_xades = workflows.AuthCoordinator(StubAuthClientNoneXades([200]))
        with (
            patch("ksef_client.services.xades.sign_xades_enveloped", return_value="signed"),
            self.assertRaises(RuntimeError),
        ):
            coord_none_xades.authenticate_with_xades(
                context_identifier_type="nip",
                context_identifier_value="123",
                subject_identifier_type="certificateSubject",
                certificate_pem=rsa_cert.certificate_pem,
                private_key_pem=rsa_cert.private_key_pem,
                poll_interval_seconds=0,
                max_attempts=1,
            )

        class StubAuthClientNoneToken(StubAuthClient):
            def submit_ksef_token_auth(self, payload):
                return None

        coord_none_token = workflows.AuthCoordinator(StubAuthClientNoneToken([200]))
        with (
            patch("ksef_client.services.workflows.encrypt_ksef_token", return_value="enc"),
            self.assertRaises(RuntimeError),
        ):
            coord_none_token.authenticate_with_ksef_token(
                token="token",
                public_certificate="cert",
                context_identifier_type="nip",
                context_identifier_value="123",
                poll_interval_seconds=0,
                max_attempts=1,
            )

    def test_auth_coordinator_xades_schema_version_option(self):
        auth = StubAuthClient([200])
        coord = workflows.AuthCoordinator(auth)
        rsa_cert = generate_rsa_cert()

        def _sign(xml, certificate_pem, private_key_pem):
            _ = (certificate_pem, private_key_pem)
            self.assertIn("http://ksef.mf.gov.pl/auth/token/2.0", xml)
            self.assertNotIn("http://ksef.mf.gov.pl/auth/token/2.1", xml)
            return "signed"

        with patch("ksef_client.services.xades.sign_xades_enveloped", side_effect=_sign):
            coord.authenticate_with_xades(
                context_identifier_type="nip",
                context_identifier_value="123",
                subject_identifier_type="certificateSubject",
                certificate_pem=rsa_cert.certificate_pem,
                private_key_pem=rsa_cert.private_key_pem,
                auth_request_schema_version="2.0",
                poll_interval_seconds=0,
                max_attempts=1,
            )

    def test_online_session_workflow(self):
        sessions = StubSessionsClient()
        workflow = workflows.OnlineSessionWorkflow(sessions)
        rsa_cert = generate_rsa_cert()
        result = workflow.open_session(
            form_code=_form_code(),
            public_certificate=rsa_cert.certificate_pem,
            public_key_id="key-id",
            access_token="token",
            upo_v43=True,
        )
        self.assertEqual(result.session_reference_number, "ref")
        open_online_calls = [call for call in sessions.calls if call[0] == "open_online"]
        self.assertEqual(open_online_calls[0][1].encryption.public_key_id, "key-id")
        workflow.send_invoice(
            session_reference_number="ref",
            invoice_xml=b"<xml/>",
            encryption_data=result.encryption_data,
            access_token="token",
            offline_mode=True,
            hash_of_corrected_invoice="hash",
        )
        workflow.close_session("ref", "token")

    def test_online_session_requires_encryption_metadata(self):
        sessions = StubSessionsClient()
        workflow = workflows.OnlineSessionWorkflow(sessions)
        encryption = workflows.EncryptionData(key=b"k" * 32, iv=b"i" * 16, encryption_info=None)
        with (
            patch("ksef_client.services.workflows.build_encryption_data", return_value=encryption),
            self.assertRaisesRegex(ValueError, "EncryptionData.encryption_info is required"),
        ):
            workflow.open_session(
                form_code=_form_code(),
                public_certificate="cert",
                access_token="token",
            )

    def test_batch_session_workflow(self):
        sessions = StubSessionsClient()
        http = RecordingHttp()
        workflow = workflows.BatchSessionWorkflow(sessions, http)
        rsa_cert = generate_rsa_cert()
        zip_bytes = build_zip({"a.xml": b"<xml/>"})
        ref = workflow.open_upload_and_close(
            form_code=_form_code(),
            zip_bytes=zip_bytes,
            public_certificate=rsa_cert.certificate_pem,
            public_key_id="key-id",
            access_token="token",
            offline_mode=True,
            upo_v43=True,
            parallelism=1,
        )
        self.assertEqual(ref, "ref")
        open_batch_calls = [call for call in sessions.calls if call[0] == "open_batch"]
        self.assertEqual(open_batch_calls[0][1].encryption.public_key_id, "key-id")

    def test_batch_session_workflow_without_offline_mode_flag(self):
        sessions = StubSessionsClient()
        http = RecordingHttp()
        workflow = workflows.BatchSessionWorkflow(sessions, http)
        rsa_cert = generate_rsa_cert()
        zip_bytes = build_zip({"a.xml": b"<xml/>"})
        workflow.open_upload_and_close(
            form_code=_form_code(),
            zip_bytes=zip_bytes,
            public_certificate=rsa_cert.certificate_pem,
            access_token="token",
            offline_mode=None,
            upo_v43=False,
            parallelism=1,
        )
        open_batch_calls = [call for call in sessions.calls if call[0] == "open_batch"]
        assert open_batch_calls
        payload = open_batch_calls[0][1]
        self.assertNotIn("offlineMode", payload.to_dict())

    def test_batch_session_requires_encryption_metadata(self):
        sessions = StubSessionsClient()
        http = RecordingHttp()
        workflow = workflows.BatchSessionWorkflow(sessions, http)
        encryption = workflows.EncryptionData(key=b"k" * 32, iv=b"i" * 16, encryption_info=None)
        zip_bytes = build_zip({"a.xml": b"<xml/>"})
        with (
            patch("ksef_client.services.workflows.build_encryption_data", return_value=encryption),
            self.assertRaisesRegex(ValueError, "EncryptionData.encryption_info is required"),
        ):
            workflow.open_upload_and_close(
                form_code=_form_code(),
                zip_bytes=zip_bytes,
                public_certificate="cert",
                access_token="token",
            )

    def test_export_workflow(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        files = {
            "_metadata.json": json.dumps({"invoices": [{"ksefNumber": "1"}]}).encode("utf-8"),
            "inv.xml": b"<xml/>",
        }
        archive = build_zip(files)
        encrypted = encrypt_aes_cbc_pkcs7(archive, key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.ExportWorkflow(cast(InvoicesClient, DummyInvoices()), RecordingHttp())
        with patch.object(
            workflow._download_helper,
            "download_parts_with_hash",
            return_value=[(encrypted, _sha256_b64(encrypted))],
        ):
            result = workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertEqual(result.metadata_summaries[0]["ksefNumber"], "1")
        self.assertIn("inv.xml", result.invoice_xml_files)

    def test_export_workflow_empty_invoice_package_returns_empty_result(self):
        encryption = workflows.EncryptionData(
            key=generate_symmetric_key(),
            iv=generate_iv(),
            encryption_info=None,
        )

        class DummyInvoices:
            pass

        workflow = workflows.ExportWorkflow(cast(InvoicesClient, DummyInvoices()), RecordingHttp())
        with patch.object(
            workflow._download_helper,
            "download_parts_with_hash",
            side_effect=AssertionError("empty export package should not be downloaded"),
        ):
            result = workflow.download_and_process_package(_empty_invoice_package(), encryption)

        self.assertEqual(result.metadata_summaries, [])
        self.assertEqual(result.invoice_xml_files, {})

    def test_export_workflow_ignores_non_xml_non_metadata_files(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        files = {
            "_metadata.json": json.dumps({"invoices": [{"ksefNumber": "1"}]}).encode("utf-8"),
            "inv.xml": b"<xml/>",
            "notes.txt": b"ignored",
        }
        archive = build_zip(files)
        encrypted = encrypt_aes_cbc_pkcs7(archive, key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.ExportWorkflow(cast(InvoicesClient, DummyInvoices()), RecordingHttp())
        with patch.object(
            workflow._download_helper,
            "download_parts_with_hash",
            return_value=[(encrypted, _sha256_b64(encrypted))],
        ):
            result = workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertNotIn("notes.txt", result.invoice_xml_files)

    def test_export_workflow_rejects_missing_hash_by_default(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        encrypted = encrypt_aes_cbc_pkcs7(build_zip({"inv.xml": b"<xml/>"}), key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.ExportWorkflow(cast(InvoicesClient, DummyInvoices()), RecordingHttp())
        with (
            patch.object(
                workflow._download_helper,
                "download_parts_with_hash",
                return_value=[(encrypted, None)],
            ),
            self.assertRaises(ValueError) as exc,
        ):
            workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertIn("Missing export part hash", str(exc.exception))

    def test_export_workflow_allows_missing_hash_when_disabled(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        encrypted = encrypt_aes_cbc_pkcs7(build_zip({"inv.xml": b"<xml/>"}), key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.ExportWorkflow(
            cast(InvoicesClient, DummyInvoices()),
            RecordingHttp(),
            require_export_part_hash=False,
        )
        with patch.object(
            workflow._download_helper,
            "download_parts_with_hash",
            return_value=[(encrypted, None)],
        ):
            result = workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertIn("inv.xml", result.invoice_xml_files)

    def test_export_workflow_rejects_hash_mismatch(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        encrypted = encrypt_aes_cbc_pkcs7(build_zip({"inv.xml": b"<xml/>"}), key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.ExportWorkflow(cast(InvoicesClient, DummyInvoices()), RecordingHttp())
        with (
            patch.object(
                workflow._download_helper,
                "download_parts_with_hash",
                return_value=[(encrypted, "bad-hash")],
            ),
            self.assertRaises(ValueError) as exc,
        ):
            workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertIn("Export part hash mismatch", str(exc.exception))

    def test_export_workflow_reads_hash_requirement_from_client_options(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        encrypted = encrypt_aes_cbc_pkcs7(build_zip({"inv.xml": b"<xml/>"}), key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        class RecordingHttpWithOptions(RecordingHttp):
            def __init__(self) -> None:
                super().__init__()
                self._options = KsefClientOptions(
                    base_url="https://api-test.ksef.mf.gov.pl",
                    require_export_part_hash=False,
                )

        http = RecordingHttpWithOptions()
        workflow = workflows.ExportWorkflow(cast(InvoicesClient, DummyInvoices()), http)
        with patch.object(
            workflow._download_helper,
            "download_parts_with_hash",
            return_value=[(encrypted, None)],
        ):
            result = workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertIn("inv.xml", result.invoice_xml_files)


class AsyncWorkflowsTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_batch_upload_helper(self):
        http = RecordingAsyncHttp()
        helper = workflows.AsyncBatchUploadHelper(http)
        reqs = [_part_upload_request()]
        await helper.upload_parts(reqs, [b"data"])
        self.assertEqual(len(http.calls), 1)

        with self.assertRaises(ValueError):
            await helper.upload_parts(reqs, [b"a", b"b"])

    async def test_async_export_download_helper(self):
        http = RecordingAsyncHttp(content=b"part", headers={"x-ms-meta-hash": "hash"})
        helper = workflows.AsyncExportDownloadHelper(http)
        parts = [_package_part()]
        data = await helper.download_parts(parts)
        self.assertEqual(data, [b"part"])
        data_with_hash = await helper.download_parts_with_hash(parts)
        self.assertEqual(data_with_hash[0][1], "hash")

    async def test_async_auth_coordinator(self):
        auth = StubAsyncAuthClient([200])
        coord = workflows.AsyncAuthCoordinator(auth)
        with patch("ksef_client.services.workflows.encrypt_ksef_token", return_value="enc"):
            result = await coord.authenticate_with_ksef_token(
                token="token",
                public_certificate="cert",
                public_key_id="async-key-id",
                context_identifier_type="nip",
                context_identifier_value="123",
                poll_interval_seconds=0,
                max_attempts=1,
            )
        self.assertEqual(result.tokens.access_token.token, "acc")
        self.assertIsNotNone(auth.last_ksef_token_payload)
        assert auth.last_ksef_token_payload is not None
        self.assertEqual(auth.last_ksef_token_payload.public_key_id, "async-key-id")

        rsa_cert = generate_rsa_cert()
        auth_xades = StubAsyncAuthClient([200])
        coord_xades = workflows.AsyncAuthCoordinator(auth_xades)
        with patch("ksef_client.services.xades.sign_xades_enveloped", return_value="signed"):
            result_xades = await coord_xades.authenticate_with_xades(
                context_identifier_type="nip",
                context_identifier_value="123",
                subject_identifier_type="certificateSubject",
                certificate_pem=rsa_cert.certificate_pem,
                private_key_pem=rsa_cert.private_key_pem,
                poll_interval_seconds=0,
                max_attempts=1,
            )
        self.assertEqual(result_xades.authentication_token, "auth")
        self.assertFalse(auth_xades.last_enforce_xades_compliance)

        auth_xades_feature = StubAsyncAuthClient([200])
        coord_xades_feature = workflows.AsyncAuthCoordinator(auth_xades_feature)
        with patch("ksef_client.services.xades.sign_xades_enveloped", return_value="signed"):
            await coord_xades_feature.authenticate_with_xades(
                context_identifier_type="nip",
                context_identifier_value="123",
                subject_identifier_type="certificateSubject",
                certificate_pem=rsa_cert.certificate_pem,
                private_key_pem=rsa_cert.private_key_pem,
                enforce_xades_compliance=True,
                poll_interval_seconds=0,
                max_attempts=1,
            )
        self.assertTrue(auth_xades_feature.last_enforce_xades_compliance)

        with patch("ksef_client.services.xades.sign_xades_enveloped", return_value="signed"):
            coord_xades_pair = workflows.AsyncAuthCoordinator(StubAsyncAuthClient([200]))
            result_xades_pair = await coord_xades_pair.authenticate_with_xades_key_pair(
                key_pair=XadesKeyPair(
                    certificate_pem=rsa_cert.certificate_pem,
                    private_key_pem=rsa_cert.private_key_pem,
                ),
                context_identifier_type="nip",
                context_identifier_value="123",
                subject_identifier_type="certificateSubject",
                poll_interval_seconds=0,
                max_attempts=1,
            )
        self.assertEqual(result_xades_pair.authentication_token, "auth")

        auth_error = StubAsyncAuthClient([400])
        coord_error = workflows.AsyncAuthCoordinator(auth_error)
        with self.assertRaises(RuntimeError):
            await coord_error._poll_auth_status("ref", "auth", 0, 1)

        class StubAsyncAuthClientWithDetails(StubAsyncAuthClient):
            async def get_auth_status(self, reference_number, authentication_token):
                return _auth_status_response(400, ["d1", "d2"])

        coord_details = workflows.AsyncAuthCoordinator(StubAsyncAuthClientWithDetails([400]))
        with self.assertRaises(RuntimeError) as exc:
            await coord_details._poll_auth_status("ref", "auth", 0, 1)
        self.assertIn("Details: d1, d2", str(exc.exception))

        auth_timeout = StubAsyncAuthClient([100, 100])
        coord_timeout = workflows.AsyncAuthCoordinator(auth_timeout)
        with patch("asyncio.sleep", return_value=None), self.assertRaises(TimeoutError):
            await coord_timeout._poll_auth_status("ref", "auth", 0, 2)

        class StubAsyncAuthClientNoneXades(StubAsyncAuthClient):
            async def submit_xades_auth_request(
                self,
                signed_xml: str,
                verify_certificate_chain=None,
                enforce_xades_compliance: bool = False,
            ):
                return None

        coord_none_xades = workflows.AsyncAuthCoordinator(StubAsyncAuthClientNoneXades([200]))
        with (
            patch("ksef_client.services.xades.sign_xades_enveloped", return_value="signed"),
            self.assertRaises(RuntimeError),
        ):
            await coord_none_xades.authenticate_with_xades(
                context_identifier_type="nip",
                context_identifier_value="123",
                subject_identifier_type="certificateSubject",
                certificate_pem=rsa_cert.certificate_pem,
                private_key_pem=rsa_cert.private_key_pem,
                poll_interval_seconds=0,
                max_attempts=1,
            )

        class StubAsyncAuthClientNoneToken(StubAsyncAuthClient):
            async def submit_ksef_token_auth(self, payload):
                return None

        coord_none_token = workflows.AsyncAuthCoordinator(StubAsyncAuthClientNoneToken([200]))
        with (
            patch("ksef_client.services.workflows.encrypt_ksef_token", return_value="enc"),
            self.assertRaises(RuntimeError),
        ):
            await coord_none_token.authenticate_with_ksef_token(
                token="token",
                public_certificate="cert",
                context_identifier_type="nip",
                context_identifier_value="123",
                poll_interval_seconds=0,
                max_attempts=1,
            )

    async def test_async_online_and_batch(self):
        sessions = StubAsyncSessionsClient()
        workflow = workflows.AsyncOnlineSessionWorkflow(sessions)
        rsa_cert = generate_rsa_cert()
        result = await workflow.open_session(
            form_code=_form_code(),
            public_certificate=rsa_cert.certificate_pem,
            public_key_id="online-key-id",
            access_token="token",
            upo_v43=True,
        )
        open_online_calls = [call for call in sessions.calls if call[0] == "open_online"]
        self.assertEqual(open_online_calls[0][1].encryption.public_key_id, "online-key-id")
        await workflow.send_invoice(
            session_reference_number="ref",
            invoice_xml=b"<xml/>",
            encryption_data=result.encryption_data,
            access_token="token",
        )
        await workflow.close_session("ref", "token")

        batch = workflows.AsyncBatchSessionWorkflow(sessions, RecordingAsyncHttp())
        zip_bytes = build_zip({"a.xml": b"<xml/>"})
        ref = await batch.open_upload_and_close(
            form_code=_form_code(),
            zip_bytes=zip_bytes,
            public_certificate=rsa_cert.certificate_pem,
            public_key_id="batch-key-id",
            access_token="token",
            offline_mode=True,
            upo_v43=True,
        )
        self.assertEqual(ref, "ref")
        open_batch_calls = [call for call in sessions.calls if call[0] == "open_batch"]
        self.assertEqual(open_batch_calls[0][1].encryption.public_key_id, "batch-key-id")

    async def test_async_batch_session_workflow_without_offline_mode_flag(self):
        sessions = StubAsyncSessionsClient()
        batch = workflows.AsyncBatchSessionWorkflow(sessions, RecordingAsyncHttp())
        rsa_cert = generate_rsa_cert()
        zip_bytes = build_zip({"a.xml": b"<xml/>"})
        await batch.open_upload_and_close(
            form_code=_form_code(),
            zip_bytes=zip_bytes,
            public_certificate=rsa_cert.certificate_pem,
            access_token="token",
            offline_mode=None,
            upo_v43=False,
        )
        open_batch_calls = [call for call in sessions.calls if call[0] == "open_batch"]
        assert open_batch_calls
        payload = open_batch_calls[0][1]
        self.assertNotIn("offlineMode", payload.to_dict())

    async def test_async_export_workflow(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        files = {
            "_metadata.json": json.dumps({"invoiceList": [{"ksefNumber": "1"}]}).encode("utf-8"),
            "inv.xml": b"<xml/>",
        }
        archive = build_zip(files)
        encrypted = encrypt_aes_cbc_pkcs7(archive, key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.AsyncExportWorkflow(
            cast(AsyncInvoicesClient, DummyInvoices()),
            RecordingAsyncHttp(),
        )
        with patch.object(
            workflow._download_helper,
            "download_parts_with_hash",
            AsyncMock(return_value=[(encrypted, _sha256_b64(encrypted))]),
        ):
            result = await workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertEqual(result.metadata_summaries[0]["ksefNumber"], "1")

    async def test_async_export_workflow_empty_invoice_package_returns_empty_result(self):
        encryption = workflows.EncryptionData(
            key=generate_symmetric_key(),
            iv=generate_iv(),
            encryption_info=None,
        )

        class DummyInvoices:
            pass

        workflow = workflows.AsyncExportWorkflow(
            cast(AsyncInvoicesClient, DummyInvoices()),
            RecordingAsyncHttp(),
        )
        with patch.object(
            workflow._download_helper,
            "download_parts_with_hash",
            AsyncMock(side_effect=AssertionError("empty export package should not be downloaded")),
        ):
            result = await workflow.download_and_process_package(
                _empty_invoice_package(),
                encryption,
            )

        self.assertEqual(result.metadata_summaries, [])
        self.assertEqual(result.invoice_xml_files, {})

    async def test_async_export_workflow_ignores_non_xml_non_metadata_files(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        files = {
            "_metadata.json": json.dumps({"invoiceList": [{"ksefNumber": "1"}]}).encode("utf-8"),
            "inv.xml": b"<xml/>",
            "notes.txt": b"ignored",
        }
        archive = build_zip(files)
        encrypted = encrypt_aes_cbc_pkcs7(archive, key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.AsyncExportWorkflow(
            cast(AsyncInvoicesClient, DummyInvoices()),
            RecordingAsyncHttp(),
        )
        with patch.object(
            workflow._download_helper,
            "download_parts_with_hash",
            AsyncMock(return_value=[(encrypted, _sha256_b64(encrypted))]),
        ):
            result = await workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertNotIn("notes.txt", result.invoice_xml_files)

    async def test_async_export_workflow_rejects_missing_hash_by_default(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        encrypted = encrypt_aes_cbc_pkcs7(build_zip({"inv.xml": b"<xml/>"}), key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.AsyncExportWorkflow(
            cast(AsyncInvoicesClient, DummyInvoices()),
            RecordingAsyncHttp(),
        )
        with (
            patch.object(
                workflow._download_helper,
                "download_parts_with_hash",
                AsyncMock(return_value=[(encrypted, None)]),
            ),
            self.assertRaises(ValueError) as exc,
        ):
            await workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertIn("Missing export part hash", str(exc.exception))

    async def test_async_export_workflow_allows_missing_hash_when_disabled(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        encrypted = encrypt_aes_cbc_pkcs7(build_zip({"inv.xml": b"<xml/>"}), key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.AsyncExportWorkflow(
            cast(AsyncInvoicesClient, DummyInvoices()),
            RecordingAsyncHttp(),
            require_export_part_hash=False,
        )
        with patch.object(
            workflow._download_helper,
            "download_parts_with_hash",
            AsyncMock(return_value=[(encrypted, None)]),
        ):
            result = await workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertIn("inv.xml", result.invoice_xml_files)

    async def test_async_export_workflow_rejects_hash_mismatch(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        encrypted = encrypt_aes_cbc_pkcs7(build_zip({"inv.xml": b"<xml/>"}), key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)

        class DummyInvoices:
            pass

        workflow = workflows.AsyncExportWorkflow(
            cast(AsyncInvoicesClient, DummyInvoices()),
            RecordingAsyncHttp(),
        )
        with (
            patch.object(
                workflow._download_helper,
                "download_parts_with_hash",
                AsyncMock(return_value=[(encrypted, "bad-hash")]),
            ),
            self.assertRaises(ValueError) as exc,
        ):
            await workflow.download_and_process_package(_invoice_package("u"), encryption)
        self.assertIn("Export part hash mismatch", str(exc.exception))


if __name__ == "__main__":
    unittest.main()
