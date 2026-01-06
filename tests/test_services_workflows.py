import json
import unittest
from dataclasses import dataclass
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import httpx

from ksef_client.clients.invoices import AsyncInvoicesClient, InvoicesClient
from ksef_client.http import HttpResponse
from ksef_client.services import workflows
from ksef_client.services.crypto import encrypt_aes_cbc_pkcs7, generate_iv, generate_symmetric_key
from ksef_client.services.xades import XadesKeyPair
from ksef_client.utils.zip_utils import build_zip
from tests.helpers import generate_rsa_cert


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

    def get_challenge(self):
        return {"challenge": "c", "timestampMs": 123}

    def submit_xades_auth_request(self, signed_xml: str, verify_certificate_chain=None):
        return {"referenceNumber": "ref", "authenticationToken": {"token": "auth"}}

    def submit_ksef_token_auth(self, payload):
        return {"referenceNumber": "ref", "authenticationToken": {"token": "auth"}}

    def get_auth_status(self, reference_number, authentication_token):
        code = self.codes.pop(0)
        return {"status": {"code": code, "description": "desc"}}

    def redeem_token(self, authentication_token):
        return {"accessToken": {"token": "acc"}, "refreshToken": {"token": "ref"}}


@dataclass
class StubAsyncAuthClient:
    codes: list[int]

    async def get_challenge(self):
        return {"challenge": "c", "timestampMs": 123}

    async def submit_xades_auth_request(self, signed_xml: str, verify_certificate_chain=None):
        return {"referenceNumber": "ref", "authenticationToken": {"token": "auth"}}

    async def submit_ksef_token_auth(self, payload):
        return {"referenceNumber": "ref", "authenticationToken": {"token": "auth"}}

    async def get_auth_status(self, reference_number, authentication_token):
        code = self.codes.pop(0)
        return {"status": {"code": code, "description": "desc"}}

    async def redeem_token(self, authentication_token):
        return {"accessToken": {"token": "acc"}, "refreshToken": {"token": "ref"}}


class StubSessionsClient:
    def __init__(self):
        self.calls = []

    def open_online_session(self, payload, access_token, upo_v43=False):
        self.calls.append(("open_online", payload, access_token, upo_v43))
        return {"referenceNumber": "ref"}

    def send_online_invoice(self, ref, payload, access_token):
        self.calls.append(("send", ref, payload))
        return {"status": "ok"}

    def close_online_session(self, ref, access_token):
        self.calls.append(("close", ref))

    def open_batch_session(self, payload, access_token, upo_v43=False):
        self.calls.append(("open_batch", payload, access_token, upo_v43))
        return {
            "referenceNumber": "ref",
            "partUploadRequests": [
                {
                    "ordinalNumber": 1,
                    "url": "https://upload",
                    "method": "PUT",
                    "headers": {"x": "y"},
                },
            ],
        }

    def close_batch_session(self, ref, access_token):
        self.calls.append(("close_batch", ref))


class StubAsyncSessionsClient:
    def __init__(self):
        self.calls = []

    async def open_online_session(self, payload, access_token, upo_v43=False):
        self.calls.append(("open_online", payload, access_token, upo_v43))
        return {"referenceNumber": "ref"}

    async def send_online_invoice(self, ref, payload, access_token):
        self.calls.append(("send", ref, payload))
        return {"status": "ok"}

    async def close_online_session(self, ref, access_token):
        self.calls.append(("close", ref))

    async def open_batch_session(self, payload, access_token, upo_v43=False):
        self.calls.append(("open_batch", payload, access_token, upo_v43))
        return {
            "referenceNumber": "ref",
            "partUploadRequests": [
                {
                    "ordinalNumber": 1,
                    "url": "https://upload",
                    "method": "PUT",
                    "headers": {"x": "y"},
                },
            ],
        }

    async def close_batch_session(self, ref, access_token):
        self.calls.append(("close_batch", ref))


class WorkflowsTests(unittest.TestCase):
    def test_pair_requests_with_parts(self):
        reqs = [
            {"ordinalNumber": 2, "url": "u2"},
            {"ordinalNumber": 1, "url": "u1"},
        ]
        parts = [(1, b"a"), (2, b"b")]
        paired = workflows._pair_requests_with_parts(reqs, parts)
        self.assertEqual(paired[0][1], b"a")

        paired_direct = workflows._pair_requests_with_parts(reqs, [b"a", b"b"])
        self.assertEqual(len(paired_direct), 2)

    def test_batch_upload_helper(self):
        http = RecordingHttp()
        helper = workflows.BatchUploadHelper(http)
        reqs = [{"ordinalNumber": 1, "url": "https://upload", "method": "PUT"}]
        helper.upload_parts(reqs, [b"data"], parallelism=1)
        self.assertEqual(len(http.calls), 1)

        with self.assertRaises(ValueError):
            helper.upload_parts(reqs, [b"a", b"b"], parallelism=1)

        helper.upload_parts(reqs, [b"data"], parallelism=2)
        self.assertEqual(len(http.calls), 2)

    def test_export_download_helper(self):
        http = RecordingHttp(content=b"part", headers={"x-ms-meta-hash": "hash"})
        helper = workflows.ExportDownloadHelper(http)
        parts = [{"url": "https://download"}]
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
                return {"status": {"code": 400, "description": "desc", "details": ["d1", "d2"]}}

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
                context_identifier_type="nip",
                context_identifier_value="123",
                poll_interval_seconds=0,
                max_attempts=1,
            )
        self.assertEqual(result.tokens.access_token.token, "acc")

        class StubAuthClientNoneXades(StubAuthClient):
            def submit_xades_auth_request(self, signed_xml: str, verify_certificate_chain=None):
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

    def test_online_session_workflow(self):
        sessions = StubSessionsClient()
        workflow = workflows.OnlineSessionWorkflow(sessions)
        rsa_cert = generate_rsa_cert()
        result = workflow.open_session(
            form_code={"systemCode": "FA"},
            public_certificate=rsa_cert.certificate_pem,
            access_token="token",
            upo_v43=True,
        )
        self.assertEqual(result.session_reference_number, "ref")
        workflow.send_invoice(
            session_reference_number="ref",
            invoice_xml=b"<xml/>",
            encryption_data=result.encryption_data,
            access_token="token",
            offline_mode=True,
            hash_of_corrected_invoice="hash",
        )
        workflow.close_session("ref", "token")

    def test_batch_session_workflow(self):
        sessions = StubSessionsClient()
        http = RecordingHttp()
        workflow = workflows.BatchSessionWorkflow(sessions, http)
        rsa_cert = generate_rsa_cert()
        zip_bytes = build_zip({"a.xml": b"<xml/>"})
        ref = workflow.open_upload_and_close(
            form_code={"systemCode": "FA"},
            zip_bytes=zip_bytes,
            public_certificate=rsa_cert.certificate_pem,
            access_token="token",
            offline_mode=True,
            upo_v43=True,
            parallelism=1,
        )
        self.assertEqual(ref, "ref")

    def test_export_workflow(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        files = {
            "_metadata.json": json.dumps({"invoices": [{"ksefNumber": "1"}]}).encode("utf-8"),
            "inv.xml": b"<xml/>",
        }
        archive = build_zip(files)
        encrypted = encrypt_aes_cbc_pkcs7(archive, key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)  # type: ignore[arg-type]

        class DummyInvoices:
            pass

        workflow = workflows.ExportWorkflow(cast(InvoicesClient, DummyInvoices()), RecordingHttp())
        with patch.object(workflow._download_helper, "download_parts", return_value=[encrypted]):
            result = workflow.download_and_process_package({"parts": [{"url": "u"}]}, encryption)
        self.assertEqual(result.metadata_summaries[0]["ksefNumber"], "1")
        self.assertIn("inv.xml", result.invoice_xml_files)


class AsyncWorkflowsTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_batch_upload_helper(self):
        http = RecordingAsyncHttp()
        helper = workflows.AsyncBatchUploadHelper(http)
        reqs = [{"ordinalNumber": 1, "url": "https://upload", "method": "PUT"}]
        await helper.upload_parts(reqs, [b"data"])
        self.assertEqual(len(http.calls), 1)

        with self.assertRaises(ValueError):
            await helper.upload_parts(reqs, [b"a", b"b"])

    async def test_async_export_download_helper(self):
        http = RecordingAsyncHttp(content=b"part", headers={"x-ms-meta-hash": "hash"})
        helper = workflows.AsyncExportDownloadHelper(http)
        parts = [{"url": "https://download"}]
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
                context_identifier_type="nip",
                context_identifier_value="123",
                poll_interval_seconds=0,
                max_attempts=1,
            )
        self.assertEqual(result.tokens.access_token.token, "acc")

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
                return {"status": {"code": 400, "description": "desc", "details": ["d1", "d2"]}}

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
                self, signed_xml: str, verify_certificate_chain=None
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
            form_code={"systemCode": "FA"},
            public_certificate=rsa_cert.certificate_pem,
            access_token="token",
            upo_v43=True,
        )
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
            form_code={"systemCode": "FA"},
            zip_bytes=zip_bytes,
            public_certificate=rsa_cert.certificate_pem,
            access_token="token",
            offline_mode=True,
            upo_v43=True,
        )
        self.assertEqual(ref, "ref")

    async def test_async_export_workflow(self):
        key = generate_symmetric_key()
        iv = generate_iv()
        files = {
            "_metadata.json": json.dumps({"invoiceList": [{"ksefNumber": "1"}]}).encode("utf-8"),
            "inv.xml": b"<xml/>",
        }
        archive = build_zip(files)
        encrypted = encrypt_aes_cbc_pkcs7(archive, key, iv)
        encryption = workflows.EncryptionData(key=key, iv=iv, encryption_info=None)  # type: ignore[arg-type]

        class DummyInvoices:
            pass

        workflow = workflows.AsyncExportWorkflow(
            cast(AsyncInvoicesClient, DummyInvoices()),
            RecordingAsyncHttp(),
        )
        with patch.object(
            workflow._download_helper,
            "download_parts",
            AsyncMock(return_value=[encrypted]),
        ):
            result = await workflow.download_and_process_package(
                {"parts": [{"url": "u"}]}, encryption
            )
        self.assertEqual(result.metadata_summaries[0]["ksefNumber"], "1")


if __name__ == "__main__":
    unittest.main()
