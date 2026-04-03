import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

from ksef_client import models


class ModelsTests(unittest.TestCase):
    def test_models_public_exports_are_curated(self):
        self.assertIn("FormCode", models.__all__)
        self.assertIn("StatusInfo", models.__all__)
        self.assertIn("QueryInvoicesMetadataResponse", models.__all__)

        unexpected = {
            "Any",
            "Enum",
            "JsonValue",
            "OpenApiEnum",
            "OpenApiModel",
            "Optional",
            "TypeAlias",
            "TypeVar",
            "annotations",
            "cast",
            "dataclass",
            "field",
            "fields",
            "sys",
        }
        for name in unexpected:
            self.assertFalse(hasattr(models, name), msg=f"{name} leaked from ksef_client.models")

    def test_serialize_model_value_returns_plain_values_unchanged(self):
        serialize_model_value = getattr(models, "_serialize_model_value")
        self.assertEqual(serialize_model_value("plain", omit_none=True), "plain")

    def test_models_stub_matches_runtime_wrappers(self):
        repo_root = Path(__file__).resolve().parents[1]
        mypy_program = textwrap.dedent(
            """
            from ksef_client import models as m

            status = m.StatusInfo(code=200, description="ok")
            status.extensions

            challenge = m.AuthenticationChallengeResponse(
                challenge="c",
                timestamp="t",
                timestamp_ms=1,
            )
            challenge.client_ip

            cert = m.PublicKeyCertificate(certificate="pem")
            cert.valid_from

            invoice = m.InvoiceMetadata(currency="PLN")
            invoice.currency

            response = m.QueryInvoicesMetadataResponse()
            response.continuation_token
            response.last_permanent_storage_date

            session = m.SessionInvoicesResponse(invoices=[])
            session.continuation_token

            problem = m.UnknownApiProblem(status=500, title="boom")
            problem.raw
            """
        ).strip()
        result = subprocess.run(
            [sys.executable, "-m", "mypy", "-c", mypy_program],
            capture_output=True,
            text=True,
            cwd=repo_root,
            env={
                **os.environ,
                "MYPYPATH": str(repo_root / "src"),
            },
            check=False,
        )
        self.assertEqual(result.returncode, 0, msg=result.stdout + result.stderr)

    def test_token_info_from_dict(self):
        data = {"token": "abc", "validUntil": "2024-01-01"}
        token = models.TokenInfo.from_dict(data)
        self.assertEqual(token.token, "abc")
        self.assertEqual(token.valid_until, "2024-01-01")

    def test_auth_challenge_from_dict(self):
        data = {
            "challenge": "c",
            "timestamp": "t",
            "timestampMs": 123,
            "clientIp": "203.0.113.10",
        }
        parsed = models.AuthenticationChallengeResponse.from_dict(data)
        self.assertEqual(parsed.challenge, "c")
        self.assertEqual(parsed.timestamp_ms, 123)
        self.assertEqual(parsed.client_ip, "203.0.113.10")

    def test_auth_init_from_dict(self):
        data = {
            "referenceNumber": "ref",
            "authenticationToken": {"token": "tok", "validUntil": "2024-01-01"},
        }
        parsed = models.AuthenticationInitResponse.from_dict(data)
        self.assertEqual(parsed.reference_number, "ref")
        self.assertEqual(parsed.authentication_token.token, "tok")

    def test_auth_tokens_from_dict(self):
        data = {
            "accessToken": {"token": "acc", "validUntil": "2024-01-01"},
            "refreshToken": {"token": "ref", "validUntil": "2024-02-01"},
        }
        parsed = models.AuthenticationTokensResponse.from_dict(data)
        self.assertEqual(parsed.access_token.token, "acc")
        self.assertEqual(parsed.refresh_token.token, "ref")

    def test_auth_token_refresh(self):
        data = {"accessToken": {"token": "acc", "validUntil": "2024-01-01"}}
        parsed = models.AuthenticationTokenRefreshResponse.from_dict(data)
        self.assertEqual(parsed.access_token.token, "acc")

    def test_auth_status_from_minimal_payload(self):
        parsed = models.AuthenticationOperationStatusResponse.from_dict(
            {"status": {"code": 100, "description": "pending"}}
        )
        self.assertEqual(parsed.status.code, 100)
        self.assertIsNone(parsed.authentication_method)
        self.assertIsNone(parsed.start_date)

    def test_wrapper_models_to_dict_include_optional_fields_when_requested(self):
        status = models.StatusInfo.from_dict({"code": 200, "description": "ok"})
        self.assertEqual(
            status.to_dict(omit_none=False),
            {"code": 200, "description": "ok", "details": None, "extensions": None},
        )

        token = models.TokenInfo.from_dict({"token": "abc"})
        self.assertEqual(token.to_dict(omit_none=False), {"token": "abc", "validUntil": None})

        challenge = models.AuthenticationChallengeResponse.from_dict(
            {"challenge": "c", "timestamp": "t", "timestampMs": 1}
        )
        self.assertEqual(
            challenge.to_dict(omit_none=False),
            {"challenge": "c", "timestamp": "t", "timestampMs": 1, "clientIp": None},
        )

        init_response = models.AuthenticationInitResponse.from_dict(
            {"referenceNumber": "ref", "authenticationToken": {"token": "abc"}}
        )
        self.assertEqual(
            init_response.to_dict(omit_none=False),
            {
                "referenceNumber": "ref",
                "authenticationToken": {"token": "abc", "validUntil": None},
            },
        )

        auth_status = models.AuthenticationOperationStatusResponse.from_dict(
            {"status": {"code": 200, "description": "ok"}}
        )
        self.assertEqual(
            auth_status.to_dict(omit_none=False),
            {
                "status": {"code": 200, "description": "ok", "details": None, "extensions": None},
                "authenticationMethod": None,
                "authenticationMethodInfo": None,
                "startDate": None,
                "isTokenRedeemed": None,
                "lastTokenRefreshDate": None,
                "refreshTokenValidUntil": None,
            },
        )

        tokens_response = models.AuthenticationTokensResponse.from_dict(
            {
                "accessToken": {"token": "abc"},
                "refreshToken": {"token": "ref"},
            }
        )
        self.assertEqual(
            tokens_response.to_dict(omit_none=False),
            {
                "accessToken": {"token": "abc", "validUntil": None},
                "refreshToken": {"token": "ref", "validUntil": None},
            },
        )

        token_refresh = models.AuthenticationTokenRefreshResponse.from_dict(
            {"accessToken": {"token": "abc"}}
        )
        self.assertEqual(
            token_refresh.to_dict(omit_none=False),
            {"accessToken": {"token": "abc", "validUntil": None}},
        )

        session = models.OpenOnlineSessionResponse.from_dict({"referenceNumber": "ref"})
        self.assertEqual(
            session.to_dict(omit_none=False),
            {"referenceNumber": "ref", "validUntil": None},
        )

    def test_invoice_export_status(self):
        data = {
            "status": {"code": 200, "description": "ok"},
            "completedDate": "2024-01-02",
            "packageExpirationDate": "2024-02-02",
            "package": {
                "invoiceCount": 1,
                "size": 10,
                "parts": [
                    {
                        "ordinalNumber": 1,
                        "partName": "p1",
                        "method": "GET",
                        "url": "https://example.com",
                        "partSize": 1,
                        "partHash": "h",
                        "encryptedPartSize": 2,
                        "encryptedPartHash": "eh",
                        "expirationDate": "2025-01-01",
                    }
                ],
                "isTruncated": False,
            },
        }
        parsed = models.InvoiceExportStatusResponse.from_dict(data)
        self.assertEqual(parsed.status.code, 200)
        self.assertIsNotNone(parsed.package)
        assert parsed.package is not None
        self.assertEqual(parsed.package.parts[0].part_name, "p1")

    def test_part_upload_request(self):
        data = {
            "ordinalNumber": 1,
            "method": "PUT",
            "url": "https://upload",
            "headers": {"x": "y"},
        }
        parsed = models.PartUploadRequest.from_dict(data)
        self.assertEqual(parsed.headers["x"], "y")

    def test_public_key_certificate_and_session_models_allow_sparse_payloads(self):
        cert = models.PublicKeyCertificate.from_dict(
            {"certificate": "pem", "usage": ["KsefTokenEncryption"]}
        )
        self.assertEqual(cert.usage[0].value, "KsefTokenEncryption")

        session = models.OpenOnlineSessionResponse.from_dict({"referenceNumber": "ref"})
        self.assertEqual(session.reference_number, "ref")
        self.assertIsNone(session.valid_until)

        invoice_status = models.SessionInvoiceStatusResponse.from_dict(
            {"status": {"code": 200, "description": "ok"}, "ksefNumber": "KSEF-1"}
        )
        self.assertEqual(invoice_status.status.code, 200)
        self.assertEqual(invoice_status.ksef_number, "KSEF-1")

        invoices = models.SessionInvoicesResponse.from_dict(
            {
                "invoices": [
                    {"status": {"code": 100, "description": "pending"}},
                    {"status": {"code": 200, "description": "ok"}, "ksefNumber": "KSEF-2"},
                ]
            }
        )
        self.assertEqual(len(invoices.invoices), 2)
        self.assertEqual(invoices.invoices[1].ksef_number, "KSEF-2")

    def test_public_key_certificate_preserves_validity_window(self):
        cert = models.PublicKeyCertificate.from_dict(
            {
                "certificate": "pem",
                "usage": ["KsefTokenEncryption"],
                "validFrom": "2026-01-01T00:00:00Z",
                "validTo": "2026-12-31T23:59:59Z",
            }
        )
        self.assertEqual(cert.valid_from, "2026-01-01T00:00:00Z")
        self.assertEqual(cert.valid_to, "2026-12-31T23:59:59Z")
        self.assertEqual(cert.to_dict()["validFrom"], "2026-01-01T00:00:00Z")
        self.assertEqual(cert.to_dict()["validTo"], "2026-12-31T23:59:59Z")

    def test_session_invoice_status_preserves_status_extensions(self):
        invoice_status = models.SessionInvoiceStatusResponse.from_dict(
            {
                "status": {
                    "code": 200,
                    "description": "ok",
                    "extensions": {"source": "ksef", "attempt": "2"},
                },
                "invoiceHash": "hash",
                "invoicingDate": "2026-01-01T00:00:00Z",
                "ordinalNumber": 1,
                "referenceNumber": "ref",
            }
        )
        self.assertEqual(invoice_status.status.extensions, {"source": "ksef", "attempt": "2"})
        self.assertEqual(
            invoice_status.to_dict()["status"]["extensions"],
            {"source": "ksef", "attempt": "2"},
        )

    def test_query_invoices_metadata_response_accepts_sparse_invoice_list_shape(self):
        parsed = models.QueryInvoicesMetadataResponse.from_dict(
            {
                "invoiceList": [
                    {"ksefNumber": "KSEF-1"},
                    {"invoiceNumber": "FV/1"},
                ]
            }
        )
        self.assertEqual(parsed.invoices[0].ksef_number, "KSEF-1")
        self.assertEqual(parsed.invoices[1].invoice_number, "FV/1")
        self.assertFalse(parsed.has_more)

    def test_query_invoices_metadata_response_preserves_full_invoice_metadata_fields(self):
        parsed = models.QueryInvoicesMetadataResponse.from_dict(
            {
                "invoices": [
                    {
                        "acquisitionDate": "2026-01-01T09:00:00Z",
                        "buyer": {
                            "identifier": {"type": "Nip", "value": "1234567890"},
                            "name": "Buyer sp. z o.o.",
                        },
                        "currency": "PLN",
                        "formCode": {
                            "systemCode": "FA (3)",
                            "schemaVersion": "1-0E",
                            "value": "FA",
                        },
                        "grossAmount": 123.45,
                        "hasAttachment": True,
                        "invoiceHash": "hash",
                        "invoiceNumber": "FV/1",
                        "invoiceType": "VAT",
                        "invoicingDate": "2026-01-01",
                        "invoicingMode": "Online",
                        "isSelfInvoicing": False,
                        "issueDate": "2026-01-01",
                        "ksefNumber": "KSEF-1",
                        "netAmount": 100.0,
                        "permanentStorageDate": "2026-01-02T00:00:00Z",
                        "seller": {"nip": "9876543210", "name": "Seller SA"},
                        "vatAmount": 23.45,
                        "authorizedSubject": {"nip": "1111111111", "role": 7, "name": "Proxy"},
                        "hashOfCorrectedInvoice": "corr-hash",
                        "thirdSubjects": [
                            {
                                "identifier": {"type": "Nip", "value": "2222222222"},
                                "role": 3,
                                "name": "Third subject",
                            }
                        ],
                    }
                ],
                "hasMore": True,
                "continuationToken": "ct-1",
            }
        )
        invoice = parsed.invoices[0]
        self.assertEqual(invoice.currency, "PLN")
        self.assertIsNotNone(invoice.buyer)
        assert invoice.buyer is not None
        self.assertEqual(invoice.buyer.name, "Buyer sp. z o.o.")
        self.assertIsNotNone(invoice.form_code)
        assert invoice.form_code is not None
        self.assertEqual(invoice.form_code.system_code, "FA (3)")
        self.assertEqual(invoice.gross_amount, 123.45)
        self.assertIsNotNone(invoice.invoice_type)
        assert invoice.invoice_type is not None
        self.assertEqual(invoice.invoice_type.value, "VAT")
        self.assertIsNotNone(invoice.invoicing_mode)
        assert invoice.invoicing_mode is not None
        self.assertEqual(invoice.invoicing_mode.value, "Online")
        self.assertIsNotNone(invoice.seller)
        assert invoice.seller is not None
        self.assertEqual(invoice.seller.nip, "9876543210")
        self.assertIsNotNone(invoice.authorized_subject)
        assert invoice.authorized_subject is not None
        self.assertEqual(invoice.authorized_subject.nip, "1111111111")
        self.assertIsNotNone(invoice.third_subjects)
        assert invoice.third_subjects is not None
        self.assertEqual(invoice.third_subjects[0].name, "Third subject")
        self.assertEqual(parsed.continuation_token, "ct-1")
        payload = invoice.to_dict()
        self.assertEqual(payload["buyer"]["name"], "Buyer sp. z o.o.")
        self.assertEqual(payload["currency"], "PLN")
        self.assertEqual(payload["formCode"]["systemCode"], "FA (3)")
        self.assertEqual(payload["grossAmount"], 123.45)
        self.assertEqual(payload["invoiceType"], "VAT")
        self.assertEqual(payload["invoicingMode"], "Online")
        self.assertEqual(payload["seller"]["nip"], "9876543210")
        self.assertEqual(payload["vatAmount"], 23.45)
        self.assertEqual(payload["authorizedSubject"]["nip"], "1111111111")
        self.assertEqual(payload["hashOfCorrectedInvoice"], "corr-hash")
        self.assertEqual(payload["thirdSubjects"][0]["name"], "Third subject")

    def test_query_invoices_metadata_response_to_dict_serializes_items(self):
        parsed = models.QueryInvoicesMetadataResponse(
            invoices=[
                models.InvoiceMetadata.from_dict(
                    {
                        "ksefNumber": "KSEF-1",
                        "invoiceNumber": "FV/1",
                        "invoiceHash": "hash",
                        "issueDate": "2026-01-01",
                        "invoicingDate": "2026-01-01",
                        "permanentStorageDate": "2026-01-02T00:00:00Z",
                    }
                )
            ],
            has_more=True,
            is_truncated=True,
            continuation_token="ct-1",
            last_permanent_storage_date="2026-01-02T00:00:00Z",
            permanent_storage_hwm_date="2026-01-03T00:00:00Z",
        )
        payload = parsed.to_dict()
        self.assertEqual(payload["invoices"][0]["ksefNumber"], "KSEF-1")
        self.assertEqual(payload["invoices"][0]["invoiceNumber"], "FV/1")
        self.assertEqual(payload["invoices"][0]["invoiceHash"], "hash")
        self.assertEqual(payload["invoices"][0]["issueDate"], "2026-01-01")
        self.assertEqual(payload["invoices"][0]["invoicingDate"], "2026-01-01")
        self.assertEqual(payload["hasMore"], True)
        self.assertEqual(payload["isTruncated"], True)
        self.assertEqual(payload["continuationToken"], "ct-1")
        self.assertEqual(payload["lastPermanentStorageDate"], "2026-01-02T00:00:00Z")
        self.assertEqual(payload["permanentStorageHwmDate"], "2026-01-03T00:00:00Z")

    def test_session_invoice_and_collection_to_dict_include_optional_fields_when_requested(self):
        invoice = models.SessionInvoiceStatusResponse.from_dict(
            {"status": {"code": 200, "description": "ok"}}
        )
        self.assertEqual(
            invoice.to_dict(omit_none=False),
            {
                "status": {"code": 200, "description": "ok", "details": None, "extensions": None},
                "invoiceHash": None,
                "invoicingDate": None,
                "ordinalNumber": None,
                "referenceNumber": None,
                "acquisitionDate": None,
                "invoiceFileName": None,
                "invoiceNumber": None,
                "invoicingMode": None,
                "ksefNumber": None,
                "permanentStorageDate": None,
                "upoDownloadUrl": None,
                "upoDownloadUrlExpirationDate": None,
            },
        )

        invoices = models.SessionInvoicesResponse(invoices=[invoice])
        self.assertEqual(
            invoices.to_dict(omit_none=False),
            {
                "invoices": [invoice.to_dict(omit_none=False)],
                "continuationToken": None,
            },
        )

    def test_lighthouse_message_and_status(self):
        message_data = {
            "id": "m-1",
            "eventId": 10,
            "category": "MAINTENANCE",
            "type": "MAINTENANCE_ANNOUNCEMENT",
            "title": "T",
            "text": "X",
            "start": "2026-03-15T01:00:00Z",
            "end": "2026-03-15T06:00:00Z",
            "version": 1,
            "published": "2026-03-10T10:00:00Z",
        }
        message = models.LighthouseMessage.from_dict(message_data)
        self.assertEqual(message.category, models.LighthouseMessageCategory.MAINTENANCE)
        self.assertEqual(message.type, models.LighthouseMessageType.MAINTENANCE_ANNOUNCEMENT)
        self.assertEqual(message.to_dict()["eventId"], 10)

        status = models.LighthouseStatusResponse.from_dict(
            {
                "status": "MAINTENANCE",
                "messages": [message_data],
            }
        )
        self.assertEqual(status.status, models.LighthouseKsefStatus.MAINTENANCE)
        self.assertIsNotNone(status.messages)
        assert status.messages is not None
        self.assertEqual(status.messages[0].id, "m-1")
        self.assertEqual(status.to_dict()["status"], "MAINTENANCE")

    def test_lighthouse_enum_fallbacks(self):
        message = models.LighthouseMessage.from_dict(
            {
                "id": "m-2",
                "eventId": 11,
                "category": "UNKNOWN",
                "type": "UNKNOWN",
                "title": "",
                "text": "",
                "start": "",
                "end": None,
                "version": 0,
                "published": "",
            }
        )
        self.assertEqual(message.category, models.LighthouseMessageCategory.FAILURE)
        self.assertEqual(message.type, models.LighthouseMessageType.FAILURE_START)

        status = models.LighthouseStatusResponse.from_dict({"status": "UNKNOWN"})
        self.assertEqual(status.status, models.LighthouseKsefStatus.AVAILABLE)
        self.assertIsNone(status.messages)
        self.assertNotIn("messages", status.to_dict())


if __name__ == "__main__":
    unittest.main()
