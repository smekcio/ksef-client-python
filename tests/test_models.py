import unittest

from ksef_client import models


class ModelsTests(unittest.TestCase):
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
