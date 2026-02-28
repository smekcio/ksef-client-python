import unittest

from ksef_client import models


class ModelsTests(unittest.TestCase):
    def test_token_info_from_dict(self):
        data = {"token": "abc", "validUntil": "2024-01-01"}
        token = models.TokenInfo.from_dict(data)
        self.assertEqual(token.token, "abc")
        self.assertEqual(token.valid_until, "2024-01-01")

    def test_auth_challenge_from_dict(self):
        data = {"challenge": "c", "timestamp": "t", "timestampMs": 123}
        parsed = models.AuthenticationChallengeResponse.from_dict(data)
        self.assertEqual(parsed.challenge, "c")
        self.assertEqual(parsed.timestamp_ms, 123)

    def test_auth_init_from_dict(self):
        data = {"referenceNumber": "ref", "authenticationToken": {"token": "tok"}}
        parsed = models.AuthenticationInitResponse.from_dict(data)
        self.assertEqual(parsed.reference_number, "ref")
        self.assertEqual(parsed.authentication_token.token, "tok")

    def test_auth_tokens_from_dict(self):
        data = {
            "accessToken": {"token": "acc"},
            "refreshToken": {"token": "ref"},
        }
        parsed = models.AuthenticationTokensResponse.from_dict(data)
        self.assertEqual(parsed.access_token.token, "acc")
        self.assertEqual(parsed.refresh_token.token, "ref")

    def test_auth_token_refresh(self):
        data = {"accessToken": {"token": "acc"}}
        parsed = models.AuthenticationTokenRefreshResponse.from_dict(data)
        self.assertEqual(parsed.access_token.token, "acc")

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
