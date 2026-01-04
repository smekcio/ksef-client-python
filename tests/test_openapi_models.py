import unittest

from ksef_client import openapi_models as m


class OpenApiModelsTests(unittest.TestCase):
    def test_from_dict_none(self):
        with self.assertRaises(ValueError):
            m.OpenApiModel.from_dict(None)  # type: ignore[arg-type]

    def test_enum_and_simple_model(self):
        method_value = list(m.AuthenticationMethod)[0].value
        data = {
            "authenticationMethod": method_value,
            "referenceNumber": "ref-1",
            "startDate": "2024-01-01",
            "status": {"code": 200, "description": "ok"},
        }
        item = m.AuthenticationListItem.from_dict(data)
        _ = m.AuthenticationListItem.from_dict(data)
        self.assertEqual(item.authenticationMethod.value, method_value)
        self.assertEqual(item.to_dict()["authenticationMethod"], method_value)

    def test_invoice_package_roundtrip(self):
        payload = {
            "invoiceCount": 1,
            "size": 10,
            "isTruncated": False,
            "parts": [
                {
                    "ordinalNumber": 1,
                    "partName": "p1",
                    "method": "GET",
                    "url": "https://example",
                    "partSize": 2,
                    "partHash": "hash",
                    "encryptedPartSize": 3,
                    "encryptedPartHash": "ehash",
                    "expirationDate": "2025-01-01",
                }
            ],
        }
        package = m.InvoicePackage.from_dict(payload)
        self.assertEqual(package.parts[0].partName, "p1")
        serialized = package.to_dict()
        self.assertEqual(serialized["parts"][0]["partName"], "p1")

    def test_invoice_status_extensions(self):
        payload = {
            "code": 200,
            "description": "ok",
            "extensions": {"x": None, "y": "1"},
        }
        info = m.InvoiceStatusInfo.from_dict(payload)
        self.assertIsNotNone(info.extensions)
        assert info.extensions is not None
        self.assertEqual(info.extensions["y"], "1")
        serialized = info.to_dict()
        self.assertIn("extensions", serialized)
        serialized_all = info.to_dict(omit_none=False)
        self.assertIn("details", serialized_all)

    def test_field_mapping(self):
        amount_type = list(m.AmountType)[0].value
        data = {"type": amount_type, "from": 10.0, "to": 20.0}
        parsed = m.InvoiceQueryAmount.from_dict(data)
        self.assertEqual(parsed.from_, 10.0)
        self.assertEqual(parsed.to, 20.0)
        self.assertIn("from", parsed.to_dict())


if __name__ == "__main__":
    unittest.main()
