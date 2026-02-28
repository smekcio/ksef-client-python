import json
import unittest
from pathlib import Path
from unittest.mock import patch

from ksef_client import openapi_models as m


class OpenApiModelsTests(unittest.TestCase):
    def test_from_dict_none(self):
        with self.assertRaises(ValueError):
            m.OpenApiModel.from_dict(None)  # type: ignore[arg-type]

    def test_enum_and_simple_model(self):
        method_value = list(m.AuthenticationMethod)[0].value
        category_value = list(m.AuthenticationMethodCategory)[0].value
        data = {
            "authenticationMethod": method_value,
            "authenticationMethodInfo": {
                "category": category_value,
                "code": "auth.method.code",
                "displayName": "Auth method display name",
            },
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
            "extensions": {"x": None, "y": "1", "nested": {"a": 1}, "flag": True},
        }
        info = m.InvoiceStatusInfo.from_dict(payload)
        self.assertIsNotNone(info.extensions)
        assert info.extensions is not None
        self.assertEqual(info.extensions["y"], "1")
        self.assertEqual(info.extensions["nested"], {"a": 1})
        self.assertTrue(info.extensions["flag"])
        serialized = info.to_dict()
        self.assertIn("extensions", serialized)
        self.assertEqual(serialized["extensions"]["nested"], {"a": 1})
        self.assertTrue(serialized["extensions"]["flag"])
        serialized_all = info.to_dict(omit_none=False)
        self.assertIn("details", serialized_all)

    def test_field_mapping(self):
        amount_type = list(m.AmountType)[0].value
        data = {"type": amount_type, "from": 10.0, "to": 20.0}
        parsed = m.InvoiceQueryAmount.from_dict(data)
        self.assertEqual(parsed.from_, 10.0)
        self.assertEqual(parsed.to, 20.0)
        self.assertIn("from", parsed.to_dict())

    def test_token_permission_type_contains_introspection(self):
        values = {item.value for item in m.TokenPermissionType}
        self.assertIn("Introspection", values)

    def test_token_permission_type_matches_openapi_when_available(self):
        repo_root = Path(__file__).resolve().parents[2]
        openapi_path = repo_root / "ksef-docs" / "open-api.json"
        if not openapi_path.exists():
            self.skipTest(
                "open-api.json not found; enum compatibility test requires monorepo layout"
            )

        spec = json.loads(openapi_path.read_text(encoding="utf-8"))
        expected = set(spec["components"]["schemas"]["TokenPermissionType"]["enum"])
        actual = {item.value for item in m.TokenPermissionType}
        self.assertSetEqual(actual, expected)

    def test_part_upload_request_headers_keep_non_string_values(self):
        payload = {
            "headers": {
                "X-Request-Id": "abc",
                "X-Retry-After": 2,
                "X-Meta": {"source": "ksef"},
                "X-Enabled": True,
            },
            "method": "PUT",
            "ordinalNumber": 1,
            "url": "https://example",
        }
        parsed = m.PartUploadRequest.from_dict(payload)
        self.assertEqual(parsed.headers["X-Request-Id"], "abc")
        self.assertEqual(parsed.headers["X-Retry-After"], 2)
        self.assertEqual(parsed.headers["X-Meta"], {"source": "ksef"})
        self.assertTrue(parsed.headers["X-Enabled"])
        self.assertEqual(parsed.to_dict()["headers"], payload["headers"])

    def test_convert_value_handles_unsubscripted_list_hint(self):
        self.assertEqual(m._convert_value(list, ["a", "b"]), ["a", "b"])

    def test_convert_value_openapi_model_non_dict_returns_raw_value(self):
        self.assertEqual(m._convert_value(m.AuthenticationListItem, "raw"), "raw")

    def test_convert_value_union_with_empty_args_falls_through(self):
        with (
            patch("ksef_client.openapi_models.get_origin", return_value=object()),
            patch("ksef_client.openapi_models.get_args", return_value=()),
        ):
            self.assertEqual(m._convert_value("ignored", "value"), "value")


if __name__ == "__main__":
    unittest.main()
