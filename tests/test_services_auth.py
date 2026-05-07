import base64
import unittest

from ksef_client.services.auth import (
    AUTH_NS,
    AUTH_TOKEN_REQUEST_NAMESPACE_BY_SCHEMA_VERSION,
    _context_tag,
    build_auth_token_request_xml,
    build_ksef_token_auth_request,
    encrypt_ksef_token,
)
from tests.helpers import generate_ec_cert, generate_rsa_cert


class AuthServiceTests(unittest.TestCase):
    def test_build_auth_token_request_xml(self):
        xml = build_auth_token_request_xml(
            challenge="c",
            context_identifier_type="nip",
            context_identifier_value="123",
            subject_identifier_type="certificateSubject",
            authorization_policy_xml="<Policy/>",
        )
        self.assertIn(AUTH_NS, xml)
        self.assertIn("http://ksef.mf.gov.pl/auth/token/2.1", xml)
        self.assertIn("<Nip>123</Nip>", xml)
        self.assertIn("<Policy/>", xml)

    def test_build_auth_token_request_xml_supports_schema_2_0(self):
        xml = build_auth_token_request_xml(
            challenge="c",
            context_identifier_type="nip",
            context_identifier_value="123",
            schema_version="2.0",
        )
        self.assertIn(AUTH_TOKEN_REQUEST_NAMESPACE_BY_SCHEMA_VERSION["2.0"], xml)
        self.assertNotIn(AUTH_TOKEN_REQUEST_NAMESPACE_BY_SCHEMA_VERSION["2.1"], xml)

    def test_build_auth_token_request_xml_rejects_unknown_schema_version(self):
        with self.assertRaises(ValueError):
            build_auth_token_request_xml(
                challenge="c",
                context_identifier_type="nip",
                context_identifier_value="123",
                schema_version="1.0",
            )

    def test_context_tag(self):
        self.assertEqual(_context_tag("NIP"), "Nip")
        self.assertEqual(_context_tag("internalId"), "InternalId")
        self.assertEqual(_context_tag("nipVatUe"), "NipVatUe")
        self.assertEqual(_context_tag("peppolId"), "PeppolId")
        with self.assertRaises(ValueError):
            _context_tag("other")

    def test_build_ksef_token_auth_request(self):
        payload = build_ksef_token_auth_request(
            challenge="c",
            context_identifier_type="nip",
            context_identifier_value="123",
            encrypted_token_base64="enc",
            public_key_id="key-id",
            authorization_policy=None,
        )
        self.assertEqual(payload.encrypted_token, "enc")
        self.assertEqual(payload.public_key_id, "key-id")
        self.assertEqual(payload.to_dict()["publicKeyId"], "key-id")
        self.assertEqual(payload.challenge, "c")
        self.assertEqual(payload.context_identifier.value, "123")

    def test_encrypt_ksef_token(self):
        rsa_cert = generate_rsa_cert()
        result_rsa = encrypt_ksef_token(
            public_certificate=rsa_cert.certificate_pem,
            token="token",
            timestamp_ms=123,
            method="rsa",
        )
        self.assertTrue(base64.b64decode(result_rsa))

        ec_cert = generate_ec_cert()
        result_ec = encrypt_ksef_token(
            public_certificate=ec_cert.certificate_pem,
            token="token",
            timestamp_ms=123,
            method="ec",
            ec_output_format="java",
        )
        self.assertTrue(base64.b64decode(result_ec))

        with self.assertRaises(ValueError):
            encrypt_ksef_token(
                public_certificate=rsa_cert.certificate_pem,
                token="token",
                timestamp_ms=1,
                method="unknown",
            )


if __name__ == "__main__":
    unittest.main()
