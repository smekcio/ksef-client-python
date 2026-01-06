import base64
import unittest

from ksef_client.services.auth import (
    AUTH_NS,
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
        self.assertIn("<Nip>123</Nip>", xml)
        self.assertIn("<Policy/>", xml)

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
            authorization_policy={"a": 1},
        )
        self.assertIn("authorizationPolicy", payload)
        self.assertEqual(payload["encryptedToken"], "enc")

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
