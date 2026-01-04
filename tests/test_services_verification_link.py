import base64
import unittest
from datetime import date
from unittest.mock import patch

from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.services.verification_link import (
    VerificationLinkService,
    _decode_base64_or_url,
    _sign_path,
)
from tests.helpers import generate_ec_cert, generate_ed25519_key_pem, generate_rsa_cert


class VerificationLinkTests(unittest.TestCase):
    def test_decode_base64_or_url(self):
        payload = b"data"
        b64 = base64.b64encode(payload).decode("ascii")
        b64url = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        self.assertEqual(_decode_base64_or_url(b64), payload)
        self.assertEqual(_decode_base64_or_url(b64url), payload)
        with patch("ksef_client.services.verification_link.b64decode", side_effect=ValueError):
            self.assertEqual(_decode_base64_or_url(b64url), payload)

    def test_invoice_verification_url(self):
        options = KsefClientOptions(base_url=KsefEnvironment.TEST.value)
        service = VerificationLinkService(options)
        url = service.build_invoice_verification_url("123", "01-01-2024", "YQ==")
        self.assertIn("/invoice/123/01-01-2024/", url)
        url_date = service.build_invoice_verification_url("123", date(2024, 1, 1), "YQ==")
        self.assertIn("/invoice/123/01-01-2024/", url_date)

    def test_certificate_verification_url_rsa(self):
        options = KsefClientOptions(base_url=KsefEnvironment.TEST.value)
        service = VerificationLinkService(options)
        rsa_cert = generate_rsa_cert()
        url = service.build_certificate_verification_url(
            seller_nip="123",
            context_identifier_type="nip",
            context_identifier_value="123",
            certificate_serial="1",
            invoice_hash="YQ==",
            signing_certificate_pem=rsa_cert.certificate_pem,
            private_key_pem=rsa_cert.private_key_pem,
            signature_format="p1363",
        )
        self.assertIn("/certificate/", url)

    def test_sign_path_errors(self):
        with self.assertRaises(ValueError):
            _sign_path("path", None, None, "p1363")

        ed_key = generate_ed25519_key_pem()
        with self.assertRaises(ValueError):
            _sign_path("path", None, ed_key, "p1363")

        rsa_cert = generate_rsa_cert()
        with self.assertRaises(ValueError):
            _sign_path("path", rsa_cert.certificate_pem, ed_key, "p1363")

    def test_sign_path_ec(self):
        ec_cert = generate_ec_cert()
        signature = _sign_path("path", None, ec_cert.private_key_pem, "der")
        self.assertTrue(signature)


if __name__ == "__main__":
    unittest.main()
