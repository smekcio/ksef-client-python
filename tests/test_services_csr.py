import base64
import unittest

from cryptography import x509
from cryptography.x509.oid import NameOID

from ksef_client.services.csr import _build_subject, generate_csr_ec, generate_csr_rsa


class CsrServiceTests(unittest.TestCase):
    def test_build_subject(self):
        subject = _build_subject(
            {
                "commonName": "Test",
                "organizationName": "KSeF",
                "countryName": "PL",
                "organizationIdentifier": "ID",
                "serialNumber": "SN",
                "uniqueIdentifier": "UID",
            }
        )
        self.assertEqual(subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "Test")
        self.assertEqual(subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value, "KSeF")
        self.assertEqual(subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value, "PL")
        self.assertEqual(
            subject.get_attributes_for_oid(NameOID.ORGANIZATION_IDENTIFIER)[0].value, "ID"
        )
        self.assertEqual(subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value, "SN")
        self.assertEqual(
            subject.get_attributes_for_oid(NameOID.X500_UNIQUE_IDENTIFIER)[0].value, "UID"
        )

    def test_generate_csr_rsa(self):
        csr = generate_csr_rsa({"commonName": "Test"})
        csr_bytes = base64.b64decode(csr.csr_base64)
        parsed = x509.load_der_x509_csr(csr_bytes)
        self.assertEqual(parsed.subject.rfc4514_string(), "CN=Test")

    def test_generate_csr_ec(self):
        csr = generate_csr_ec({"commonName": "Test"})
        csr_bytes = base64.b64decode(csr.csr_base64)
        parsed = x509.load_der_x509_csr(csr_bytes)
        self.assertEqual(parsed.subject.rfc4514_string(), "CN=Test")


if __name__ == "__main__":
    unittest.main()
