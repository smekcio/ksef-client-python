import unittest

from ksef_client.utils.certificate_serial import (
    is_valid_certificate_serial_number,
    require_certificate_serial_number,
    validate_certificate_serial_number,
)
from ksef_client.utils.collective_identifier import (
    is_valid_collective_identifier_number,
    require_collective_identifier_number,
    validate_collective_identifier_number,
)
from ksef_client.utils.ksef_number import _crc8, require_ksef_number


class CollectiveIdentifierValidatorTests(unittest.TestCase):
    def test_valid_collective_identifier(self):
        value = "1111111111-IZ202607-65ED02180000-E7"
        result = validate_collective_identifier_number(value)
        self.assertTrue(result.is_valid)
        self.assertEqual(require_collective_identifier_number(value), value)

    def test_invalid_checksum(self):
        value = "1111111111-IZ202607-65ED02180000-00"
        result = validate_collective_identifier_number(value)
        self.assertFalse(result.is_valid)
        self.assertIn("checksum mismatch", result.message)

    def test_empty(self):
        self.assertFalse(is_valid_collective_identifier_number(""))
        with self.assertRaises(ValueError):
            require_collective_identifier_number("")

    def test_invalid_format(self):
        result = validate_collective_identifier_number("not-an-iz")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.message, "invalid format")

    def test_lowercase_hex_rejected(self):
        value = "1111111111-IZ202607-65ed02180000-E7"
        self.assertFalse(is_valid_collective_identifier_number(value))

    def test_computed_checksum_roundtrip(self):
        prefix = "2222222222-IZ202601-AABBCCDDEEFF"
        checksum = f"{_crc8(prefix.encode('ascii')):02X}"
        value = f"{prefix}-{checksum}"
        self.assertTrue(is_valid_collective_identifier_number(value))


class CertificateSerialValidatorTests(unittest.TestCase):
    def test_valid_serial(self):
        value = "ABCDEF0123456789"
        result = validate_certificate_serial_number(value)
        self.assertTrue(result.is_valid)
        self.assertEqual(require_certificate_serial_number(value), value)

    def test_empty(self):
        self.assertFalse(is_valid_certificate_serial_number(""))
        with self.assertRaises(ValueError):
            require_certificate_serial_number("")

    def test_invalid_format(self):
        result = validate_certificate_serial_number("abcdef0123456789")
        self.assertFalse(result.is_valid)
        self.assertEqual(result.message, "invalid format")
        with self.assertRaises(ValueError):
            require_certificate_serial_number("short")


class KsefNumberRequireTests(unittest.TestCase):
    def test_require_valid(self):
        value = "5265877635-20250826-0100001AF629-AF"
        self.assertEqual(require_ksef_number(value), value)

    def test_require_invalid(self):
        with self.assertRaises(ValueError):
            require_ksef_number("bad")


if __name__ == "__main__":
    unittest.main()
