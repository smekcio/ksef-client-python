import re
import unittest
from unittest.mock import patch

from ksef_client.utils.ksef_number import _crc8, validate_ksef_number, is_valid_ksef_number


class KsefNumberValidatorTests(unittest.TestCase):
    def test_valid_ksef_number(self):
        ksef = "5265877635-20250826-0100001AF629-AF"
        result = validate_ksef_number(ksef)
        self.assertTrue(result.is_valid)

    def test_invalid_checksum(self):
        ksef = "5265877635-20250826-0100001AF629-00"
        result = validate_ksef_number(ksef)
        self.assertFalse(result.is_valid)

    def test_empty(self):
        self.assertFalse(is_valid_ksef_number(""))

    def test_invalid_format(self):
        result = validate_ksef_number("bad-format")
        self.assertFalse(result.is_valid)

    def test_invalid_parts(self):
        ksef = "1234567890-20240101-ABCDEF--123456-F"
        with patch("ksef_client.utils.ksef_number.KSEF_NUMBER_PATTERN", re.compile(r".*")):
            result = validate_ksef_number(ksef)
        self.assertFalse(result.is_valid)

    def test_invalid_length(self):
        ksef = "1234567890-20240101-ABCDEF-1234-AF"
        with patch("ksef_client.utils.ksef_number.KSEF_NUMBER_PATTERN", re.compile(r".*")):
            result = validate_ksef_number(ksef)
        self.assertFalse(result.is_valid)

    def test_optional_hyphen_valid(self):
        nip = "5265877635"
        date = "20250826"
        part = "0100001AF629"
        normalized = f"{nip}-{date}-{part}-00"
        checksum = f"{_crc8(normalized[:32].encode('ascii')):02X}"
        normalized = f"{nip}-{date}-{part}-{checksum}"
        with_hyphen = f"{nip}-{date}-{part[:6]}-{part[6:]}-{checksum}"
        result = validate_ksef_number(with_hyphen)
        self.assertTrue(result.is_valid)


if __name__ == "__main__":
    unittest.main()
