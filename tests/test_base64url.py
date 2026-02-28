import unittest

from ksef_client.utils.base64url import b64decode, b64encode, b64url_decode, b64url_encode


class Base64UrlTests(unittest.TestCase):
    def test_roundtrip(self):
        data = b"hello-world"
        encoded = b64url_encode(data)
        decoded = b64url_decode(encoded)
        self.assertEqual(decoded, data)

    def test_standard_base64(self):
        data = b"data"
        encoded = b64encode(data)
        decoded = b64decode(encoded)
        self.assertEqual(decoded, data)

    def test_standard_base64_decode_bytes_input(self):
        data = b"data"
        encoded = b64encode(data).encode("ascii")
        decoded = b64decode(encoded)
        self.assertEqual(decoded, data)


if __name__ == "__main__":
    unittest.main()
