import binascii
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


class StandardBase64StrictnessTests(unittest.TestCase):
    """`b64decode` musi odrzucać alfabet base64url, a nie po cichu go gubić.

    Bez ``validate=True`` w ``base64.b64decode`` znaki ``-``/``_`` są *odrzucane*
    (nie powodują błędu), więc helper "spróbuj standardowy base64, a w razie błędu
    base64url" nigdy nie robił fallbacku i zwracał krótszy — albo pusty — wynik.
    """

    def test_urlsafe_alphabet_is_rejected(self):
        with self.assertRaises(binascii.Error):
            b64decode("____")

    def test_real_digest_in_urlsafe_form_is_rejected(self):
        url_form = "Utbj3k-g3MKZRmlfk5QMPn8m8w4eOfSxpJrZiDkRJ4Y"
        with self.assertRaises(binascii.Error):
            b64decode(url_form)

    def test_valid_standard_base64_still_decodes(self):
        self.assertEqual(b64decode("YQ=="), b"a")
        self.assertEqual(b64decode(b"YWJj"), b"abc")

    def test_b64url_decode_handles_urlsafe_alphabet(self):
        self.assertEqual(b64url_decode("____"), b"\xff\xff\xff")
        self.assertEqual(b64url_decode("-w"), b"\xfb")


class Base64UrlStrictnessTests(unittest.TestCase):
    """`b64url_decode` musi zgłaszać błąd, a nie po cichu gubić znaki.

    ``base64.urlsafe_b64decode`` *odrzuca* znaki spoza alfabetu i zwraca krótszy
    — albo pusty — wynik, więc hash faktury ``"!!!"`` dawał link bez hasha
    zamiast czytelnego błędu.
    """

    def test_characters_outside_the_alphabet_are_rejected(self):
        for value in ("!!!!", "ab!d", "a b", "aą"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                b64url_decode(value)

    def test_impossible_length_is_rejected(self):
        with self.assertRaises(ValueError):
            b64url_decode("AAAAA")

    def test_invalid_value_is_reported_with_the_input(self):
        with self.assertRaisesRegex(ValueError, "Invalid base64url value"):
            b64url_decode("!")

    def test_valid_values_still_decode(self):
        self.assertEqual(b64url_decode("YQ"), b"a")
        self.assertEqual(b64url_decode("YWJj"), b"abc")
        self.assertEqual(b64url_decode(""), b"")


if __name__ == "__main__":
    unittest.main()
