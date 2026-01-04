import json
import unittest

from ksef_client.services.person_token import (
    PersonTokenService,
    _distinct,
    _ensure_list,
    _parse_json_string_array,
    _split_jwt,
    _try_parse_json,
    _unix_to_datetime,
    _unwrap_if_quoted_json,
)
from ksef_client.utils.base64url import b64url_encode


class PersonTokenTests(unittest.TestCase):
    def test_parse_token(self):
        payload = {
            "iss": "issuer",
            "aud": ["a1", "a2"],
            "exp": 1700000000,
            "iat": "1700000001",
            "per": json.dumps(["p1", "p2"]),
            "pec": json.dumps(["x1"]),
            "rol": json.dumps(["r1"]),
            "pep": '"[\\"e1\\"]"',
            "role": ["legacy"],
            "roles": "single",
            "sud": json.dumps({"sub": "1"}),
            "ipp": json.dumps({"ip": "1"}),
        }
        token = _build_jwt(payload)
        parsed = PersonTokenService().parse(token)
        self.assertEqual(parsed.issuer, "issuer")
        self.assertIn("p1", parsed.permissions)
        self.assertIn("legacy", parsed.roles)
        self.assertIsNotNone(parsed.ip_policy)
        assert parsed.ip_policy is not None
        self.assertEqual(parsed.ip_policy["ip"], "1")

    def test_split_jwt_invalid(self):
        with self.assertRaises(ValueError):
            _split_jwt("bad")

    def test_unix_to_datetime(self):
        self.assertIsNotNone(_unix_to_datetime(1))
        self.assertIsNotNone(_unix_to_datetime("2"))
        self.assertIsNone(_unix_to_datetime("nope"))
        self.assertIsNone(_unix_to_datetime(None))

        self.assertIsNone(_unix_to_datetime(10**20))

    def test_try_parse_json(self):
        parsed = _try_parse_json(json.dumps({"a": 1}))
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual(parsed["a"], 1)
        self.assertIsNone(_try_parse_json("{bad"))
        self.assertIsNone(_try_parse_json(None))

    def test_parse_json_string_array(self):
        self.assertEqual(_parse_json_string_array(json.dumps(["a", "b"])), ["a", "b"])
        self.assertEqual(_parse_json_string_array("a,b"), ["a", "b"])
        self.assertEqual(_parse_json_string_array("a"), ["a"])
        self.assertEqual(_parse_json_string_array(None), [])

    def test_unwrap_if_quoted_json(self):
        value = _unwrap_if_quoted_json('"[1]"')
        self.assertEqual(value, "[1]")
        invalid = _unwrap_if_quoted_json('"\\x"')
        self.assertEqual(invalid, '"\\x"')

    def test_distinct_and_list(self):
        self.assertEqual(_distinct(["a", "A", "b"]), ["a", "b"])
        self.assertEqual(_ensure_list("a"), ["a"])
        self.assertEqual(_ensure_list(["a", 1]), ["a", "1"])
        self.assertEqual(_ensure_list(None), [])


def _build_jwt(payload: dict) -> str:
    header = b64url_encode(json.dumps({"alg": "none"}).encode("utf-8"))
    body = b64url_encode(json.dumps(payload).encode("utf-8"))
    return f"{header}.{body}."


if __name__ == "__main__":
    unittest.main()
