import unittest

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError


class ExceptionsTests(unittest.TestCase):
    def test_http_error_str(self):
        err = KsefHttpError(status_code=500, message="boom")
        self.assertEqual(str(err), "HTTP 500: boom")

    def test_rate_limit_error(self):
        err = KsefRateLimitError(status_code=429, message="Too Many", retry_after="10")
        self.assertEqual(err.retry_after, "10")
        self.assertIsInstance(err, KsefHttpError)

    def test_api_error(self):
        err = KsefApiError(status_code=400, message="bad", exception_response={"a": 1})
        self.assertEqual(err.exception_response, {"a": 1})


if __name__ == "__main__":
    unittest.main()
