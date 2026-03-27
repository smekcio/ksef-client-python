import unittest

from ksef_client.exceptions import KsefApiError, KsefHttpError, KsefRateLimitError
from ksef_client.models import ExceptionResponse, UnknownApiProblem


class ExceptionsTests(unittest.TestCase):
    def test_http_error_str(self):
        err = KsefHttpError(status_code=500, message="boom")
        self.assertEqual(str(err), "HTTP 500: boom")

    def test_rate_limit_error(self):
        err = KsefRateLimitError(
            status_code=429,
            message="Too Many",
            retry_after=10,
            retry_after_raw="10",
        )
        self.assertEqual(err.retry_after, 10)
        self.assertEqual(err.retry_after_raw, "10")
        self.assertIsInstance(err, KsefHttpError)

    def test_api_error(self):
        problem = ExceptionResponse.from_dict({"exception": {}})
        err = KsefApiError(
            status_code=400, message="bad", exception_response=problem, problem=problem
        )
        self.assertIs(err.exception_response, problem)
        self.assertIs(err.problem, problem)

    def test_http_error_problem(self):
        problem = UnknownApiProblem(status=500, title="boom", detail="bad", raw={"x": 1})
        err = KsefHttpError(status_code=500, message="boom", problem=problem)
        self.assertIs(err.problem, problem)


if __name__ == "__main__":
    unittest.main()
