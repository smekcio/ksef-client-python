import copy
import pickle
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


class ExceptionsSerializationTests(unittest.TestCase):
    """Wyjątki muszą przetrwać ``pickle``/``copy`` — inaczej gubią się między procesami.

    Konstruktory SDK ustawiają pola słowami kluczowymi (``KsefApiError(status_code=...)``),
    więc ``args`` jest puste, a domyślny ``BaseException.__reduce__`` odtwarzał klasę bez
    argumentów wymaganych pozycyjnie (``TypeError: __init__() missing 2 required
    positional arguments``). ``ProcessPoolExecutor`` przenosi wynik przez ``pickle``,
    więc użytkownik dostawał inny błąd niż ten, który naprawdę wystąpił.
    """

    def _assert_round_trip(self, exc: KsefHttpError) -> None:
        for operation_name, restore in (
            ("pickle", lambda error: pickle.loads(pickle.dumps(error))),
            ("copy.copy", copy.copy),
            ("copy.deepcopy", copy.deepcopy),
        ):
            with self.subTest(operation=operation_name, exception=type(exc).__name__):
                restored = restore(exc)
                self.assertIs(type(restored), type(exc))
                self.assertEqual(restored, exc)
                self.assertEqual(str(restored), str(exc))
                self.assertEqual(restored.args, exc.args)

    def test_errors_built_with_keywords_survive_serialization(self):
        exception_response = ExceptionResponse.from_dict({"exception": {}})
        problem = UnknownApiProblem(status=503, title="boom", detail="bad", raw={"x": 1})
        errors = [
            KsefHttpError(
                status_code=503,
                message="boom",
                response_body={"x": 1},
                problem=problem,
                retry_after=30,
                retry_after_raw="30",
            ),
            KsefApiError(
                status_code=400,
                message="bad",
                response_body={"detail": "d"},
                problem=exception_response,
                exception_response=exception_response,
            ),
            KsefRateLimitError(
                status_code=429, message="Too Many", retry_after=10, retry_after_raw="10"
            ),
        ]
        for exc in errors:
            self._assert_round_trip(exc)

    def test_positional_args_are_preserved(self):
        err = KsefHttpError(500, "boom")
        restored = pickle.loads(pickle.dumps(err))
        self.assertEqual(restored.args, (500, "boom"))
        self.assertEqual(str(restored), "HTTP 500: boom")

    def test_rate_limit_error_keeps_its_positional_order(self):
        """`retry_after`/`retry_after_raw` zostają 5. i 6. argumentem pozycyjnym."""
        err = KsefRateLimitError(429, "Too Many", None, None, 5, "5")
        self.assertEqual(err.retry_after, 5)
        self.assertEqual(err.retry_after_raw, "5")
        self.assertIsNone(err.exception_response)
        self._assert_round_trip(err)

    def test_deepcopy_does_not_share_nested_payloads(self):
        problem = UnknownApiProblem(status=500, title="boom", detail="bad", raw={"x": 1})
        err = KsefHttpError(
            status_code=500, message="boom", problem=problem, response_body={"x": [1]}
        )
        restored = copy.deepcopy(err)
        self.assertIsNot(restored.problem, err.problem)
        self.assertIsNot(restored.response_body, err.response_body)
        self.assertEqual(restored.response_body, err.response_body)


class RateLimitProblemTests(unittest.TestCase):
    """429 z ciałem ``ExceptionResponse`` ma wypełniać oba pola problemu."""

    def test_rate_limit_with_exception_payload_fills_both_fields(self):
        problem = ExceptionResponse.from_dict({"exception": {}})
        err = KsefRateLimitError(status_code=429, message="Too Many Requests", problem=problem)
        self.assertIsInstance(err.problem, ExceptionResponse)
        self.assertIs(err.exception_response, problem)

    def test_explicit_exception_response_is_not_overwritten(self):
        problem = ExceptionResponse.from_dict({"exception": {"exceptionDetailList": []}})
        explicit = ExceptionResponse.from_dict({"exception": {}})
        err = KsefRateLimitError(
            status_code=429,
            message="Too Many Requests",
            problem=problem,
            exception_response=explicit,
        )
        self.assertIs(err.exception_response, explicit)

    def test_non_exception_problem_leaves_exception_response_empty(self):
        problem = UnknownApiProblem(status=429, title="boom", detail=None, raw={"error": "limit"})
        err = KsefRateLimitError(status_code=429, message="Too Many Requests", problem=problem)
        self.assertIsNone(err.exception_response)


if __name__ == "__main__":
    unittest.main()
