import unittest

from ksef_client.services.hwm import (
    dedupe_by_ksef_number,
    get_effective_start_date,
    update_continuation_point,
)


class HwmServiceTests(unittest.TestCase):
    def test_update_continuation_point(self):
        points: dict[str, str | None] = {}
        update_continuation_point(
            points, "seller", {"isTruncated": True, "lastPermanentStorageDate": "2024-01-01"}
        )
        self.assertEqual(points["seller"], "2024-01-01")

        update_continuation_point(
            points, "seller", {"isTruncated": False, "permanentStorageHwmDate": "2024-02-01"}
        )
        self.assertEqual(points["seller"], "2024-02-01")

        update_continuation_point(points, "seller", {"isTruncated": False})
        self.assertNotIn("seller", points)

    def test_get_effective_start_date(self):
        points: dict[str, str | None] = {"buyer": "2024-01-01"}
        self.assertEqual(get_effective_start_date(points, "buyer", "2024-02-01"), "2024-01-01")
        self.assertEqual(get_effective_start_date(points, "other", "2024-02-01"), "2024-02-01")

    def test_dedupe_by_ksef_number(self):
        data = [
            {"ksefNumber": "ABC"},
            {"KsefNumber": "abc"},
            {"ksefNumber": "DEF"},
            {"other": "x"},
        ]
        result = dedupe_by_ksef_number(data)
        self.assertEqual(len(result), 2)
        self.assertIn("ABC", result)
        self.assertIn("DEF", result)


if __name__ == "__main__":
    unittest.main()
