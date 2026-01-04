import unittest

from ksef_client import types


class TypesTests(unittest.TestCase):
    def test_all_exports(self):
        self.assertIn("JsonDict", types.__all__)
        self.assertIn("Headers", types.__all__)
        self.assertTrue(hasattr(types, "JsonMapping"))


if __name__ == "__main__":
    unittest.main()
