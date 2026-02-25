import unittest
from unittest.mock import patch

from ksef_client.config import (
    KsefClientOptions,
    KsefEnvironment,
    KsefLighthouseEnvironment,
    _package_version,
)


class ConfigTests(unittest.TestCase):
    def test_package_version_fallback(self):
        with patch("ksef_client.config.metadata.version", side_effect=Exception("boom")):
            self.assertEqual(_package_version(), "0.0.0")

    def test_normalized_base_url(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        self.assertEqual(options.normalized_base_url(), "https://api-test.ksef.mf.gov.pl/v2")

        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl/v2")
        self.assertEqual(options.normalized_base_url(), "https://api-test.ksef.mf.gov.pl/v2")

        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl/api/v2/")
        self.assertEqual(options.normalized_base_url(), "https://api-test.ksef.mf.gov.pl/api/v2")

    def test_resolve_qr_base_url(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl",
            base_qr_url="https://example.com/qr/",
        )
        self.assertEqual(options.resolve_qr_base_url(), "https://example.com/qr")

        options = KsefClientOptions(base_url=KsefEnvironment.TEST.value)
        self.assertEqual(options.resolve_qr_base_url(), "https://qr-test.ksef.mf.gov.pl")

        options = KsefClientOptions(base_url=KsefEnvironment.DEMO.value)
        self.assertEqual(options.resolve_qr_base_url(), "https://qr-demo.ksef.mf.gov.pl")

        options = KsefClientOptions(base_url=KsefEnvironment.PROD.value)
        self.assertEqual(options.resolve_qr_base_url(), "https://qr.ksef.mf.gov.pl")

        options = KsefClientOptions(base_url="https://example.com")
        with self.assertRaises(ValueError):
            options.resolve_qr_base_url()

    def test_resolve_lighthouse_base_url(self):
        options = KsefClientOptions(
            base_url="https://api-test.ksef.mf.gov.pl",
            base_lighthouse_url="https://example.com/lh/",
        )
        self.assertEqual(options.resolve_lighthouse_base_url(), "https://example.com/lh")

        options = KsefClientOptions(base_url=KsefEnvironment.TEST.value)
        self.assertEqual(
            options.resolve_lighthouse_base_url(),
            KsefLighthouseEnvironment.TEST.value,
        )

        options = KsefClientOptions(base_url=KsefEnvironment.DEMO.value)
        self.assertEqual(
            options.resolve_lighthouse_base_url(),
            KsefLighthouseEnvironment.TEST.value,
        )

        options = KsefClientOptions(base_url=KsefEnvironment.PROD.value)
        self.assertEqual(
            options.resolve_lighthouse_base_url(),
            KsefLighthouseEnvironment.PROD.value,
        )

        options = KsefClientOptions(base_url=KsefLighthouseEnvironment.PRD.value)
        self.assertEqual(
            options.resolve_lighthouse_base_url(),
            KsefLighthouseEnvironment.PROD.value,
        )

        options = KsefClientOptions(base_url="https://example.com")
        with self.assertRaises(ValueError):
            options.resolve_lighthouse_base_url()


if __name__ == "__main__":
    unittest.main()
