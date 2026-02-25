import unittest
from unittest.mock import AsyncMock, Mock, patch

from ksef_client.client import AsyncKsefClient, KsefClient
from ksef_client.config import KsefClientOptions


class ClientTests(unittest.TestCase):
    def test_sync_client_context(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = KsefClient(options)
        with (
            patch.object(client._http, "close", Mock()) as close_mock,
            patch.object(client._lighthouse_http, "close", Mock()) as lighthouse_close_mock,
        ):
            with client as ctx:
                self.assertIs(ctx, client)
                self.assertIsNotNone(client.http_client)
                self.assertIsNotNone(client.lighthouse)
            close_mock.assert_called_once()
            lighthouse_close_mock.assert_called_once()

    def test_sync_client_unknown_lighthouse_mapping_fallbacks_to_empty_base(self):
        options = KsefClientOptions(base_url="https://unknown.example")
        client = KsefClient(options)
        with patch.object(client._http, "close", Mock()), patch.object(
            client._lighthouse_http, "close", Mock()
        ):
            self.assertEqual(client.lighthouse._base_url, "")
            client.close()


class AsyncClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_client_context(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncKsefClient(options)
        with (
            patch.object(client._http, "aclose", AsyncMock()) as aclose_mock,
            patch.object(
                client._lighthouse_http,
                "aclose",
                AsyncMock(),
            ) as lighthouse_aclose_mock,
        ):
            async with client as ctx:
                self.assertIs(ctx, client)
                self.assertIsNotNone(client.http_client)
                self.assertIsNotNone(client.lighthouse)
            aclose_mock.assert_called_once()
            lighthouse_aclose_mock.assert_called_once()

    async def test_async_client_unknown_lighthouse_mapping_fallbacks_to_empty_base(self):
        options = KsefClientOptions(base_url="https://unknown.example")
        client = AsyncKsefClient(options)
        with patch.object(client._http, "aclose", AsyncMock()), patch.object(
            client._lighthouse_http, "aclose", AsyncMock()
        ):
            self.assertEqual(client.lighthouse._base_url, "")
            await client.aclose()


if __name__ == "__main__":
    unittest.main()
