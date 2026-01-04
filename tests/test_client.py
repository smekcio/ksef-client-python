import unittest
from unittest.mock import AsyncMock, Mock, patch

from ksef_client.client import AsyncKsefClient, KsefClient
from ksef_client.config import KsefClientOptions


class ClientTests(unittest.TestCase):
    def test_sync_client_context(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = KsefClient(options)
        with patch.object(client._http, "close", Mock()) as close_mock:
            with client as ctx:
                self.assertIs(ctx, client)
                self.assertIsNotNone(client.http_client)
            close_mock.assert_called_once()


class AsyncClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_client_context(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncKsefClient(options)
        with patch.object(client._http, "aclose", AsyncMock()) as aclose_mock:
            async with client as ctx:
                self.assertIs(ctx, client)
                self.assertIsNotNone(client.http_client)
            aclose_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
