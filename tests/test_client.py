import unittest
from unittest.mock import AsyncMock, Mock

from ksef_client.client import AsyncKsefClient, KsefClient
from ksef_client.config import KsefClientOptions


class ClientTests(unittest.TestCase):
    def test_sync_client_context(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = KsefClient(options)
        client._http.close = Mock()
        with client as ctx:
            self.assertIs(ctx, client)
            self.assertIsNotNone(client.http_client)
        client._http.close.assert_called_once()


class AsyncClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_async_client_context(self):
        options = KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")
        client = AsyncKsefClient(options)
        client._http.aclose = AsyncMock()
        async with client as ctx:
            self.assertIs(ctx, client)
            self.assertIsNotNone(client.http_client)
        client._http.aclose.assert_called_once()


if __name__ == "__main__":
    unittest.main()
