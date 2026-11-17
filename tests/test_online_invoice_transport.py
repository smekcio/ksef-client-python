"""Resume an encrypted online session across client and database restarts."""

from __future__ import annotations

import json
from contextlib import contextmanager

import httpx
import pytest

from ksef_client import AuthenticatedClient, Ksef, KsefClientOptions
from ksef_client.exceptions import KsefResponseLimitError, KsefTransportError
from ksef_client.online_invoices import OnlineInvoiceStatus, SQLiteOnlineInvoiceStore
from ksef_client.token_manager import TokenManager
from tests.helpers import generate_rsa_cert
from tests.test_offline_invoice_state import HASH, NUMBER, remote_invoice
from tests.test_offline_invoice_store import KEY, XML
from tests.test_online_invoices import individual_upo


def test_real_session_checkpoint_recovers_individual_upo_after_disconnected_post(tmp_path):
    options = KsefClientOptions(base_url="https://example.test/v2")
    certificate = generate_rsa_cert()
    sent = 0
    closed = False
    oversized_upo = True
    upo = individual_upo()

    def respond(request):
        nonlocal sent, closed
        method, path = request.method, request.url.path
        if path == "/v2/security/public-key-certificates":
            return httpx.Response(
                200,
                json=[
                    {
                        "certificate": certificate.certificate_der_b64,
                        "usage": ["SymmetricKeyEncryption"],
                        "validFrom": "2000-01-01T00:00:00Z",
                        "validTo": "2100-01-01T00:00:00Z",
                    }
                ],
            )
        assert request.headers["Authorization"] == "Bearer test-token"
        if (method, path) == ("POST", "/v2/sessions/online"):
            assert json.loads(request.content)["encryption"]["encryptedSymmetricKey"]
            return httpx.Response(201, json={"referenceNumber": "session-1"})
        if (method, path) == ("POST", "/v2/sessions/online/session-1/invoices"):
            payload = json.loads(request.content)
            assert payload["offlineMode"] is False and payload["invoiceHash"] == HASH
            assert payload["encryptedInvoiceContent"] and XML not in request.content
            sent += 1
            raise httpx.ReadError("connection lost after receiving invoice", request=request)
        if (method, path) == ("GET", "/v2/sessions/session-1/invoices"):
            return httpx.Response(
                200, json={"invoices": [remote_invoice(200, number=NUMBER).to_dict()]}
            )
        if (method, path) == ("GET", "/v2/sessions/session-1"):
            return httpx.Response(
                200,
                json={
                    "dateCreated": "2026-11-01T00:00:00Z",
                    "dateUpdated": "2026-11-01T00:01:00Z",
                    "status": {"code": 200 if closed else 100, "description": "test"},
                },
            )
        if (method, path) == ("POST", "/v2/sessions/online/session-1/close"):
            closed = True
            return httpx.Response(204)
        assert (method, path) == ("GET", "/v2/sessions/session-1/invoices/invoice-1/upo")
        assert closed
        content = b" " * (1024 * 1024 + 1) if oversized_upo else upo
        return httpx.Response(
            200, content=iter([content]), headers={"Content-Type": "application/xml"}
        )

    @contextmanager
    def reopen():
        api = AuthenticatedClient(options, TokenManager("test-token"))
        with api:
            http = api.http_client
            http._client.close()
            http._client = httpx.Client(transport=httpx.MockTransport(respond))
            client = Ksef(api, options, context_type="Nip", context_value="integration")
            with SQLiteOnlineInvoiceStore.open(tmp_path / "state.db", key=KEY) as store:
                yield client.invoices.online(store, namespace="tenant")

    with reopen() as online:
        online.enqueue("local-id", XML)
        assert online.advance("local-id").status is OnlineInvoiceStatus.SESSION_OPEN
    with reopen() as online, pytest.raises(KsefTransportError):
        online.advance("local-id")
    with reopen() as online:
        assert online.advance("local-id").ksef_number == NUMBER
        assert online.advance("local-id").status is OnlineInvoiceStatus.ACCEPTED
        with pytest.raises(KsefResponseLimitError):
            online.advance("local-id")
        oversized_upo = False
        assert online.advance("local-id").status is OnlineInvoiceStatus.COMPLETE
        assert online.read_upo("local-id") == upo
    assert sent == 1
