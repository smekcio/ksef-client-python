"""Resume an encrypted online session across client and database restarts."""

from __future__ import annotations

import asyncio
import json
from contextlib import AsyncExitStack, contextmanager
from inspect import isawaitable

import httpx
import pytest

from ksef_client import (
    AsyncAuthenticatedClient,
    AsyncKsef,
    AuthenticatedClient,
    Ksef,
    KsefClientOptions,
)
from ksef_client.exceptions import (
    KsefHttpError,
    KsefResponseLimitError,
    KsefTransportError,
)
from ksef_client.models import TokenInfo
from ksef_client.online_invoices import (
    AsyncOnlineInvoices,
    AsyncSQLiteOnlineInvoiceStore,
    OnlineInvoices,
    OnlineInvoiceStatus,
    SQLiteOnlineInvoiceStore,
)
from ksef_client.token_manager import AsyncTokenManager, TokenManager, TokenManagerError
from tests.helpers import generate_rsa_cert
from tests.test_offline_invoice_state import HASH, NUMBER, remote_invoice
from tests.test_offline_invoice_store import KEY, XML
from tests.test_online_invoices import individual_upo


def streamed_json(payload):
    return httpx.Response(
        200,
        stream=httpx.ByteStream(json.dumps(payload).encode()),
        headers={"Content-Type": "application/json"},
    )


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
            return streamed_json(
                {
                    "continuationToken": "",
                    "invoices": [
                        {
                            **remote_invoice(200, number=NUMBER).to_dict(),
                            "ordinalNumber": 1,
                            "invoicingDate": "2026-11-01T00:00:00Z",
                        }
                    ],
                },
            )
        if (method, path) == ("GET", "/v2/sessions/session-1"):
            return streamed_json(
                {
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


@pytest.mark.parametrize("phase", ["open", "send", "close"])
@pytest.mark.parametrize("use_async", [False, True])
def test_durable_online_post_refreshes_after_401_without_replaying(tmp_path, use_async, phase):
    options = KsefClientOptions(base_url="https://example.test/v2")
    certificate = generate_rsa_cert()
    paths = {
        "open": "/v2/sessions/online",
        "send": "/v2/sessions/online/session-1/invoices",
        "close": "/v2/sessions/online/session-1/close",
    }
    posts = []
    refreshes = []
    finalized = False

    def refresh(token):
        refreshes.append(token)
        return TokenInfo("fresh-token", "2099-01-01T00:00:00Z")

    def respond(request):
        method, path = request.method, request.url.path
        if method == "POST":
            posts.append(path)
            if path == paths[phase] and request.headers["Authorization"] == "Bearer stale-token":
                return httpx.Response(401)
            if path == paths["open"]:
                return httpx.Response(201, json={"referenceNumber": "session-1"})
            if path == paths["send"]:
                raise httpx.ReadError("send result unavailable", request=request)
            assert path == paths["close"]
            return httpx.Response(204)
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
        if (method, path) == ("GET", "/v2/sessions/session-1/invoices"):
            assert finalized
            return streamed_json({"invoices": [], "continuationToken": ""})
        assert (method, path) == ("GET", "/v2/sessions/session-1")
        if refreshes:
            assert request.headers["Authorization"] == "Bearer fresh-token"
        return streamed_json(
            {
                "dateCreated": "2026-11-01T00:00:00Z",
                "dateUpdated": "2026-11-01T00:01:00Z",
                "status": {"code": 440 if finalized else 100, "description": "test"},
                "invoiceCount": 0,
            },
        )

    async def call(method, *args):
        result = method(*args)
        return await result if isawaitable(result) else result

    async def run():
        nonlocal finalized
        async with AsyncExitStack() as stack:
            path = tmp_path / "online.db"
            api: AuthenticatedClient | AsyncAuthenticatedClient
            online: OnlineInvoices | AsyncOnlineInvoices
            if use_async:
                api = AsyncAuthenticatedClient(
                    options,
                    AsyncTokenManager("stale-token", "refresh-token", refresh_handler=refresh),
                )
                await stack.enter_async_context(api)
                await api.http_client._client.aclose()
                api.http_client._client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
                client = AsyncKsef(api, options, context_type="Nip", context_value="test")
                store = await stack.enter_async_context(
                    await AsyncSQLiteOnlineInvoiceStore.open(path, key=KEY)
                )
                online = client.invoices.online(store, namespace="tenant")
            else:
                api = AuthenticatedClient(
                    options, TokenManager("stale-token", "refresh-token", refresh_handler=refresh)
                )
                stack.enter_context(api)
                api.http_client._client.close()
                api.http_client._client = httpx.Client(transport=httpx.MockTransport(respond))
                sync_client = Ksef(api, options, context_type="Nip", context_value="test")
                sync_store = stack.enter_context(SQLiteOnlineInvoiceStore.open(path, key=KEY))
                online = sync_client.invoices.online(sync_store, namespace="tenant")
            await call(online.enqueue, "id", XML)
            if phase != "open":
                await call(online.advance, "id")
            if phase == "close":
                with pytest.raises(KsefTransportError):
                    await call(online.advance, "id")
            action = online.retry_if_unsubmitted if phase == "close" else online.advance
            with pytest.raises(KsefHttpError) as caught:
                await call(action, "id")
            assert caught.value.status_code == 401
            assert posts.count(paths[phase]) == 1
            assert refreshes == ["refresh-token"]
            row = await call(online.status, "id")
            assert row.status is (
                OnlineInvoiceStatus.QUEUED
                if phase == "open"
                else OnlineInvoiceStatus.SUBMISSION_UNKNOWN
            )
            await call(api.sessions.get_session_status, "session-1")
            if phase == "send":
                finalized = True
                retry = await call(online.retry_if_unsubmitted, "id")
                assert retry.status is OnlineInvoiceStatus.QUEUED
                assert posts.count(paths["send"]) == 1

    asyncio.run(run())


@pytest.mark.parametrize("use_async", [False, True])
@pytest.mark.parametrize("rebind_during_request", [False, True])
def test_durable_online_refuses_rebound_default_auth_transport(
    tmp_path, use_async, rebind_during_request
):
    options = KsefClientOptions(base_url="https://example.test/v2")
    other_options = KsefClientOptions(base_url="https://other.example.test/v2")
    certificate = generate_rsa_cert()
    wire = []
    other_wire = []

    def other_response(request):
        other_wire.append(request.url.path)
        return httpx.Response(401)

    async def run():
        api: AuthenticatedClient | AsyncAuthenticatedClient
        other_api: AuthenticatedClient | AsyncAuthenticatedClient
        worker: OnlineInvoices | AsyncOnlineInvoices

        def respond(request):
            wire.append((request.method, request.url.path))
            if request.url.path == "/v2/security/public-key-certificates":
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
            assert request.url.path == "/v2/sessions/online"
            api.token_manager.bind_auth_client(other_api.auth)
            return httpx.Response(401)

        async with AsyncExitStack() as stack:
            path = tmp_path / "online.db"
            valid_until = None if rebind_during_request else "2000-01-01T00:00:00Z"
            if use_async:
                manager = AsyncTokenManager(
                    "access-a", "refresh-a", access_token_valid_until=valid_until
                )
                other_api = AsyncAuthenticatedClient(other_options, manager)
                api = AsyncAuthenticatedClient(options, manager)
                for instance, responder in ((other_api, other_response), (api, respond)):
                    await stack.enter_async_context(instance)
                    await instance.http_client._client.aclose()
                    instance.http_client._client = httpx.AsyncClient(
                        transport=httpx.MockTransport(responder)
                    )
                client = AsyncKsef(api, options, context_type="Nip", context_value="test")
                store = await stack.enter_async_context(
                    await AsyncSQLiteOnlineInvoiceStore.open(path, key=KEY)
                )
                worker = client.invoices.online(store, namespace="tenant")
                await worker.enqueue("id", XML)
            else:
                sync_manager = TokenManager(
                    "access-a", "refresh-a", access_token_valid_until=valid_until
                )
                other_api = AuthenticatedClient(other_options, sync_manager)
                api = AuthenticatedClient(options, sync_manager)
                for instance, responder in ((other_api, other_response), (api, respond)):
                    stack.enter_context(instance)
                    instance.http_client._client.close()
                    instance.http_client._client = httpx.Client(
                        transport=httpx.MockTransport(responder)
                    )
                sync_client = Ksef(api, options, context_type="Nip", context_value="test")
                sync_store = stack.enter_context(SQLiteOnlineInvoiceStore.open(path, key=KEY))
                worker = sync_client.invoices.online(sync_store, namespace="tenant")
                worker.enqueue("id", XML)

            if not rebind_during_request:
                api.token_manager.bind_auth_client(other_api.auth)
            with pytest.raises(TokenManagerError, match="authentication transport changed"):
                result = worker.advance("id")
                if isawaitable(result):
                    await result
            row = worker.status("id")
            if isawaitable(row):
                row = await row
            assert row.status is OnlineInvoiceStatus.QUEUED
        assert not other_wire
        expected_wire = [("GET", "/v2/security/public-key-certificates")]
        if rebind_during_request:
            expected_wire.append(("POST", "/v2/sessions/online"))
        assert wire == expected_wire

    asyncio.run(run())
