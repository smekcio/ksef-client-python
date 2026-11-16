from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from ksef_client import KsefClientOptions
from ksef_client import models as m
from ksef_client.async_facade import AsyncAuthenticationOperation
from ksef_client.clients.auth import AsyncAuthClient, AuthClient
from ksef_client.clients.testdata import AsyncTestDataClient
from ksef_client.clients.testdata import TestDataClient as SyncTestDataClient
from ksef_client.clients.tokens import AsyncTokensClient, TokensClient
from ksef_client.facade import AuthenticationOperation
from ksef_client.http import HttpResponse
from ksef_client.operations import OperationState
from tests.test_clients import DummyAsyncHttp, DummyHttp

DATE = "2027-01-01T00:00:00Z"
DEMO = KsefClientOptions(base_url="https://api-demo.ksef.mf.gov.pl")
SNAPSHOT = Path(__file__).resolve().parents[1] / "specs/ksef-openapi.snapshot.json"


def response(path, method="get", status=200):
    spec = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    content = spec["paths"][path][method]["responses"][str(status)].get("content")
    if content:
        media = content["application/json"]
        example = (
            media["example"]
            if "example" in media
            else next(iter(media["examples"].values()))["value"]
        )
        body = json.dumps(example).encode()
    else:
        body = b""
    return HttpResponse(status, httpx.Headers({"Content-Type": "application/json"}), body)


@pytest.mark.parametrize("is_async", [False, True])
def test_rev2_operations(is_async):
    async def run():
        def http(path, method="get", status=200):
            result = response(path, method, status)
            return (DummyAsyncHttp if is_async else DummyHttp)(result)

        async def invoke(method, *args, **kwargs):
            result = method(*args, **kwargs)
            return await result if is_async else result

        tokens = AsyncTokensClient if is_async else TokensClient
        auth = AsyncAuthClient if is_async else AuthClient
        testdata = AsyncTestDataClient if is_async else SyncTestDataClient

        transport = http("/tokens/rev2", "post", 202)
        token = await invoke(
            tokens(transport).generate_token_rev2,
            m.GenerateTokenRequestRev2(
                description="Test token",
                permissions=[m.TokenPermissionType.INVOICEREAD],
                valid_to=DATE,
            ),
            access_token="access",
        )
        assert isinstance(token, m.GenerateTokenResponseRev2)
        assert token.token not in repr(token)
        assert transport.last_request_args == ("POST", "/tokens/rev2")
        assert transport.last_request_kwargs["expected_status"] == {202}
        assert transport.last_request_kwargs["json"] == {
            "description": "Test token",
            "permissions": ["InvoiceRead"],
            "validTo": DATE,
        }

        transport = http("/tokens/rev2")
        listed = await invoke(
            tokens(transport).list_tokens_rev2,
            statuses=[m.TokenStatusFilterRev2.ACTIVE, "AwaitingApproval"],
            author_identifier_type=m.TokenAuthorIdentifierTypeFilterRev2.NIP,
            valid_from=DATE,
            valid_to=DATE,
            page_size=15,
            continuation_token="next",
            description="Token",
            author_identifier="identifier",
        )
        assert isinstance(listed.tokens[0].status, m.TokenStatusRev2)
        assert transport.last_request_args == ("GET", "/tokens/rev2")
        assert transport.last_request_kwargs["params"] == {
            "status": ["Active", "AwaitingApproval"],
            "authorIdentifierType": "Nip",
            "validFrom": DATE,
            "validTo": DATE,
            "pageSize": 15,
            "description": "Token",
            "authorIdentifier": "identifier",
        }
        assert transport.last_request_kwargs["headers"] == {"x-continuation-token": "next"}
        await invoke(tokens(transport).list_tokens_rev2)
        assert transport.last_request_kwargs["params"] == {}
        assert transport.last_request_kwargs["headers"] is None

        transport = http("/tokens/rev2/{referenceNumber}")
        status = await invoke(tokens(transport).get_token_status_rev2, "ref", access_token="access")
        assert isinstance(status.status.code, m.TokenStatusRev2Code)
        assert status.valid_to
        assert transport.last_request_args == ("GET", "/tokens/rev2/ref")
        assert transport.last_request_kwargs["access_token"] == "access"

        for route, client, method_name in [
            ("/tokens/{referenceNumber}/approve", tokens, "approve_token"),
            (
                "/testdata/tokens/{referenceNumber}/expire-approval",
                testdata,
                "expire_token_approval",
            ),
        ]:
            transport = http(route, "post", 204)
            assert (
                await invoke(getattr(client(transport), method_name), "ref", access_token="access")
                is None
            )
            assert transport.last_request_args == (
                "POST",
                route.replace("{referenceNumber}", "ref"),
            )
            assert transport.last_request_kwargs["expected_status"] == {204}
            assert transport.last_request_kwargs["json"] is None

        transport = http("/auth/sessions/rev2")
        sessions = await invoke(
            auth(transport).get_active_sessions_rev2, page_size=10, continuation_token="next"
        )
        assert isinstance(
            sessions.items[0].authentication_method_info.category,
            m.AuthenticationMethodCategoryRev2,
        )
        assert transport.last_request_args == ("GET", "/auth/sessions/rev2")
        assert transport.last_request_kwargs["headers"] == {"x-continuation-token": "next"}
        assert transport.last_request_kwargs["params"] == {"pageSize": 10}
        await invoke(auth(transport).get_active_sessions_rev2)
        assert transport.last_request_kwargs["headers"] is None
        assert transport.last_request_kwargs["params"] is None

        transport = http("/auth/rev2/{referenceNumber}")
        auth_status = await invoke(auth(transport).get_auth_status_rev2, "ref", "auth-token")
        assert isinstance(auth_status, m.AuthenticationOperationStatusResponseRev2)
        assert isinstance(auth_status.authentication_method_info.category.raw_code, str)
        assert transport.last_request_args == ("GET", "/auth/rev2/ref")
        assert transport.last_request_kwargs["access_token"] == "auth-token"

    asyncio.run(run())


@pytest.mark.parametrize("rev2", [False, True])
def test_facade_can_select_auth_status_revision(rev2):
    options = replace(DEMO, auth_status_rev2=rev2)
    state = OperationState(
        kind="auth",
        reference_number="ref",
        environment=options.normalized_base_url(),
        context_key="Nip:123",
        payload={"authentication_token": "operation-token"},
    )
    sync_api = Mock()
    sync = AuthenticationOperation(sync_api, state, options)
    assert (
        sync.get_status()
        is (
            sync_api.auth.get_auth_status_rev2 if rev2 else sync_api.auth.get_auth_status
        ).return_value
    )

    async def run():
        api = Mock()
        api.auth.get_auth_status = AsyncMock()
        api.auth.get_auth_status_rev2 = AsyncMock()
        operation = AsyncAuthenticationOperation(api, state, options)
        selected = api.auth.get_auth_status_rev2 if rev2 else api.auth.get_auth_status
        assert await operation.get_status() is selected.return_value
        selected.assert_awaited_once_with("ref", "operation-token")

    asyncio.run(run())


def test_context_limits_accept_both_rollout_versions():
    old = m.EffectiveContextLimits(
        batch_session=m.BatchSessionEffectiveContextLimits(
            max_invoice_size_in_mb=1, max_invoice_with_attachment_size_in_mb=1, max_invoices=1
        ),
        online_session=m.OnlineSessionEffectiveContextLimits(
            max_invoice_size_in_mb=1, max_invoice_with_attachment_size_in_mb=1, max_invoices=1
        ),
        collective_identifier=m.CollectiveIdentifierEffectiveContextLimits(
            max_invoices=1,
        ),
    )
    assert m.EffectiveContextLimits.from_dict(old.to_dict()).tokens is None
    new = m.EffectiveContextLimits.from_dict({**old.to_dict(), "tokens": {"maxTokens": 30}})
    assert new.tokens == m.TokensEffectiveContextLimits(max_tokens=30)
