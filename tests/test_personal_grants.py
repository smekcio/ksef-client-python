import asyncio
import json
from typing import Any

import httpx
import pytest

from ksef_client import (
    AsyncAuthenticatedClient,
    AsyncKsef,
    AsyncTokenManager,
    AuthenticatedClient,
    Ksef,
    KsefClientOptions,
    TokenManager,
)
from ksef_client.clients.permissions import _parse_personal_grants
from ksef_client.exceptions import KsefPaginationError


def grant(number: int, **fields: Any) -> dict[str, Any]:
    return {
        "id": f"00000000-0000-0000-0000-{number:012d}",
        "permissionScope": "InvoiceRead",
        "permissionState": "Active",
        "canDelegate": False,
        "description": "Example permission",
        "startDate": "2026-01-01T00:00:00Z",
        **fields,
    }


@pytest.fixture(params=["sync", "async"])
def read_pages(request, monkeypatch):
    options = KsefClientOptions("https://permissions.example")

    def read(pages, **kwargs):
        offsets: list[int] = []

        def respond(transport, req):
            assert req.method == "POST"
            assert req.url.path == "/v2/permissions/query/personal/grants"
            assert req.headers["Authorization"] == "Bearer alias-access"
            assert json.loads(req.content) == {}
            offset = len(offsets)
            assert dict(req.url.params) == {"pageOffset": str(offset), "pageSize": "100"}
            offsets.append(offset)
            return httpx.Response(200, json=pages[offset])

        async def async_respond(transport, req):
            return respond(transport, req)

        async def read_async():
            monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", async_respond)
            api = AsyncAuthenticatedClient(options, AsyncTokenManager("alias-access", "refresh"))
            async with AsyncKsef(api, options, context_type="Nip", context_value="demo") as sdk:
                return await sdk.permissions.list_personal_grants(**kwargs)

        try:
            if request.param == "async":
                return asyncio.run(read_async())
            monkeypatch.setattr(httpx.HTTPTransport, "handle_request", respond)
            api = AuthenticatedClient(options, TokenManager("alias-access", "refresh"))
            with Ksef(api, options, context_type="Nip", context_value="demo") as sdk:
                return sdk.permissions.list_personal_grants(**kwargs)
        finally:
            assert offsets == list(range(len(pages)))

    return read


def test_reads_all_grants_with_owner_scopes_and_states(read_pages):
    first = grant(1, targetIdentifier={"type": "Nip", "value": "1234567890"})
    second = grant(2, permissionState="Inactive", targetIdentifier={"type": "AllPartners"})
    third = grant(3, permissionScope="FutureScope", canDelegate=True)
    report = read_pages(
        [
            {"hasMore": True, "permissions": [first], "ownerPermissions": ["InvoiceRead"]},
            {"hasMore": True, "permissions": [second]},
            {
                "hasMore": False,
                "permissions": [third],
                "ownerPermissions": ["InvoiceRead", "FutureOwner"],
            },
        ],
        max_pages=3,
    )
    assert report.to_dict() == {
        "hasMore": False,
        "permissions": [first, second, third],
        "ownerPermissions": ["InvoiceRead", "FutureOwner"],
    }


@pytest.mark.parametrize(
    "extra, expected",
    [({}, None), ({"ownerPermissions": None}, None), ({"ownerPermissions": []}, [])],
)
def test_empty_response_preserves_owner_information(read_pages, extra, expected):
    report = read_pages([{"hasMore": False, "permissions": [], **extra}])
    assert report.permissions == []
    assert report.owner_permissions == expected


@pytest.mark.parametrize(
    "pages, max_pages, message",
    [
        ([{"hasMore": True, "permissions": []}], 5, "empty page"),
        ([{"hasMore": True, "permissions": [grant(1)]}], 1, "page limit"),
        (
            [
                {"hasMore": True, "permissions": [grant(1)]},
                {"hasMore": False, "permissions": [grant(1)]},
            ],
            2,
            "repeated",
        ),
        ([{"hasMore": False, "permissions": {}}], 5, "invalid"),
    ],
)
def test_incomplete_report_raises(read_pages, pages, max_pages, message):
    with pytest.raises(KsefPaginationError, match=message):
        read_pages(pages, max_pages=max_pages)


def test_rejects_invalid_limit_before_http(read_pages):
    with pytest.raises(ValueError):
        read_pages([], max_pages=0)


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"hasMore": "false", "permissions": []},
        {"hasMore": False},
        {"hasMore": False, "permissions": [], "ownerPermissions": "InvoiceRead"},
        {"hasMore": False, "permissions": [], "ownerPermissions": [""]},
        *(
            {"hasMore": False, "permissions": [item]}
            for item in (
                None,
                {},
                grant(1, permissionScope=None),
                grant(1, permissionState={}),
                grant(1, canDelegate="false"),
                grant(1, contextIdentifier="bad"),
                grant(1, authorizedIdentifier={"type": "Nip"}),
                grant(1, targetIdentifier={"value": "123"}),
                {k: v for k, v in grant(1).items() if k != "startDate"},
            )
        ),
    ],
)
def test_invalid_payload_is_never_reported_as_no_access(payload):
    with pytest.raises(KsefPaginationError, match="invalid personal permissions page"):
        _parse_personal_grants(payload)
