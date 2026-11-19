import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, Mock

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
from ksef_client.clients import permissions
from ksef_client.exceptions import KsefPaginationError, KsefResponseLimitError
from ksef_client.http import HttpResponse
from ksef_client.models import PermissionState, PersonalPermissionsQueryRequest
from ksef_client.token_manager import TokenManagerError


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

    def read(pages, *, operation=None, context_type="Nip", transport_options=None, **kwargs):
        offsets: list[int] = []
        actual = transport_options or options

        def respond(transport, req):
            assert req.method == "POST"
            assert req.url.path == "/v2/permissions/query/personal/grants"
            assert req.headers["Authorization"] == "Bearer alias-access"
            assert json.loads(req.content) == {}
            offset = len(offsets)
            assert dict(req.url.params) == {"pageOffset": str(offset), "pageSize": "100"}
            offsets.append(offset)
            assert req.headers["Accept-Encoding"] == "identity"
            return httpx.Response(200, stream=httpx.ByteStream(json.dumps(pages[offset]).encode()))

        async def async_respond(transport, req):
            return respond(transport, req)

        async def read_async():
            monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", async_respond)
            api = AsyncAuthenticatedClient(actual, AsyncTokenManager("alias-access", "refresh"))
            async with AsyncKsef(
                api, options, context_type=context_type, context_value="1234567890"
            ) as sdk:
                if operation is not None:
                    return await sdk.permissions.check_operation(operation, **kwargs)
                return await sdk.permissions.list_personal_grants(**kwargs)

        try:
            if request.param == "async":
                return asyncio.run(read_async())
            monkeypatch.setattr(httpx.HTTPTransport, "handle_request", respond)
            api = AuthenticatedClient(actual, TokenManager("alias-access", "refresh"))
            with Ksef(api, options, context_type=context_type, context_value="1234567890") as sdk:
                if operation is not None:
                    return sdk.permissions.check_operation(operation, **kwargs)
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
            {
                "hasMore": True,
                "permissions": [first],
                "ownerPermissions": ["InvoiceRead", "FutureOwner"],
            },
            {"hasMore": True, "permissions": [second]},
            {
                "hasMore": False,
                "permissions": [third],
                "ownerPermissions": ["FutureOwner", "InvoiceRead", "InvoiceRead"],
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


@pytest.mark.parametrize("use_async", [False, True])
def test_operation_check_rejects_refresh_client_bound_to_another_transport(use_async, monkeypatch):
    options = KsefClientOptions("https://permissions.example")
    other = KsefClientOptions("https://other.example")
    expired = "2000-01-01T00:00:00Z"

    def unexpected_request(*args):
        pytest.fail("Unexpected HTTP request with a mismatched token refresh client")

    async def read_async():
        monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", unexpected_request)
        manager = AsyncTokenManager("access", "refresh", access_token_valid_until=expired)
        async with (
            AsyncAuthenticatedClient(options, manager) as api,
            AsyncAuthenticatedClient(other, manager),
        ):
            sdk = AsyncKsef(api, options, context_type="Nip", context_value="1234567890")
            await sdk.permissions.check_operation("download-purchases")

    with pytest.raises(TokenManagerError, match="authentication transport changed"):
        if use_async:
            asyncio.run(read_async())
        else:
            monkeypatch.setattr(httpx.HTTPTransport, "handle_request", unexpected_request)
            manager = TokenManager("access", "refresh", access_token_valid_until=expired)
            with AuthenticatedClient(options, manager) as api, AuthenticatedClient(other, manager):
                sdk = Ksef(api, options, context_type="Nip", context_value="1234567890")
                sdk.permissions.check_operation("download-purchases")


@pytest.mark.parametrize("last_scopes", [[], ["InvoiceWrite"]])
def test_changed_owner_permissions_do_not_produce_a_combined_snapshot(read_pages, last_scopes):
    with pytest.raises(KsefPaginationError, match="inconsistent owner permissions"):
        read_pages(
            [
                {"hasMore": True, "permissions": [grant(1)], "ownerPermissions": ["InvoiceRead"]},
                {"hasMore": False, "permissions": [grant(2)], "ownerPermissions": last_scopes},
            ]
        )


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
                grant(1, targetIdentifier={"type": "Nip"}),
                grant(1, targetIdentifier={"type": "InternalId", "value": None}),
                grant(1, targetIdentifier={"type": "Nip", "value": "incomplete"}),
                grant(1, targetIdentifier={"type": "AllPartners", "value": "1234567890"}),
                grant(1, id="short"),
                grant(1, description=None),
                grant(1, startDate=[]),
                grant(1, subjectPersonDetails=[]),
                grant(
                    1,
                    subjectPersonDetails={
                        "subjectDetailsType": "PersonByIdentifier",
                        "firstName": "Anna",
                        "lastName": "Nowak",
                        "birthDate": 7,
                    },
                ),
                grant(
                    1,
                    subjectPersonDetails={
                        "subjectDetailsType": "PersonByIdentifier",
                        "firstName": "Anna",
                        "lastName": "Nowak",
                        "personIdentifier": [],
                    },
                ),
                grant(1, subjectEntityDetails="invalid"),
                {k: v for k, v in grant(1).items() if k != "startDate"},
            )
        ),
    ],
)
def test_invalid_payload_is_never_reported_as_no_access(payload):
    with pytest.raises(KsefPaginationError, match="invalid personal permissions page"):
        permissions._parse_personal_grants(json.dumps(payload).encode(), 100)


def test_response_respects_transport_byte_budget(read_pages, monkeypatch):
    monkeypatch.setattr(permissions, "_PERSONAL_PAGE_BYTES", 32)
    with pytest.raises(KsefResponseLimitError):
        read_pages([{"hasMore": False, "permissions": [grant(1)]}])


def test_page_cannot_exceed_requested_or_default_number_of_grants():
    page = json.dumps({"hasMore": False, "permissions": [grant(n) for n in range(11)]}).encode()
    for page_size in (None, 10):
        with pytest.raises(KsefPaginationError):
            permissions._parse_personal_grants(page, page_size)
    assert len(permissions._parse_personal_grants(page, 11).permissions) == 11
    with pytest.raises(ValueError):
        permissions._personal_page_params(0, 101)


@pytest.mark.parametrize("use_async", [False, True])
def test_filtered_page_preserves_personal_details_and_explicit_credentials(use_async):
    original = grant(
        1,
        contextIdentifier={"type": "InternalId", "value": "1234567890-12345"},
        authorizedIdentifier={"type": "Fingerprint", "value": "a" * 64},
        subjectEntityDetails={"subjectDetailsType": "EntityByIdentifier", "fullName": "Example"},
    )
    person = grant(
        2,
        subjectPersonDetails={
            "subjectDetailsType": "PersonByFingerprintWithIdentifier",
            "firstName": "Anna",
            "lastName": "Nowak",
            "personIdentifier": {"type": "Nip", "value": "1234567890"},
        },
    )
    raw = {"permissions": [original, person], "hasMore": False}
    http = Mock()
    response = HttpResponse(
        status_code=200, headers=httpx.Headers(), content=json.dumps(raw).encode()
    )
    filters = PersonalPermissionsQueryRequest(permission_state=PermissionState.ACTIVE)
    if use_async:
        http.request = AsyncMock(return_value=response)
        result = asyncio.run(
            permissions.AsyncPermissionsClient(http).query_personal_grants(
                filters, page_offset=2, access_token="test-token"
            )
        )
    else:
        http.request.return_value = response
        result = permissions.PermissionsClient(http).query_personal_grants(
            filters, page_offset=2, access_token="test-token"
        )
    sent = http.request.call_args.kwargs
    assert (sent["params"], sent["json"], sent["access_token"]) == (
        {"pageOffset": 2},
        {"permissionState": "Active"},
        "test-token",
    )
    assert result.to_dict() == raw


_CURRENT = {"type": "Nip", "value": "1234567890"}
_OTHER = {"type": "Nip", "value": "9999999999"}


@pytest.mark.parametrize("field", ["contextIdentifier", "targetIdentifier"])
def test_direct_facade_accepts_login_context_spelling(read_pages, field):
    page = {"permissions": [grant(1, **{field: _CURRENT})], "hasMore": False}
    check = read_pages([page], operation="download-purchases", context_type=" nip ")
    assert check.status == "grant_found"


@pytest.mark.parametrize(
    "overrides,owners,status,reason",
    [
        ({}, [], "grant_found", "personal_grant"),
        ({"contextIdentifier": _CURRENT}, None, "grant_found", "personal_grant"),
        (
            {"targetIdentifier": _CURRENT, "contextIdentifier": _OTHER},
            [],
            "grant_found",
            "personal_grant",
        ),
        ({"targetIdentifier": _OTHER}, [], "grant_not_found", "no_applicable_grant"),
        (
            {"targetIdentifier": {"type": "InternalId", "value": "1234567890-00001"}},
            [],
            "indeterminate",
            "scope_uncertain",
        ),
        (
            {"permissionState": "Inactive", "canDelegate": True},
            [],
            "grant_not_found",
            "no_applicable_grant",
        ),
        ({"permissionState": "FutureState"}, [], "indeterminate", "scope_uncertain"),
        (
            {"permissionScope": "CredentialsManage"},
            ["InvoiceWrite"],
            "grant_not_found",
            "no_applicable_grant",
        ),
        (
            {"permissionScope": "EnforcementOperations"},
            None,
            "indeterminate",
            "owner_scopes_unreported",
        ),
        ({"targetIdentifier": {"type": "AllPartners"}}, [], "indeterminate", "scope_uncertain"),
        (
            {"targetIdentifier": {"type": "FutureTarget", "value": "1234567890"}},
            [],
            "indeterminate",
            "scope_uncertain",
        ),
        ({"contextIdentifier": _OTHER}, [], "indeterminate", "scope_uncertain"),
        ({"authorizedIdentifier": _CURRENT}, [], "indeterminate", "scope_uncertain"),
        ({"permissionState": "Inactive"}, ["InvoiceRead"], "grant_found", "owner_grant"),
    ],
)
def test_purchase_scope_check_uses_login_context_and_complete_grants(
    read_pages, overrides, owners, status, reason
):
    item = grant(1, **overrides)
    page = {"permissions": [item], "ownerPermissions": owners, "hasMore": False}
    report = read_pages([page], operation="download-purchases")
    assert (report.status, report.reason, report.required_scope) == (status, reason, "InvoiceRead")
    assert report.grant_id == (item["id"] if reason == "personal_grant" else None)


@pytest.mark.parametrize(
    "owners,personal",
    [(["EnforcementOperations"], []), ([], [grant(1, permissionScope="PefInvoiceWrite")])],
)
def test_special_online_scopes_do_not_confirm_an_ordinary_sale(read_pages, owners, personal):
    report = read_pages(
        [{"permissions": personal, "ownerPermissions": owners, "hasMore": False}],
        operation="send-online",
    )
    assert (report.status, report.reason) == ("indeterminate", "specialised_scope")


def test_matching_grant_on_later_page_takes_precedence_over_uncertain_evidence(read_pages):
    matching = grant(2, permissionScope="InvoiceWrite")
    pages = [
        {
            "permissions": [grant(1, permissionScope="InvoiceWrite", authorizedIdentifier=_OTHER)],
            "hasMore": True,
        },
        {"permissions": [matching], "hasMore": False},
    ]
    result = read_pages(pages, operation="send-online", max_pages=2)
    assert result.to_dict()["grantId"] == matching["id"]
    assert result.required_scope == "InvoiceWrite"


def test_operation_check_rejects_unknown_operation_before_http(read_pages):
    with pytest.raises(ValueError, match="InvoicePermissionOperation"):
        read_pages([], operation="typo")


@pytest.mark.parametrize(
    "options",
    [
        KsefClientOptions("https://other-environment.example"),
        KsefClientOptions("https://permissions.example", custom_headers={"aUtHoRiZaTiOn": "test"}),
        KsefClientOptions("https://permissions.example", custom_headers={"Host": "other.example"}),
    ],
)
def test_operation_check_rejects_mismatched_identity_before_http(read_pages, options):
    with pytest.raises(ValueError, match="Permission evidence requires"):
        read_pages([], operation="send-online", transport_options=options)
