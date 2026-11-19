import json
import re

import httpx
import pytest

from ksef_client.cli import app
from ksef_client.cli.auth.scope import login_scope, token_pair_digest
from ksef_client.cli.commands import _workflow
from ksef_client.cli.exit_codes import ExitCode


@pytest.fixture
def endpoint(monkeypatch):
    # Exercise the CLI's real profile binding, token transport and HTTP error mapping.
    tokens = ("sample-access", "sample-refresh")
    metadata = {
        "login_scope": login_scope("https://api-demo.ksef.mf.gov.pl", "Nip", "123"),
        "token_pair_digest": token_pair_digest(*tokens),
    }
    monkeypatch.delenv("KSEF_XADES_SELECTOR", raising=False)
    monkeypatch.setenv("COLUMNS", "130")
    monkeypatch.setattr(_workflow, "get_tokens", lambda _: tokens)
    monkeypatch.setattr(_workflow, "get_cached_metadata", lambda _: metadata)

    def serve(*responses):
        offsets: list[int] = []

        def respond(transport, request):
            assert request.method == "POST"
            assert request.url.host == "api-demo.ksef.mf.gov.pl"
            assert request.url.path == "/v2/permissions/query/personal/grants"
            assert request.headers["Authorization"] == "Bearer sample-access"
            assert json.loads(request.content) == {}
            assert dict(request.url.params) == {"pageOffset": str(len(offsets)), "pageSize": "100"}
            offsets.append(len(offsets))
            reply = responses[offsets[-1]]
            return httpx.Response(
                reply.status_code, headers=reply.headers, stream=httpx.ByteStream(reply.content)
            )

        monkeypatch.setattr(httpx.HTTPTransport, "handle_request", respond)
        return offsets

    return serve


def sample_grant():
    return {
        "id": "00000000-0000-0000-0000-000000000001",
        "permissionScope": "InvoiceRead",
        "permissionState": "Inactive",
        "canDelegate": False,
        "contextIdentifier": {"type": "Nip", "value": "1111111111"},
        "authorizedIdentifier": {"type": "Nip", "value": "2222222222"},
        "targetIdentifier": {"type": "AllPartners"},
        "description": "private description",
        "subjectPersonDetails": {
            "subjectDetailsType": "PersonByIdentifier",
            "firstName": "private name",
            "lastName": "private surname",
        },
        "startDate": "2026-01-01T00:00:00Z",
    }


@pytest.mark.parametrize("as_json", [False, True])
def test_prints_report_from_selected_profile(runner, endpoint, as_json):
    grant = sample_grant()
    offsets = endpoint(
        httpx.Response(
            200,
            json={"permissions": [grant], "ownerPermissions": ["InvoiceWrite"], "hasMore": True},
        ),
        httpx.Response(200, json={"permissions": [], "hasMore": False}),
    )
    args = ["--profile", "demo", *(["--json"] if as_json else []), "health", "permissions"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert offsets == [0, 1]
    for sensitive in ("private", "sample-access", "sample-refresh", "subjectPersonDetails"):
        assert sensitive not in result.output
    if as_json:
        payload = json.loads(result.output)
        assert payload["ok"] and payload["command"] == "health.permissions"
        assert payload["profile"] == "demo"
        assert payload["data"] == {
            "permissions": [
                {
                    k: v
                    for k, v in grant.items()
                    if k not in {"description", "subjectPersonDetails", "startDate"}
                }
            ],
            "ownerPermissions": ["InvoiceWrite"],
        }
    else:
        for term in (
            "InvoiceRead",
            "Inactive",
            "No",
            "Grantor",
            "1111111111",
            "Authorized",
            "2222222222",
            "AllPartners",
            "Owner permissions",
            "InvoiceWrite",
        ):
            assert term in result.output


@pytest.mark.parametrize(
    "extra, message",
    [({}, "not reported by KSeF"), ({"ownerPermissions": []}, "Owner permissions: none")],
)
def test_reports_empty_grants_and_owner_availability(runner, endpoint, extra, message):
    endpoint(httpx.Response(200, json={"permissions": [], "hasMore": False, **extra}))
    result = runner.invoke(app, ["health", "permissions"])
    assert result.exit_code == 0, result.output
    assert "Personal grants: none" in result.output
    assert message in result.output


def test_future_scope_is_literal_terminal_text(runner, endpoint):
    grant = {**sample_grant(), "permissionScope": "[red]New\x1bScope", "canDelegate": True}
    endpoint(httpx.Response(200, json={"permissions": [grant], "hasMore": False}))
    result = runner.invoke(app, ["--no-color", "health", "permissions"])
    assert result.exit_code == 0, result.output
    assert "[red]New?Scope" in result.output
    assert "Yes" in result.output
    assert "\x1b" not in result.output


def test_narrow_terminal_preserves_the_full_permission_code(runner, endpoint, monkeypatch):
    monkeypatch.setenv("COLUMNS", "60")
    scope = "CollectiveIdentifierManage"
    endpoint(
        httpx.Response(
            200,
            json={"permissions": [{**sample_grant(), "permissionScope": scope}], "hasMore": False},
        )
    )
    result = runner.invoke(app, ["health", "permissions"])
    assert result.exit_code == 0, result.output
    first_column = [
        re.split(r"[│|]", row)[1].strip()
        for row in result.output.splitlines()
        if row.startswith(("│", "|"))
    ]
    assert scope in "".join(first_column)
    assert "…" not in result.output


@pytest.mark.parametrize(
    "response, code",
    [
        (httpx.Response(403, json={"private": "message"}), ExitCode.AUTH_ERROR),
        (httpx.Response(429, headers={"Retry-After": "180"}, json={}), ExitCode.RETRY_EXHAUSTED),
        (httpx.Response(503, json={"private": "message"}), ExitCode.API_ERROR),
        (httpx.Response(200, json={"permissions": {}, "hasMore": False}), ExitCode.API_ERROR),
    ],
)
def test_second_page_error_returns_no_partial_report(runner, endpoint, response, code):
    offsets = endpoint(
        httpx.Response(200, json={"permissions": [sample_grant()], "hasMore": True}),
        response,
    )
    result = runner.invoke(app, ["--json", "health", "permissions"])
    assert result.exit_code == code, result.output
    assert offsets == [0, 1]
    payload = json.loads(result.output)
    assert not payload["ok"] and payload["data"] is None
    assert payload["errors"][0]["code"] == code.name
    if code == ExitCode.RETRY_EXHAUSTED:
        assert payload["errors"][0]["retry_after_seconds"] == 180
    for private in ("private", "InvoiceRead", "sample-access"):
        assert private not in result.output


def test_page_limit_is_actionable(runner, endpoint):
    calls = endpoint(httpx.Response(200, json={"permissions": [sample_grant()], "hasMore": True}))
    result = runner.invoke(app, ["--json", "health", "permissions", "--max-pages", "1"])
    assert calls == [0] and result.exit_code == ExitCode.API_ERROR
    assert "--max-pages" in result.output
    assert json.loads(result.output)["data"] is None


def test_requires_authentication_bound_to_current_context(runner, endpoint, monkeypatch):
    calls = endpoint()
    monkeypatch.setattr(
        _workflow, "get_cached_metadata", lambda _: {"login_scope": "a different context"}
    )
    result = runner.invoke(app, ["--json", "health", "permissions"])
    assert result.exit_code == ExitCode.AUTH_ERROR, result.output
    assert calls == []
    assert json.loads(result.output)["errors"][0]["code"] == "AUTH_ERROR"


def test_targeted_grant_without_a_target_value_returns_no_report(runner, endpoint):
    row = {**sample_grant(), "targetIdentifier": {"type": "Nip"}}
    endpoint(httpx.Response(200, json={"permissions": [row], "hasMore": False}))
    result = runner.invoke(app, ["--json", "health", "permissions"])
    assert result.exit_code == ExitCode.API_ERROR
    assert json.loads(result.output)["data"] is None
    assert row["id"] not in result.output


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("operation", ["send-online", "download-purchases"])
@pytest.mark.parametrize("source", ["personal", "owner", "missing", "unknown"])
def test_check_for_operation_returns_grant_evidence(runner, endpoint, operation, source, as_json):
    scope = "InvoiceWrite" if operation == "send-online" else "InvoiceRead"
    row = sample_grant()
    direct = {
        key: value
        for key, value in row.items()
        if key not in {"authorizedIdentifier", "targetIdentifier", "contextIdentifier"}
    }
    available = source in {"personal", "owner"}
    data = {
        "hasMore": False,
        "permissions": [dict(direct, permissionState="Active", permissionScope=scope)]
        if source == "personal"
        else [],
        "ownerPermissions": [scope] if source == "owner" else None if source == "unknown" else [],
    }
    calls = endpoint(httpx.Response(200, json=data))
    args = [*(["--json"] if as_json else []), "health", "permissions", "--for", operation]
    result = runner.invoke(app, args)
    assert result.exit_code == (0 if available else ExitCode.AUTH_ERROR), result.output
    assert calls == [0]
    expected = (
        "grant_found"
        if available
        else "grant_not_found"
        if source == "missing"
        else "indeterminate"
    )
    if as_json:
        payload = json.loads(result.output)
        assert payload["ok"] is available
        report = payload["data"]
        assert (report["status"], report["operation"], report["requiredScope"]) == (
            expected,
            operation,
            scope,
        )
        assert report["tokenScopeChecked"] is False
        assert report["grantId"] == (row["id"] if source == "personal" else None)
    else:
        assert expected in result.output and scope in result.output
        if source == "personal":
            assert row["id"] in result.output
    for secret in ("private", "sample-access", "1111111111", "subjectPersonDetails"):
        assert secret not in result.output


def test_permission_check_discards_earlier_evidence_on_later_failure(runner, endpoint):
    calls = endpoint(
        httpx.Response(
            200,
            json={
                "permissions": [sample_grant()],
                "ownerPermissions": ["InvoiceWrite"],
                "hasMore": True,
            },
        ),
        httpx.Response(403, json={}),
    )
    result = runner.invoke(app, ["--json", "health", "permissions", "--for", "send-online"])
    assert calls == [0, 1]
    assert result.exit_code == ExitCode.AUTH_ERROR
    assert json.loads(result.output)["data"] is None
    assert "grant_found" not in result.output
