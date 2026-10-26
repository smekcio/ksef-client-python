from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ksef_client.rate_limit_routing import (
    canonical_rate_limit_environment,
    classify_rate_limit_groups,
)

BASE = "https://api-test.ksef.mf.gov.pl/v2"
GROUPS = {
    "anonymous": "anonymous",
    "batchSession": "batch_session",
    "batchSessionClose": "batch_session_close",
    "collectiveIdentifier": "collective_identifier",
    "invoiceDownload": "invoice_download",
    "invoiceExport": "invoice_export",
    "invoiceExportStatus": "invoice_export_status",
    "invoiceMetadata": "invoice_metadata",
    "invoiceSend": "invoice_send",
    "invoiceStatus": "invoice_status",
    "onlineSession": "online_session",
    "onlineSessionClose": "online_session_close",
    "sessionInvoiceList": "session_invoice_list",
    "sessionList": "session_list",
    "sessionMisc": "session_misc",
}


def _snapshot_routes():
    source = Path(__file__).resolve().parents[1] / "specs/ksef-openapi.snapshot.json"
    spec = json.loads(source.read_text(encoding="utf-8"))
    routes = []
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if method not in {"get", "post", "put", "delete", "patch"}:
                continue
            description = operation["responses"]["429"]["description"]
            match = re.search(
                r"\*\*Limity liczby żądań\*\*\s*\|[^\n]*\|\s*([A-Za-z][A-Za-z0-9]*|-)\s*$",
                description,
                re.M,
            )
            assert match is not None, (method, path)
            group = "anonymous" if match[1] == "-" else match[1]
            routes.append((method.upper(), path, group))
    return routes


@pytest.mark.parametrize("method,template,group", _snapshot_routes())
def test_every_snapshot_operation_uses_its_declared_group(method, template, group):
    concrete = re.sub(r"\{[^}]+\}", "DUMMY_REFERENCE", template)
    expected = f"other:{method} {template}" if group == "other" else GROUPS[group]
    result = classify_rate_limit_groups(method, concrete, BASE)
    assert result == ("global", expected)
    assert "DUMMY_REFERENCE" not in str(result)


def test_snapshot_operation_count_guards_accidental_table_omissions():
    from ksef_client.rate_limit_routing import _ROUTE_GROUPS

    assert len(_snapshot_routes()) == len(_ROUTE_GROUPS) == 83


@pytest.mark.parametrize(
    "path",
    [
        "/invoices/query/metadata",
        "invoices/query/metadata?sortOrder=Asc#DUMMY_FRAGMENT",
        "/v2/invoices/query/metadata",
        "/api/v2/invoices/query/metadata",
        BASE + "/invoices/query/metadata?DUMMY_SECRET",
        "https://API-TEST.KSEF.MF.GOV.PL.:443/v2/invoices/query/metadata",
        "/%69nvoices/query/metadata",
        "/invoices//query/metadata/",
        "/unused/../invoices/query/metadata",
        "/Invoices/Query/Metadata",
        "https://api-test.ksef.mf.gov.pl/V2/INVOICES/query/metadata",
    ],
)
def test_api_path_spellings_share_one_budget(path):
    assert classify_rate_limit_groups(" post ", path, BASE) == ("global", "invoice_metadata")


@pytest.mark.parametrize(
    "path",
    [
        "https://storage.example.invalid/invoice?sig=DUMMY_SECRET",
        "https://api-latarnia-test.ksef.mf.gov.pl/status",
        "https://api-test.ksef.mf.gov.pl.evil.invalid/v2/invoices/query/metadata",
        "https://api-test.ksef.mf.gov.pl/v2-other/invoices/query/metadata",
        "https://api-test.ksef.mf.gov.pl/not-api/invoices/query/metadata",
        "https://api-test.ksef.mf.gov.pl:8443/v2/invoices/query/metadata",
        "http://api-test.ksef.mf.gov.pl/v2/invoices/query/metadata",
        "https://api-test.ksef.mf.gov.pl@evil.invalid/v2/invoices/query/metadata",
    ],
)
@pytest.mark.parametrize("skip_auth", [False, True])
def test_external_traffic_never_consumes_api_quota(path, skip_auth):
    assert classify_rate_limit_groups("POST", path, BASE, skip_auth=skip_auth) is None


@pytest.mark.parametrize("skip_auth", [False, True])
def test_public_relative_routes_remain_limited_with_skip_auth(skip_auth):
    assert classify_rate_limit_groups("POST", "/auth/challenge", BASE, skip_auth=skip_auth) == (
        "global",
        "anonymous",
    )
    assert classify_rate_limit_groups(
        "GET", "/security/public-key-certificates", BASE, skip_auth=skip_auth
    ) == ("global", "anonymous")


def test_auth_bootstrap_does_not_take_token_or_context_group():
    for method, path in [
        ("GET", "/auth/DUMMY_REFERENCE"),
        ("POST", "/auth/token/redeem"),
        ("POST", "/auth/token/refresh"),
    ]:
        assert classify_rate_limit_groups(method, path, BASE) == ("global", "anonymous")


def test_static_routes_win_over_parameterized_routes():
    assert classify_rate_limit_groups("GET", "/sessions/ref/invoices/failed", BASE) == (
        "global",
        "session_invoice_list",
    )
    assert classify_rate_limit_groups("GET", "/sessions/ref/invoices/invoice", BASE) == (
        "global",
        "invoice_status",
    )
    assert classify_rate_limit_groups("DELETE", "/auth/sessions/current", BASE) == (
        "global",
        "other:DELETE /auth/sessions/current",
    )


def test_other_counters_use_bounded_templates_not_reference_numbers():
    a = classify_rate_limit_groups("GET", "/tokens/DUMMY_ONE", BASE)
    b = classify_rate_limit_groups("GET", "/tokens/DUMMY_TWO?token=DUMMY_SECRET", BASE)
    assert a == b == ("global", "other:GET /tokens/{referenceNumber}")
    assert a != classify_rate_limit_groups("DELETE", "/tokens/DUMMY_ONE", BASE)
    assert a != classify_rate_limit_groups("GET", "/rate-limits", BASE)


@pytest.mark.parametrize(
    "path", ["/future/DUMMY_ONE", "/future/DUMMY_TWO", "/invoices/query/metadata-more"]
)
def test_unknown_api_resources_share_one_conservative_bucket(path):
    assert classify_rate_limit_groups("GET", path, BASE) == ("global", "other")


def test_custom_api_prefix_and_root_configuration():
    assert classify_rate_limit_groups("POST", "/invoices/query/metadata", BASE[:-3]) == (
        "global",
        "invoice_metadata",
    )
    custom = "https://gateway.example.invalid/service/api/v2"
    assert classify_rate_limit_groups("POST", custom + "/invoices/query/metadata", custom) == (
        "global",
        "invoice_metadata",
    )
    assert (
        classify_rate_limit_groups("POST", custom + "-other/invoices/query/metadata", custom)
        is None
    )
    assert classify_rate_limit_groups("GET", custom, custom) == ("global", "other")
    assert classify_rate_limit_groups("GET", "/v2", BASE) == ("global", "other")


def test_userinfo_never_appears_in_group_keys():
    assert classify_rate_limit_groups(
        "GET", "https://DUMMY_USER:DUMMY_PASSWORD@api-test.ksef.mf.gov.pl/v2/tokens/ref", BASE
    ) == ("global", "other:GET /tokens/{referenceNumber}")


@pytest.mark.parametrize("base", ["", "ftp://example.invalid", "https://example.invalid:bad"])
def test_invalid_origins_fail_with_safe_errors(base):
    with pytest.raises(ValueError, match="rate limit classification") as caught:
        classify_rate_limit_groups("GET", "/tokens/ref", base)
    assert base not in str(caught.value) if base else True


def test_invalid_request_port_and_encoding_have_safe_errors():
    with pytest.raises(ValueError, match="rate limit classification"):
        classify_rate_limit_groups("GET", "https://api-test.ksef.mf.gov.pl:bad/v2/tokens/ref", BASE)
    with pytest.raises(ValueError, match="path encoding"):
        classify_rate_limit_groups("GET", "/tokens/%FF", BASE)


@pytest.mark.parametrize(
    "url",
    [
        BASE,
        "https://API-TEST.KSEF.MF.GOV.PL.:443/api/v2",
        "https://DUMMY_USER:DUMMY_SECRET@api-test.ksef.mf.gov.pl/proxy/v2?sig=DUMMY_SIG#fragment",
        "https://api-test.ksef.mf.gov.pl",
    ],
)
def test_environment_aliases_cannot_create_separate_global_quota(url):
    assert canonical_rate_limit_environment(url) == "https://api-test.ksef.mf.gov.pl:443"


def test_environment_origin_normalizes_idna_and_ipv6():
    assert canonical_rate_limit_environment("https://żółć.example.invalid/v2") == (
        canonical_rate_limit_environment("https://xn--kda4b0koi.example.invalid/api/v2")
    )
    assert canonical_rate_limit_environment("http://[::1]:8080/v2") == "http://[::1]:8080"
