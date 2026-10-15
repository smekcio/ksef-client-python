"""Strażnik: liczby-limity w SDK/CLI muszą zgadzać się z kontraktem OpenAPI.

Rozjazdy w tej klasie są ciche: walidacja lokalna odrzuca wartości, które API
przyjmuje (albo odwrotnie), a użytkownik dowiaduje się o tym dopiero z błędu
serwera. Test czyta ``specs/ksef-openapi.snapshot.json`` i porównuje z nim
publiczne stałe oraz granice opcji CLI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.main import get_command

from ksef_client.cli import app as cli_app
from ksef_client.clients.invoices import INVOICE_QUERY_MAX_RANGE_DAYS
from ksef_client.utils import (
    MAX_BATCH_PART_SIZE_BYTES,
    MAX_IDENTIFIERS_PER_INVOICE,
    MAX_IDENTIFIERS_PER_INVOICES_QUERY,
    MAX_INVOICE_DESCRIPTION_LENGTH,
    MAX_INVOICES_PER_IDENTIFIER,
    MAX_QUERY_RANGE_DAYS,
    MIN_INVOICES_PER_IDENTIFIER,
    PAGE_SIZE_INVOICES_MAX,
    PAGE_SIZE_MAX,
    PAGE_SIZE_MIN,
)
from ksef_client.utils.zip_utils import MAX_BATCH_PARTS

REPO_ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_PATH = REPO_ROOT / "specs" / "ksef-openapi.snapshot.json"

with SNAPSHOT_PATH.open(encoding="utf-8") as handle:
    SPEC: dict[str, Any] = json.load(handle)

SCHEMAS = SPEC["components"]["schemas"]
PATHS = SPEC["paths"]


def _page_size_limits(path: str, method: str) -> tuple[int, int]:
    for entry in PATHS[path][method].get("parameters", []):
        if entry.get("name") == "pageSize":
            schema = entry["schema"]
            return schema["minimum"], schema["maximum"]
    raise AssertionError(f"brak parametru pageSize w {method.upper()} {path}")


def _cli_param(command_path: list[str], name: str) -> Any:
    command: Any = get_command(cli_app)
    for part in command_path:
        command = command.commands[part]
    return next(param for param in command.params if param.name == name)


def test_page_size_minimum_is_the_same_for_every_endpoint() -> None:
    limits = {
        (path, method): _page_size_limits(path, method)
        for path, operations in PATHS.items()
        for method in operations
        if method != "parameters" and isinstance(operations[method], dict)
        if any(
            entry.get("name") == "pageSize"
            for entry in operations[method].get("parameters", [])
        )
    }
    assert limits, "kontrakt nie deklaruje żadnego parametru pageSize"

    minimums = {minimum for minimum, _ in limits.values()}
    assert minimums == {PAGE_SIZE_MIN}, f"kontrakt ma inne minima pageSize: {minimums}"


@pytest.mark.parametrize(
    ("path", "method", "expected_max"),
    [
        ("/collective-identifiers/query", "post", PAGE_SIZE_MAX),
        ("/collective-identifiers/ksef/{ksefNumber}", "get", PAGE_SIZE_MAX),
        ("/collective-identifiers/invoices", "post", PAGE_SIZE_INVOICES_MAX),
    ],
)
def test_sdk_page_size_constants_match_the_contract(
    path: str, method: str, expected_max: int
) -> None:
    _, contract_max = _page_size_limits(path, method)
    assert contract_max == expected_max, (
        f"{method.upper()} {path}: kontrakt dopuszcza do {contract_max}, SDK używa {expected_max}"
    )


def test_cli_page_size_bounds_match_the_contract() -> None:
    """Opcje CLI mają przyjmować dokładnie zakres z kontraktu (inaczej blokują legalne wartości)."""
    cases = {
        ("invoice", "list"): ("/invoices/query/metadata", "post"),
        ("iz", "query"): ("/collective-identifiers/query", "post"),
        ("iz", "by-ksef"): ("/collective-identifiers/ksef/{ksefNumber}", "get"),
        ("iz", "invoices"): ("/collective-identifiers/invoices", "post"),
    }
    for command_path, (path, method) in cases.items():
        minimum, maximum = _page_size_limits(path, method)
        param = _cli_param(list(command_path), "page_size")
        command_name = " ".join(command_path)
        assert param.type.min == minimum, f"{command_name}: min {param.type.min} != {minimum}"
        assert param.type.max == maximum, (
            f"{command_name}: max {param.type.max} != {maximum} "
            f"(kontrakt {method.upper()} {path})"
        )


def test_collective_identifier_invoice_limits_match_the_contract() -> None:
    override = SCHEMAS["CollectiveIdentifierContextLimitsOverride"]["properties"]["maxInvoices"]
    assert (override["minimum"], override["maximum"]) == (
        MIN_INVOICES_PER_IDENTIFIER,
        MAX_INVOICES_PER_IDENTIFIER,
    )

    query_description = SCHEMAS["CollectiveIdentifierInvoicesQueryRequest"]["properties"][
        "collectiveIdentifierNumbers"
    ]["description"]
    assert str(MAX_IDENTIFIERS_PER_INVOICES_QUERY) in query_description, query_description

    per_invoice_description = SCHEMAS["CollectiveIdentifierInvoice"]["properties"]["ksefNumber"][
        "description"
    ]
    assert str(MAX_IDENTIFIERS_PER_INVOICE) in per_invoice_description, per_invoice_description

    description_field = SCHEMAS["CollectiveIdentifierInvoice"]["properties"]["description"]
    assert description_field["maxLength"] == MAX_INVOICE_DESCRIPTION_LENGTH


def test_batch_package_limits_match_the_contract() -> None:
    parts_description = SCHEMAS["BatchFileInfo"]["properties"]["fileParts"]["description"]
    assert str(MAX_BATCH_PARTS) in parts_description, parts_description
    assert "100MB" in parts_description, parts_description
    assert MAX_BATCH_PART_SIZE_BYTES == 100 * 1_000_000


def test_query_date_range_limit_matches_the_contract() -> None:
    """Zakres zapytania o faktury i o identyfikatory zbiorcze to 100 dni (kontrakt 2.9.0)."""
    invoices_range = SCHEMAS["InvoiceQueryFilters"]["properties"]["dateRange"]["description"]
    assert f"{MAX_QUERY_RANGE_DAYS} dni" in " ".join(invoices_range.split()), invoices_range

    identifiers_range = SCHEMAS["CollectiveIdentifiersQueryRequest"]["properties"][
        "dateCreatedFrom"
    ]["description"]
    assert f"{MAX_QUERY_RANGE_DAYS} dni" in " ".join(identifiers_range.split()), identifiers_range

    assert INVOICE_QUERY_MAX_RANGE_DAYS == MAX_QUERY_RANGE_DAYS
