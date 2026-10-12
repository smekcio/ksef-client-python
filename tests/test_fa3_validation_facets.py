"""Walidacja XML FA(3) wobec ograniczeń schematu.

Dwa poziomy testów:

1. **Spójność tabeli ze schematem** — parser XSD wyciąga faktyczne ograniczenia
   i porównuje je z tabelą `ELEMENT_FACETS`. Dzięki temu tabela nie może po cichu
   rozjechać się z kontraktem (test jest jedynym miejscem, w którym wolno
   „tłumaczyć" schemat na kod).
2. **Zachowanie silnika** — walidacja wykrywa naruszenia długości, precyzji,
   słowników, wzorców, liczności i braków elementów wymaganych.
"""

from __future__ import annotations

import re
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from ksef_client.documents.fa3 import (
    BasicInvoiceBuilder,
    InvoiceParty,
    TaxCategory,
)
from ksef_client.documents.fa3.validation import (
    ELEMENT_FACETS,
    Facet,
    FacetKind,
    validate_xml_facets,
)
from ksef_client.documents.fa3.xml import FA3XmlValidationError, _q

SCHEMAS = Path(__file__).resolve().parents[1] / "src/ksef_client/documents/fa3/schemas"
XSD_FILES = (
    "schemat_FA(3)_v1-0E.xsd",
    "StrukturyDanych_v10-0E.xsd",
    "ElementarneTypyDanych_v10-0E.xsd",
    "KodyKrajow_v10-0E.xsd",
)

_XSD = "{http://www.w3.org/2001/XMLSchema}"


# ---------------------------------------------------------------------------
# 1. Spójność tabeli ograniczeń ze schematem
# ---------------------------------------------------------------------------


def _xsd_simple_types() -> dict[str, ET.Element]:
    """Wszystkie `xsd:simpleType` z kompletu schematów, po nazwie."""
    found: dict[str, ET.Element] = {}
    for name in XSD_FILES:
        root = ET.parse(SCHEMAS / name).getroot()
        for node in root.iter(f"{_XSD}simpleType"):
            type_name = node.get("name")
            if type_name:
                found.setdefault(type_name, node)
    return found


def _xsd_restriction_facets(node: ET.Element) -> dict[str, Any]:
    """Wartości `xsd:maxLength`/`fractionDigits`/`enumeration` danego typu."""
    restriction = node.find(f"{_XSD}restriction")
    if restriction is None:
        return {}
    facets: dict[str, Any] = {
        "base": restriction.get("base"),
        "maxLength": None,
        "minLength": None,
        "fractionDigits": None,
        "enumerations": frozenset(),
        "pattern": None,
        "minInclusive": None,
        "maxInclusive": None,
    }
    for child in restriction:
        tag = child.tag.replace(_XSD, "")
        if tag in {"maxLength", "minLength", "fractionDigits", "minInclusive", "maxInclusive"}:
            facets[tag] = child.get("value")
        elif tag == "pattern":
            facets["pattern"] = child.get("value")
        elif tag == "enumeration":
            facets["enumerations"] = facets["enumerations"] | {child.get("value")}
    return facets


def _resolve(type_name: str, types: dict[str, ET.Element], seen: set[str] | None = None):
    """Idzie po łańcuchu `base` aż do typu z ograniczeniami; scala napotkane facety."""
    seen = seen or set()
    if type_name in seen or type_name not in types:
        return {}
    seen.add(type_name)
    facets = _xsd_restriction_facets(types[type_name])
    base = facets.get("base")
    if base and base not in {
        "xsd:string",
        "xsd:token",
        "xsd:decimal",
        "xsd:integer",
        "xsd:byte",
        "xsd:normalizedString",
        "xsd:dateTime",
        "xsd:date",
    }:
        inherited = _resolve(base, types, seen)
        for key, value in inherited.items():
            if facets.get(key) in (None, frozenset()):
                facets[key] = value
    return facets


@pytest.fixture(scope="module")
def xsd_types() -> dict[str, ET.Element]:
    return _xsd_simple_types()


def test_every_facet_type_exists_in_the_schema(xsd_types: dict[str, ET.Element]) -> None:
    """Każdy `xsd_type` użyty w tabeli musi istnieć w schemacie."""
    unknown = sorted(
        {
            entry.facet.xsd_type
            for entry in ELEMENT_FACETS.values()
            if entry.facet.xsd_type is not None and entry.facet.xsd_type not in xsd_types
        }
    )
    assert not unknown, f"typy spoza schematu: {unknown}"


def test_declared_enumerations_match_the_schema(xsd_types: dict[str, ET.Element]) -> None:
    """Słowniki wartości muszą być identyczne z `xsd:enumeration` schematu."""
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        declared = entry.facet.allowed
        if declared is None:
            continue
        if entry.facet.xsd_type is None:
            continue
        schema_enums = _resolve(entry.facet.xsd_type, xsd_types).get("enumerations") or frozenset()
        if not schema_enums:
            continue
        checked += 1
        if declared != schema_enums:
            mismatches.append(
                f"{element} ({entry.facet.xsd_type}): tabela={sorted(declared)} "
                f"schemat={sorted(schema_enums)}"
            )
    assert checked >= 10, "test nie sprawdził żadnego słownika — sprawdź mapowanie typów"
    assert not mismatches, "\n".join(mismatches)


def test_declared_max_length_matches_the_schema(xsd_types: dict[str, ET.Element]) -> None:
    """`max_length` w tabeli musi zgadzać się z `xsd:maxLength` schematu."""
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        facet = entry.facet
        if facet.kind is not FacetKind.STRING or facet.max_length is None:
            continue
        if facet.xsd_type is None:
            # Ograniczenie inline w schemacie (bez nazwanego typu) — pomijamy
            # w porownaniu z nazwanymi typami, zachowanie pilnuje test silnika.
            continue
        schema_facets = _resolve(facet.xsd_type, xsd_types)
        schema_max = schema_facets.get("maxLength")
        if schema_max is None:
            continue
        checked += 1
        if int(schema_max) != facet.max_length:
            mismatches.append(
                f"{element} ({facet.xsd_type}): tabela={facet.max_length} schemat={schema_max}"
            )
    assert checked >= 10, "test nie sprawdził żadnego limitu długości"
    assert not mismatches, "\n".join(mismatches)


def test_declared_decimals_match_the_schema(xsd_types: dict[str, ET.Element]) -> None:
    """`decimals` w tabeli musi zgadzać się z `xsd:fractionDigits` schematu."""
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        facet = entry.facet
        if facet.decimals is None or facet.xsd_type is None:
            continue
        schema_facets = _resolve(facet.xsd_type, xsd_types)
        schema_fraction = schema_facets.get("fractionDigits")
        if schema_fraction is None:
            continue
        checked += 1
        if int(schema_fraction) != facet.decimals:
            mismatches.append(
                f"{element} ({facet.xsd_type}): tabela={facet.decimals} schemat={schema_fraction}"
            )
    assert checked >= 3, "test nie sprawdził żadnej precyzji"
    assert not mismatches, "\n".join(mismatches)


def test_declared_patterns_accept_schema_valid_samples(xsd_types: dict[str, ET.Element]) -> None:
    """Wzorce w tabeli muszą przepuszczać wartości zgodne ze wzorcem schematu."""
    samples = {
        "NIP": "1111111111",
        "IDWew": "1111111111-00001",
        "NrVatUE": "DE123456",
        "SWIFT": "DEUTDEFF",
        "KRS": "0000111111",
        "REGON": "123456789",
        "IPKSeF": "123abc456DEFG",
        "NrKSeFFaKorygowanej": "1111111111-20260101-AAAAAA-BBBBBB-01",
    }
    for element, sample in samples.items():
        entry = ELEMENT_FACETS[element]
        assert entry.pattern is not None, element
        assert entry.pattern.fullmatch(sample), f"{element}: {sample!r} odrzucone"


def test_ksef_number_pattern_accepts_both_schema_lengths() -> None:
    """Schemat dopuszcza 35 i 36 znaków numeru KSeF (myślnik jest opcjonalny)."""
    entry = ELEMENT_FACETS["NrKSeFFaKorygowanej"]
    assert entry.facet.lengths == frozenset({35, 36})
    for value in (
        "1111111111-20260101-AAAAAA-BBBBBB-01",
        "1111111111-20260101-AAAAAABBBBBB-01",
        "9999999999-20260401-D5FB0C9ED490-9A",
    ):
        assert entry.pattern is not None and entry.pattern.fullmatch(value), value
        assert len(value) in entry.facet.lengths


# ---------------------------------------------------------------------------
# 2. Zachowanie silnika
# ---------------------------------------------------------------------------


def _invoice_xml(**line_kwargs: Any) -> str:
    builder = BasicInvoiceBuilder(invoice_number="FV/FACETS")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2"))
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100", **line_kwargs)
    return builder.build().to_xml().decode("utf-8")


def _tree(**line_kwargs: Any) -> ET.Element:
    return ET.fromstring(_invoice_xml(**line_kwargs))


def test_valid_invoice_has_no_facet_issues() -> None:
    assert validate_xml_facets(_tree()) == []


def test_unknown_vat_rate_is_reported() -> None:
    """Silnik sprawdza słownik `P_12` niezależnie od walidacji biznesowej."""
    root = _tree()
    row = root.find(f".//{_q('FaWiersz')}")
    assert row is not None
    rate = row.find(_q("P_12"))
    assert rate is not None
    rate.text = "17"
    issues = validate_xml_facets(root)
    assert any(issue.element == "P_12" and "słownika" in issue.message for issue in issues)


def test_text_length_overflow_is_reported() -> None:
    root = _tree()
    description = root.find(f".//{_q('P_7')}")
    assert description is not None
    description.text = "x" * 513
    issues = validate_xml_facets(root)
    assert any("513" in issue.message and "P_7" in issue.path for issue in issues)


def test_decimal_precision_overflow_is_reported() -> None:
    """`P_9A` dopuszcza 8 miejsc; 9 musi zostać zgłoszone."""
    root = _tree()
    price = root.find(f".//{_q('P_9A')}")
    assert price is not None
    price.text = "1.123456789"
    issues = validate_xml_facets(root)
    assert any("miejsc po przecinku" in issue.message for issue in issues)


def test_non_numeric_value_is_reported() -> None:
    root = _tree()
    amount = root.find(f".//{_q('P_11')}")
    assert amount is not None
    amount.text = "nie-liczba"
    issues = validate_xml_facets(root)
    assert any("nie jest poprawną liczbą" in issue.message for issue in issues)


def test_out_of_range_percentage_is_reported() -> None:
    root = _tree()
    share_holder = ET.SubElement(ET.SubElement(root, _q("Podmiot3")), _q("Udzial"))
    share_holder.text = "150"
    issues = validate_xml_facets(root)
    assert any("przekracza maksimum 100" in issue.message for issue in issues)


def test_too_many_occurrences_are_reported() -> None:
    """`FaWiersz` ma limit 10 000 — silnik liczy rodzeństwo."""
    root = _tree()
    fa = root.find(_q("Fa"))
    assert fa is not None
    row = fa.find(_q("FaWiersz"))
    assert row is not None
    for _ in range(3):
        fa.append(ET.fromstring(ET.tostring(row)))
    # Zmniejszamy limit w locie, żeby nie budować 10 001 wierszy.
    from ksef_client.documents.fa3.validation import engine as engine_module

    original = engine_module.occurrence_limit
    engine_module.occurrence_limit = lambda parent, child: (
        2 if child == "FaWiersz" else original(parent, child)
    )
    try:
        issues = validate_xml_facets(root)
    finally:
        engine_module.occurrence_limit = original
    assert any("dopuszcza maksymalnie 2" in issue.message for issue in issues)


def test_missing_required_element_is_reported() -> None:
    """Brak `P_15` w `Fa` musi być zgłoszony."""
    root = _tree()
    fa = root.find(_q("Fa"))
    assert fa is not None
    total = fa.find(_q("P_15"))
    assert total is not None
    fa.remove(total)
    issues = validate_xml_facets(root)
    assert any(
        issue.element == "P_15" and "brak wymaganego elementu" in issue.message for issue in issues
    )


def test_pattern_violation_is_reported() -> None:
    root = _tree()
    nip = root.find(f".//{_q('NIP')}")
    assert nip is not None
    nip.text = "123"
    issues = validate_xml_facets(root)
    assert any("nie pasuje do formatu" in issue.message for issue in issues)


def test_invalid_date_is_reported() -> None:
    root = _tree()
    issue_date = root.find(f".//{_q('P_1')}")
    assert issue_date is not None
    issue_date.text = "nie-data"
    issues = validate_xml_facets(root)
    assert any("nie jest poprawną datą" in issue.message for issue in issues)


def test_date_before_schema_minimum_is_reported() -> None:
    """`TData` ma dolną granicę 2016-07-01 (schemat: minInclusive)."""
    root = _tree()
    issue_date = root.find(f".//{_q('P_1')}")
    assert issue_date is not None
    issue_date.text = "2010-01-01"
    issues = validate_xml_facets(root)
    assert any("wcześniejsza niż minimum" in issue.message for issue in issues)


def test_date_after_schema_maximum_is_reported() -> None:
    root = _tree()
    issue_date = root.find(f".//{_q('P_1')}")
    assert issue_date is not None
    issue_date.text = "2099-01-01"
    issues = validate_xml_facets(root)
    assert any("późniejsza niż maksimum" in issue.message for issue in issues)


def test_datetime_without_timezone_is_accepted() -> None:
    """`xsd:dateTime` dopuszcza brak strefy — nie może to być błąd."""
    from ksef_client.documents.fa3.validation.engine import _check_date_range
    from ksef_client.documents.fa3.validation.facets import DATA_CZAS

    assert _check_date_range("2026-04-01T08:30:00", DATA_CZAS, "path", "El") == []
    assert _check_date_range("2026-04-01T08:30:00Z", DATA_CZAS, "path", "El") == []


def test_datetime_before_schema_minimum_is_reported() -> None:
    from ksef_client.documents.fa3.validation.engine import _check_date_range
    from ksef_client.documents.fa3.validation.facets import DATA_CZAS

    issues = _check_date_range("2020-01-01T00:00:00Z", DATA_CZAS, "path", "El")
    assert issues and "wcześniejsza niż minimum" in issues[0].message


def test_integer_facet_rejects_fractional_value() -> None:
    from ksef_client.documents.fa3.validation.engine import _check_text
    from ksef_client.documents.fa3.validation.facets import NATURALNY

    issues = _check_text("1.5", NATURALNY, "path", "NrWierszaFa")
    assert any("liczbą całkowitą" in issue.message for issue in issues)


def test_integer_facet_rejects_value_below_minimum() -> None:
    from ksef_client.documents.fa3.validation.engine import _check_text
    from ksef_client.documents.fa3.validation.facets import NATURALNY

    issues = _check_text("0", NATURALNY, "path", "NrWierszaFa")
    assert any("mniejsza od minimum" in issue.message for issue in issues)


def test_facet_describe_covers_all_kinds() -> None:
    """`describe()` musi dawać czytelny opis dla każdego wariantu ograniczenia."""
    assert "dozwolone wartości" in Facet(FacetKind.STRING, "X", allowed=frozenset({"1"})).describe()
    assert "długość 35, 36" in Facet(FacetKind.STRING, "X", lengths=frozenset({35, 36})).describe()
    assert (
        "długość 1-10" in Facet(FacetKind.STRING, "X", max_length=10, minimum_length=1).describe()
    )
    assert "maksymalnie 5 znaków" in Facet(FacetKind.STRING, "X", max_length=5).describe()
    assert "co najmniej 3 znaków" in Facet(FacetKind.STRING, "X", minimum_length=3).describe()
    assert "2 miejsc po przecinku" in Facet(FacetKind.DECIMAL, "X", decimals=2).describe()
    assert (
        "zakres 0-100"
        in Facet(FacetKind.DECIMAL, "X", minimum=Decimal("0"), maximum=Decimal("100")).describe()
    )
    assert "minimum 1" in Facet(FacetKind.INTEGER, "X", minimum=Decimal("1")).describe()
    assert "maksimum 7" in Facet(FacetKind.INTEGER, "X", maximum=Decimal("7")).describe()
    assert (
        "zakres dat"
        in Facet(
            FacetKind.STRING, "X", minimum_date="2016-07-01", maximum_date="2050-01-01"
        ).describe()
    )
    assert "typ X" in Facet(FacetKind.STRING, "X").describe()


def test_facet_issue_str_includes_path() -> None:
    from ksef_client.documents.fa3.validation import FacetIssue

    issue = FacetIssue("Fa/FaWiersz/P_7", "P_7", "za długie")
    assert str(issue) == "Fa/FaWiersz/P_7: za długie"


def test_engine_ignores_non_fa3_namespaced_elements() -> None:
    """Elementy spoza przestrzeni nazw FA(3) nie są walidowane."""
    root = _tree()
    foreign = ET.SubElement(root, "{http://example.com/other}Cos")
    foreign.text = "x" * 5000
    assert validate_xml_facets(root) == []


def test_facet_for_returns_none_for_unknown_element() -> None:
    from ksef_client.documents.fa3.validation import facet_for

    assert facet_for("NieMaTakiegoElementu") is None
    assert facet_for("P_7") is not None


def test_validation_error_message_points_at_element() -> None:
    """`to_xml()` ma zgłaszać ścieżkę elementu, a nie surowy błąd SCHEMAV."""
    builder = BasicInvoiceBuilder(invoice_number="FV/FACETS-ERR")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2"))
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    invoice = builder.build()
    broken = invoice.to_xml().decode("utf-8").replace("<P_12>23</P_12>", "<P_12>99</P_12>")
    root = ET.fromstring(broken)
    issues = validate_xml_facets(root)
    assert issues
    assert all(issue.path.startswith("Faktura") for issue in issues)


def test_margin_rate_code_is_accepted() -> None:
    """`np I` (procedura marży) musi przechodzić słownik `P_12`."""
    root = _tree(tax=TaxCategory.margin())
    rate = root.find(f".//{_q('P_12')}")
    assert rate is not None and rate.text == "np I"
    assert validate_xml_facets(root) == []


def test_regex_patterns_in_table_are_anchored() -> None:
    """Wzorce muszą odrzucać wartości z nadmiarowymi znakami."""
    entry = ELEMENT_FACETS["KRS"]
    assert entry.pattern is not None
    assert not entry.pattern.fullmatch("0000111111X")
    assert not entry.pattern.fullmatch("000011111")
    assert re.fullmatch(entry.pattern, "0000111111")


def test_date_facets_declare_schema_bounds() -> None:
    """Zakresy dat w tabeli muszą odpowiadać schematowi."""
    assert ELEMENT_FACETS["P_1"].facet.minimum_date == "2016-07-01"
    assert ELEMENT_FACETS["P_1"].facet.maximum_date == "2050-01-01"
    assert ELEMENT_FACETS["DataUmowy"].facet.minimum_date == "1990-01-01"
    assert ELEMENT_FACETS["P_22A"].facet.minimum_date == "2006-01-01"
    assert ELEMENT_FACETS["DataGodzRozpTransportu"].facet.minimum_date == "2021-10-01T00:00:00Z"


def test_issue_date_today_is_within_bounds() -> None:
    """Sanity check: dzisiejsza data mieści się w zakresie schematu."""
    today = date.today().isoformat()
    from ksef_client.documents.fa3.validation.engine import _check_date_range
    from ksef_client.documents.fa3.validation.facets import DATA

    assert _check_date_range(today, DATA, "path", "P_1") == []


def test_xml_validation_error_is_a_value_error() -> None:
    assert issubclass(FA3XmlValidationError, ValueError)


def test_local_name_without_namespace_prefix() -> None:
    """Element bez przestrzeni nazw też ma czytelną nazwę lokalną."""
    from ksef_client.documents.fa3.validation.engine import _local_name

    assert _local_name("P_7") == "P_7"
    assert _local_name("{http://crd.gov.pl/wzor/2025/06/25/13775/}P_7") == "P_7"


def test_disallowed_length_is_reported() -> None:
    """Pola z zamkniętą listą długości (np. numer KSeF) muszą ją respektować."""
    from ksef_client.documents.fa3.validation.engine import _check_text
    from ksef_client.documents.fa3.validation.facets import NUMER_KSEF

    issues = _check_text(
        "1111111111-20260101-AAAAAA-BBBBBBB-01", NUMER_KSEF, "p", "NrKSeFFaKorygowanej"
    )
    assert issues and "niedozwolona" in issues[0].message
    assert _check_text("1111111111-20260101-AAAAAA-BBBBBB-01", NUMER_KSEF, "p", "X") == []
