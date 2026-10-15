from __future__ import annotations

import ast
import json
import re
import runpy
import zipfile
from dataclasses import replace
from datetime import date, datetime
from decimal import Decimal
from importlib import resources
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

import ksef_client.documents.fa3 as fa3_public
from ksef_client.documents.fa3 import (
    AdditionalDescription,
    Address,
    AdvancePayment,
    Annotation,
    AnnotationSet,
    Attachment,
    AttachmentBlock,
    AttachmentTable,
    AuthorizedPartyRole,
    BankAccount,
    BasicInvoiceBuilder,
    Contact,
    CorrectedAdvanceState,
    CorrectionInvoiceBuilder,
    CorrectionReference,
    CorrectionType,
    CoverageStatus,
    Discount,
    ExciseRefund,
    FA3BatchDraft,
    FA3Draft,
    FA3Invoice,
    FA3InvoiceBuilder,
    FA3InvoiceKind,
    FA3Party,
    Footer,
    GTUCode,
    InvoiceLine,
    LineIdentifiers,
    LineProcedure,
    MarginProcedure,
    NewTransportMeans,
    Order,
    OrderLine,
    OrderLineProcedure,
    PartialPayment,
    Party,
    PartyIdentifier,
    PaymentDue,
    PaymentMethod,
    PaymentTerms,
    Registry,
    Settlement,
    SettlementAdjustment,
    SettlementInvoiceBuilder,
    TaxCategory,
    TaxSummary,
    ThirdPartyRole,
    TransactionTerms,
    Transport,
    TransportKind,
    VatClass,
    XsdElement,
    audit_fa3_xsd_coverage,
    parse_fa3_xsd_elements,
)
from ksef_client.documents.fa3 import xsd_audit as xsd_audit_module
from ksef_client.documents.fa3.domain import (
    AdvanceInvoiceReference,
    FA3InvoiceBuilderV2,
    InvoiceParty,
    TaxCategoryKind,
)
from ksef_client.documents.fa3.models import (
    FA3Line,
    FA3ValidationIssue,
    _coerce_optional_decimal,
    _first_non_empty_text,
    _looks_like_zero,
    _optional_decimal,
    _optional_iso_date,
    _parse_iso_date,
    decimal_from_value,
    money,
    parse_vat_code,
    parse_vat_rate,
)
from ksef_client.documents.fa3.validation import validate_xml_facets
from ksef_client.documents.fa3.xml import (
    FA3XmlValidationError,
    _amount,
    _amount2,
    _basic_xml_validation,
    _q,
    _schema_resolver,
    _vat_rate,
    validate_fa3_xml_xsd,
)
from ksef_client.documents.fa3.xml import (
    _draft_vat_bucket as _draft_bucket,
)
from ksef_client.documents.fa3.xsd_map import (
    RAW_EXTENSION_PATHS,
    SUPPORTED_BUILDER_PATHS,
    UNSUPPORTED_PATHS,
)

ALL_INVOICE_KIND_CASES: list[tuple[FA3InvoiceKind, str, dict[str, Any]]] = [
    (FA3InvoiceKind.BASIC, "VAT", {}),
    (FA3InvoiceKind.SIMPLIFIED, "UPR", {}),
    (
        FA3InvoiceKind.CORRECTION,
        "KOR",
        {
            "correction_reason": "Zmiana ceny",
            "corrected_invoice_number": "FV/OLD/1",
            "corrected_invoice_date": date(2026, 1, 1),
        },
    ),
    (FA3InvoiceKind.ADVANCE, "ZAL", {}),
    (
        FA3InvoiceKind.SETTLEMENT,
        "ROZ",
        {
            "advance_invoice_number": "FV/ZAL/1",
            "settlement_amount": decimal_from_value("123.00", field_name="kwota"),
        },
    ),
    (
        FA3InvoiceKind.ADVANCE_CORRECTION,
        "KOR_ZAL",
        {
            "correction_reason": "Korekta zaliczki",
            "corrected_invoice_number": "FV/ZAL/1",
            "corrected_invoice_date": date(2026, 1, 1),
        },
    ),
    (
        FA3InvoiceKind.SETTLEMENT_CORRECTION,
        "KOR_ROZ",
        {
            "correction_reason": "Korekta rozliczenia",
            "corrected_invoice_number": "FV/ROZ/1",
            "corrected_invoice_date": date(2026, 1, 1),
            "advance_invoice_number": "FV/ZAL/1",
            "settlement_amount": decimal_from_value("123.00", field_name="kwota"),
        },
    ),
]


def test_json_batch_roundtrip_xml_files_and_zip(tmp_path: Path) -> None:
    draft = _draft("FV/JSON/1")
    batch = FA3BatchDraft((draft,))
    json_path = tmp_path / "draft.json"

    json_text = batch.to_json(json_path)
    loaded = FA3BatchDraft.from_json(json_path)
    from_text = FA3BatchDraft.from_json(json_text)
    from_dict = FA3BatchDraft.from_json(json.loads(json_text))

    assert loaded == from_text == from_dict == batch
    files = loaded.to_xml_files(tmp_path / "xml")
    assert files[0].read_bytes().startswith(b"<?xml")
    assert b"<RodzajFaktury>VAT</RodzajFaktury>" in files[0].read_bytes()

    zip_path = loaded.to_xml_zip(tmp_path / "fa3.zip")
    with zipfile.ZipFile(BytesIO(zip_path.read_bytes())) as zf:
        assert zf.namelist() == ["FV_JSON_1.xml"]


def test_correction_settlement_example_runs_and_writes_xsd_valid_xml(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    example = Path(__file__).parents[1] / "docs" / "examples" / "fa3_correction_settlement_sdk.py"
    monkeypatch.chdir(tmp_path)

    runpy.run_path(str(example), run_name="__main__")

    correction = tmp_path / "artifacts" / "fa3-special-cases" / "correction.xml"
    settlement = tmp_path / "artifacts" / "fa3-special-cases" / "settlement.xml"
    assert correction.exists()
    assert settlement.exists()
    validate_fa3_xml_xsd(correction.read_bytes())
    validate_fa3_xml_xsd(settlement.read_bytes())


def test_packaged_fa3_xsd_files_have_no_trailing_whitespace() -> None:
    schema_root = resources.files("ksef_client.documents.fa3.schemas")

    for schema in schema_root.iterdir():
        if schema.name.endswith(".xsd"):
            for line_number, line in enumerate(schema.read_bytes().splitlines(), start=1):
                assert line.rstrip(b" \t") == line, f"{schema.name}:{line_number}"


@pytest.mark.parametrize(("kind", "code", "extra"), ALL_INVOICE_KIND_CASES)
def test_all_invoice_kinds_are_exported_to_xml(
    kind: FA3InvoiceKind,
    code: str,
    extra: dict[str, Any],
) -> None:
    draft = _draft(f"FV/{code}/1", kind=kind, **extra)

    xml = draft.to_xml()

    assert f"<RodzajFaktury>{code}</RodzajFaktury>".encode() in xml


def test_sdk_only_public_api_exports() -> None:
    assert hasattr(fa3_public, "FA3InvoiceBuilder")
    assert hasattr(fa3_public, "FA3BatchDraft")
    assert hasattr(fa3_public, "validate_fa3_xml_xsd")

    assert not hasattr(fa3_public, "FA3Importer")
    assert not hasattr(fa3_public, "FA3Template")
    assert not hasattr(fa3_public, "ImportMode")


@pytest.mark.parametrize(("kind", "code", "extra"), ALL_INVOICE_KIND_CASES)
def test_all_invoice_kinds_pass_xsd_validation(
    kind: FA3InvoiceKind,
    code: str,
    extra: dict[str, Any],
) -> None:
    draft = _draft(f"FV/{code}/XSD", kind=kind, **extra)

    xml = draft.to_xml(xsd_validate=True)

    assert f"<RodzajFaktury>{code}</RodzajFaktury>".encode() in xml


def test_models_cover_human_aliases_and_validation_edges() -> None:
    assert FA3InvoiceKind.parse(FA3InvoiceKind.BASIC) is FA3InvoiceKind.BASIC
    decimal_value = decimal_from_value(
        decimal_from_value("2", field_name="kwota"),
        field_name="kwota",
    )
    assert str(decimal_value) == "2"
    assert decimal_from_value("1,23", field_name="kwota").as_tuple().digits == (1, 2, 3)
    assert decimal_from_value(1, field_name="kwota").as_tuple().digits == (1,)
    assert parse_vat_rate("zw") is None
    assert _optional_decimal({"kwota": "4.56"}, "kwota") == decimal_from_value(
        "4.56",
        field_name="kwota",
    )
    assert _coerce_optional_decimal("7.89", "kwota") == decimal_from_value(
        "7.89",
        field_name="kwota",
    )
    zero_line = FA3Line.from_dict(
        {
            "opis": "Gratis",
            "ilosc": 1,
            "jm": "szt",
            "cena_netto": 0,
            "vat": "zw",
        }
    )
    assert zero_line.quantity == Decimal("1")
    assert zero_line.unit_net_price == Decimal("0")
    zero_quantity_line = FA3Line.from_dict(
        {
            "opis": "Zero qty",
            "ilosc": 0,
            "jm": "szt",
            "cena_netto": 10,
            "vat": "23",
        }
    )
    assert zero_quantity_line.quantity == Decimal("0")
    assert any(
        "ilość musi być większa od zera" in issue.message
        for issue in zero_quantity_line.validate()[0]
    )

    zero_draft = FA3Draft.from_dict(
        {
            "numer_faktury": "FV/ZERO/1",
            "data_wystawienia": "2026-01-15",
            "sprzedawca": {
                "nazwa": "Sprzedawca",
                "nip": "1234567890",
                "adres": "Adres S",
                "kraj": "PL",
            },
            "nabywca": {
                "nazwa": "Nabywca",
                "nip": "1111111111",
                "adres": "Adres N",
                "kraj": "PL",
            },
            "pozycje": [
                {
                    "opis": "Gratis",
                    "ilosc": 1,
                    "jm": "szt",
                    "cena_netto": 0,
                    "vat": "zw",
                }
            ],
        }
    )
    assert zero_draft.lines[0].unit_net_price == Decimal("0")
    # Stawka "zw" wymaga podstawy prawnej do adnotacji P_19A (samo P_19N byłoby
    # sprzeczne z pozycją zwolnioną).
    zero_draft = replace(
        zero_draft,
        lines=[replace(zero_draft.lines[0], exemption_basis="art. 43 ust. 1 ustawy")],
    )
    # Stawka "zw" wymaga podstawy prawnej do adnotacji P_19A (samo P_19N byłoby
    # sprzeczne z pozycją zwolnioną) - patrz test_draft_exempt_line_requires_basis.
    zero_draft = replace(
        zero_draft,
        lines=[replace(zero_draft.lines[0], exemption_basis="art. 43 ust. 1 ustawy")],
    )
    # P_9A jest typu TKwotowy2 (do 8 miejsc po przecinku), więc wartość jest
    # normalizowana: 0.00 -> "0". XSD wymaga co najmniej jednej cyfry po kropce.
    assert "<P_9A>0</P_9A>" in zero_draft.to_xml().decode("utf-8")
    empty_lines_keep_priority = FA3Draft.from_dict(
        {
            "numer_faktury": "FV/EMPTY-LINES/1",
            "data_wystawienia": "2026-01-15",
            "sprzedawca": {"nazwa": "Sprzedawca", "nip": "1234567890"},
            "nabywca": {"nazwa": "Nabywca", "nip": "1111111111"},
            "pozycje": [],
            "lines": [
                {
                    "opis": "Should not win",
                    "ilosc": 1,
                    "cena_netto": 10,
                    "vat": "23",
                }
            ],
        }
    )
    assert empty_lines_keep_priority.lines == []

    with pytest.raises(ValueError, match="Nieznany typ"):
        FA3InvoiceKind.parse("dziwna")
    with pytest.raises(ValueError, match="wymagane"):
        decimal_from_value("", field_name="kwota")
    with pytest.raises(ValueError, match="musi być liczbą"):
        decimal_from_value("abc", field_name="kwota")
    with pytest.raises(ValueError, match="Data jest wymagana"):
        _parse_iso_date("")

    assert _parse_iso_date(date(2026, 1, 15)) == date(2026, 1, 15)
    assert _optional_iso_date("2026-01-16") == date(2026, 1, 16)
    assert _vat_rate(None) == "zw"
    assert _vat_rate(decimal_from_value("8.5", field_name="vat")) == "8.5"

    issue = FA3ValidationIssue("tekst").with_location(row_number=7, cell="A7")
    assert issue.row_number == 7
    assert issue.cell == "A7"

    party_errors = FA3Party(name="", tax_id="", country_code="").validate("Podmiot")
    # `AdresL1` jest wymagane w schemacie, a draft wstawiał w to miejsce literał
    # "brak" — czyli fałszywy adres zamiast komunikatu o brakującym polu.
    assert len(party_errors) == 4
    assert any("adres jest wymagany" in issue.message for issue in party_errors)

    exempt_line = FA3Line(
        description="Zwolnione",
        quantity=decimal_from_value("1", field_name="ilosc"),
        unit="szt",
        unit_net_price=decimal_from_value("10", field_name="cena"),
        vat_rate=None,
        net_amount=decimal_from_value("11", field_name="netto"),
        vat_amount=decimal_from_value("1", field_name="vat"),
    )
    errors, warnings = exempt_line.validate()
    assert errors == []
    assert len(warnings) == 2
    assert str(exempt_line.effective_net_amount) == "11.00"
    assert str(exempt_line.effective_vat_amount) == "1.00"
    # Brutto liczone z *efektywnego* netto i VAT, żeby P_13_x + P_14_x == P_15.
    assert str(exempt_line.effective_gross_amount) == "12.00"

    bad_line = FA3Line(
        description="",
        quantity=decimal_from_value("0", field_name="ilosc"),
        unit="szt",
        unit_net_price=decimal_from_value("-1", field_name="cena"),
        vat_rate=decimal_from_value("-1", field_name="vat"),
    )
    assert len(bad_line.validate()[0]) == 4

    gross_override_line = FA3Line(
        description="Brutto override",
        quantity=decimal_from_value("1", field_name="ilosc"),
        unit="szt",
        unit_net_price=decimal_from_value("10", field_name="cena"),
        vat_rate=decimal_from_value("23", field_name="vat"),
        gross_amount=decimal_from_value("99", field_name="brutto"),
    )
    assert str(gross_override_line.effective_gross_amount) == "99.00"


@pytest.mark.parametrize(
    ("payload", "keys", "expected"),
    [
        (
            {"numer_faktury": "", "invoice_number": "FV/1"},
            ("numer_faktury", "invoice_number"),
            "FV/1",
        ),
        (
            {"numer_faktury": "   ", "invoice_number": "FV/2"},
            ("numer_faktury", "invoice_number"),
            "FV/2",
        ),
        ({"waluta": "", "currency": "eur"}, ("waluta", "currency"), "eur"),
        ({"forma": "   ", "method": "gotowka"}, ("forma", "method"), "gotowka"),
    ],
)
def test_first_non_empty_text_alias_fallback(
    payload: dict[str, Any],
    keys: tuple[str, ...],
    expected: str,
) -> None:
    assert _first_non_empty_text(payload, *keys) == expected


def test_fa3draft_from_dict_prefers_non_empty_text_aliases() -> None:
    draft = FA3Draft.from_dict(
        {
            "numer_faktury": "",
            "invoice_number": "FV/ALIAS/1",
            "data_wystawienia": "2026-01-15",
            "waluta": "   ",
            "currency": "eur",
            "miejsce_wystawienia": "   ",
            "issue_place": "Warszawa",
            "sprzedawca": {"nazwa": "S", "nip": "1234567890"},
            "nabywca": {"nazwa": "B", "nip": "1111111111"},
            "pozycje": [{"opis": "Line", "ilosc": 1, "cena_netto": 10, "vat": "23"}],
        }
    )
    assert draft.invoice_number == "FV/ALIAS/1"
    assert draft.currency == "EUR"
    assert draft.issue_place == "Warszawa"


def test_fa3draft_from_dict_preserves_structural_values_with_aliases() -> None:
    draft_zero = FA3Draft.from_dict(
        {
            "numer_faktury": "FV/STRUCT/0",
            "data_wystawienia": "2026-01-15",
            "sprzedawca": {"nazwa": "S", "nip": "1234567890"},
            "nabywca": {"nazwa": "B", "nip": "1111111111"},
            "pozycje": [{"opis": "Line", "ilosc": 1, "cena_netto": 10, "vat": "23"}],
            "rozliczenie": {"kwota": 0},
            "settlement": {"amount": 9},
        }
    )
    assert draft_zero.settlement_amount == Decimal("0")

    draft_empty_lines = FA3Draft.from_dict(
        {
            "numer_faktury": "FV/STRUCT/LINES",
            "data_wystawienia": "2026-01-15",
            "sprzedawca": {"nazwa": "S", "nip": "1234567890"},
            "nabywca": {"nazwa": "B", "nip": "1111111111"},
            "pozycje": [],
            "lines": [{"opis": "Fallback", "ilosc": 1, "cena_netto": 10, "vat": "23"}],
        }
    )
    assert draft_empty_lines.lines == []


def test_draft_and_xml_validation_edges() -> None:
    invalid_builder = FA3InvoiceBuilder(
        invoice_number="",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="", tax_id=""),
        buyer=FA3Party(name="", tax_id=""),
        currency="",
    )
    with pytest.raises(ValueError, match="Numer faktury"):
        invalid_builder.build()

    settlement_builder = FA3InvoiceBuilder(
        invoice_number="FV/ROZ/BAD",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1"),
        buyer=FA3Party(name="B", tax_id="2"),
        kind=FA3InvoiceKind.SETTLEMENT,
    )
    settlement_builder.add_line("Usługa", quantity="1", unit_net_price="1")
    with pytest.raises(ValueError, match="Rozliczenie"):
        settlement_builder.build()

    correction_without_date = FA3InvoiceBuilder(
        invoice_number="FV/KOR/BAD-DATE",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1"),
        buyer=FA3Party(name="B", tax_id="2"),
        kind=FA3InvoiceKind.CORRECTION,
        correction_reason="Korekta",
        corrected_invoice_number="FV/OLD/1",
    )
    correction_without_date.add_line("Usługa", quantity="1", unit_net_price="1")
    with pytest.raises(ValueError, match="data faktury korygowanej"):
        correction_without_date.build()

    correction_without_reason = FA3InvoiceBuilder(
        invoice_number="FV/KOR/BAD-REASON",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1"),
        buyer=FA3Party(name="B", tax_id="2"),
        kind=FA3InvoiceKind.CORRECTION,
        corrected_invoice_number="FV/OLD/1",
        corrected_invoice_date=date(2026, 1, 1),
    )
    correction_without_reason.add_line("Usługa", quantity="1", unit_net_price="1")
    with pytest.raises(ValueError, match="przyczyna korekty"):
        correction_without_reason.build()

    correction_without_number = FA3InvoiceBuilder(
        invoice_number="FV/KOR/BAD-NUMBER",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1"),
        buyer=FA3Party(name="B", tax_id="2"),
        kind=FA3InvoiceKind.CORRECTION,
        correction_reason="Korekta",
        corrected_invoice_date=date(2026, 1, 1),
        corrected_ksef_number="1111111111-20260101-AAAAAA-BBBBBB-01",
    )
    correction_without_number.add_line("Usługa", quantity="1", unit_net_price="1")
    with pytest.raises(ValueError, match="numer faktury korygowanej"):
        correction_without_number.build()

    settlement_with_both_refs = FA3InvoiceBuilder(
        invoice_number="FV/ROZ/BAD-BOTH",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1"),
        buyer=FA3Party(name="B", tax_id="2"),
        kind=FA3InvoiceKind.SETTLEMENT,
        advance_invoice_number="FV/ZAL/1",
        advance_ksef_number="1111111111-20260101-AAAAAA-BBBBBB-01",
    )
    settlement_with_both_refs.add_line("Usługa", quantity="1", unit_net_price="1")
    with pytest.raises(ValueError, match="albo numer KSeF, nie oba"):
        settlement_with_both_refs.build()

    invoice_with_empty_advance_ref = FA3Invoice(
        invoice_number="FV/ROZ/BAD-XML",
        issue_date=date(2026, 1, 15),
        seller=Party.polish_company(nip="1234567890", name="S", address="Adres"),
        buyer=Party.polish_company(nip="1111111111", name="B", address="Adres"),
        lines=(
            InvoiceLine.service(
                "Usługa",
                quantity="1",
                unit_net_price="1",
            ),
        ),
        kind=FA3InvoiceKind.SETTLEMENT,
        advance_invoices=(AdvanceInvoiceReference(),),
    )
    with pytest.raises(
        FA3XmlValidationError,
        match="podaj numer faktury zaliczkowej albo numer KSeF",
    ):
        invoice_with_empty_advance_ref.to_xml(validate=False)
    invoice_with_both_advance_refs = replace(
        invoice_with_empty_advance_ref,
        advance_invoices=(
            AdvanceInvoiceReference(
                invoice_number="FV/ZAL/1",
                ksef_number="1111111111-20260101-AAAAAA-BBBBBB-01",
            ),
        ),
    )
    with pytest.raises(
        FA3XmlValidationError,
        match="podaj numer faktury zaliczkowej albo numer KSeF, nie oba",
    ):
        invoice_with_both_advance_refs.to_xml(validate=False)

    draft_with_both_advance_refs = FA3Draft(
        invoice_number="FV/DRAFT/BAD",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1"),
        buyer=FA3Party(name="B", tax_id="2"),
        lines=[
            FA3Line(
                description="Usluga",
                quantity=Decimal("1"),
                unit="szt",
                unit_net_price=Decimal("1"),
                vat_rate=Decimal("23"),
            ),
        ],
        kind=FA3InvoiceKind.SETTLEMENT,
        advance_invoice_number="FV/ZAL/1",
        advance_ksef_number="1111111111-20260101-AAAAAA-BBBBBB-01",
    )
    with pytest.raises(
        FA3XmlValidationError,
        match="invoice.advance_invoice_number",
    ):
        draft_with_both_advance_refs.to_xml(validate=False)

    invoice_with_mixed_sale_period = FA3Invoice(
        invoice_number="FV/BAD/PERIOD",
        issue_date=date(2026, 1, 15),
        seller=Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres"),
        buyer=Party.polish_company(nip="1111111111", name="Nabywca", address="Adres"),
        lines=(InvoiceLine.service("Usluga", quantity="1", unit_net_price="1"),),
        sale_date=date(2026, 1, 14),
        period_from=date(2026, 1, 1),
        period_to=date(2026, 1, 31),
    )
    with pytest.raises(ValueError, match="sale_date"):
        invoice_with_mixed_sale_period.to_xml()

    invoice_with_mixed_payment = FA3Invoice(
        invoice_number="FV/BAD/PAY",
        issue_date=date(2026, 1, 15),
        seller=Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres"),
        buyer=Party.polish_company(nip="1111111111", name="Nabywca", address="Adres"),
        lines=(InvoiceLine.service("Usluga", quantity="1", unit_net_price="1"),),
        payment_terms=PaymentTerms(
            paid_date=date(2026, 1, 15),
            partial_payments=(PartialPayment.create("1", date(2026, 1, 14)),),
        ),
    )
    with pytest.raises(ValueError, match="payment_terms"):
        invoice_with_mixed_payment.to_xml()

    invoice_with_conflicting_settlement_choice = replace(
        invoice_with_mixed_payment,
        invoice_number="FV/BAD/SETTLEMENT-CHOICE",
        payment_terms=None,
        settlement_data=Settlement(
            amount_due=Decimal("10.00"),
            amount_to_settle=Decimal("1.00"),
        ),
    )
    with pytest.raises(ValueError, match="DoZaplaty albo DoRozliczenia"):
        invoice_with_conflicting_settlement_choice.to_xml()

    invoice_with_conflicting_payment_method = replace(
        invoice_with_mixed_payment,
        invoice_number="FV/BAD/PAYMENT-METHOD",
        payment_terms=PaymentTerms(
            method=PaymentMethod.CASH.value,
            other_method_description="kompensata",
        ),
    )
    with pytest.raises(ValueError, match="forme platnosci albo opis innej formy"):
        invoice_with_conflicting_payment_method.to_xml()

    invoice_with_conflicting_partial_payment_method = replace(
        invoice_with_mixed_payment,
        invoice_number="FV/BAD/PAYMENT-METHOD-PARTIAL",
        payment_terms=PaymentTerms(
            partial_payments=(
                PartialPayment.create(
                    "1",
                    date(2026, 1, 14),
                    method=PaymentMethod.CASH.value,
                    other_method_description="kompensata",
                ),
            ),
        ),
    )
    with pytest.raises(
        ValueError,
        match="partial_payments\\[1\\].*forme platnosci albo opis innej formy",
    ):
        invoice_with_conflicting_partial_payment_method.to_xml()

    invoice_with_half_period = FA3Invoice(
        invoice_number="FV/BAD/HALF-PERIOD",
        issue_date=date(2026, 1, 15),
        seller=Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres"),
        buyer=Party.polish_company(nip="1111111111", name="Nabywca", address="Adres"),
        lines=(InvoiceLine.service("Usluga", quantity="1", unit_net_price="1"),),
        period_from=date(2026, 1, 1),
    )
    with pytest.raises(ValueError, match="okres faktury wymaga obu dat"):
        invoice_with_half_period.to_xml()

    settlement_builder_v2 = (
        FA3InvoiceBuilderV2("FV/BAD/ADVREF", FA3InvoiceKind.SETTLEMENT)
        .issued_on(date(2026, 1, 15))
        .seller(Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres"))
        .buyer(Party.polish_company(nip="1111111111", name="Nabywca", address="Adres"))
        .add_line("Usluga", quantity="1", unit_net_price="1")
        .settles_advance()
    )
    with pytest.raises(ValueError, match="podaj numer faktury zaliczkowej albo numer KSeF"):
        settlement_builder_v2.build()

    correction_with_blank_reason = FA3Invoice.correction("FV/BAD/CORRECTION-REASON")
    correction_with_blank_reason.issued_on(date(2026, 1, 15))
    correction_with_blank_reason.seller(
        Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres")
    )
    correction_with_blank_reason.buyer(
        Party.polish_company(nip="1111111111", name="Nabywca", address="Adres")
    )
    correction_with_blank_reason.add_service_line("Usluga", quantity="1", unit_net_price="1")
    correction_with_blank_reason.corrects_invoice(
        number="FV/OLD/1",
        issue_date=date(2026, 1, 1),
        reason="   ",
    )
    with pytest.raises(ValueError, match="invoice.correction_reason"):
        correction_with_blank_reason.build()

    correction_with_blank_corrected_number = FA3Invoice.correction("FV/BAD/CORRECTED-NUMBER")
    correction_with_blank_corrected_number.issued_on(date(2026, 1, 15))
    correction_with_blank_corrected_number.seller(
        Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres")
    )
    correction_with_blank_corrected_number.buyer(
        Party.polish_company(nip="1111111111", name="Nabywca", address="Adres")
    )
    correction_with_blank_corrected_number.add_service_line(
        "Usluga", quantity="1", unit_net_price="1"
    )
    correction_with_blank_corrected_number.corrects_invoice(
        number="   ",
        issue_date=date(2026, 1, 1),
        reason="Rabat",
    )
    with pytest.raises(
        ValueError,
        match="invoice.corrected_invoices\\[1\\]\\.invoice_number",
    ):
        correction_with_blank_corrected_number.build()

    valid_correction_builder = FA3Invoice.correction("FV/OK/CORRECTION")
    valid_correction_builder.issued_on(date(2026, 1, 15))
    valid_correction_builder.seller(
        Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres")
    )
    valid_correction_builder.buyer(
        Party.polish_company(nip="1111111111", name="Nabywca", address="Adres")
    )
    valid_correction_builder.add_service_line("Usluga", quantity="1", unit_net_price="1")
    valid_correction_builder.corrects_invoice(
        number="FV/OLD/2",
        issue_date=date(2026, 1, 1),
        reason="Korekta danych",
    )
    valid_correction = valid_correction_builder.build()
    valid_correction_xml = valid_correction.to_xml()
    assert "<PrzyczynaKorekty>Korekta danych</PrzyczynaKorekty>" in valid_correction_xml.decode(
        "utf-8"
    )
    assert "<NrFaKorygowanej>FV/OLD/2</NrFaKorygowanej>" in valid_correction_xml.decode("utf-8")

    empty_draft = FA3Draft(
        invoice_number="FV/EMPTY",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1"),
        buyer=FA3Party(name="B", tax_id="2"),
        lines=[],
    )
    assert "co najmniej" in empty_draft.validate()[0][0].message
    with pytest.raises(FA3XmlValidationError):
        empty_draft.to_xml()

    with pytest.raises(FA3XmlValidationError):
        _basic_xml_validation(ET.Element("Faktura"))


def test_xml_exports_advanced_fields_and_payment_variants() -> None:
    draft = _draft(
        "FV/ADV/1",
        kind=FA3InvoiceKind.SETTLEMENT_CORRECTION,
        correction_reason="Korekta",
        corrected_invoice_number="FV/OLD/1",
        corrected_invoice_date=date(2026, 1, 1),
        corrected_ksef_number="1111111111-20260101-AAAAAA-BBBBBB-01",
        advance_ksef_number="1111111111-20260102-AAAAAA-BBBBBB-02",
        settlement_amount=decimal_from_value("12.34", field_name="kwota"),
        payment_due_date=date(2026, 1, 31),
        payment_method="gotówka",
    )

    xml = draft.to_xml()
    xml_text = xml.decode("utf-8")

    assert b"<DataWystFaKorygowanej>2026-01-01</DataWystFaKorygowanej>" in xml
    assert b"<NrKSeF>1</NrKSeF>" in xml
    assert b"<NrKSeFFaZaliczkowej>1111111111-20260102-AAAAAA-BBBBBB-02</NrKSeFFaZaliczkowej>" in xml
    assert b"<DoZaplaty>12.34</DoZaplaty>" in xml
    assert b"<FormaPlatnosci>1</FormaPlatnosci>" in xml
    assert b"<Zaliczka>" not in xml
    assert xml_text.index("<DataWystFaKorygowanej>") < xml_text.index("<NrFaKorygowanej>")
    assert xml_text.index("<FakturaZaliczkowa>") < xml_text.index("<FaWiersz>")
    assert xml_text.index("<FaWiersz>") < xml_text.index("<Rozliczenie>")
    assert xml_text.index("<Rozliczenie>") < xml_text.index("<Platnosc>")


def test_payment_method_without_a_due_date_is_still_emitted() -> None:
    """Sama forma płatności (bez terminu) jest poprawnym, wspieranym wejściem.

    Test wariantów płatności ustawia zawsze oba pola naraz, więc regresja, w której
    `<FormaPlatnosci>` znika, gdy nie ma terminu, przechodziła na zielono.
    """
    draft = _draft("FV/PAY/1", payment_method="gotówka")
    xml = draft.to_xml(xsd_validate=True).decode("utf-8")
    assert "<Platnosc>" in xml
    assert "<FormaPlatnosci>1</FormaPlatnosci>" in xml


def test_payment_method_mobile_alias_is_mapped_to_code_seven() -> None:
    """Alias „mobilna" z `_payment_code` musi trafić do dokumentu jako kod 7.

    Pozostałe aliasy mają testy (``gotówka`` → ``1``), ale ``mobilna`` nie
    występowało w żadnym teście — usunięcie tego wpisu z mapy przechodziło na
    zielono, a do ``FormaPlatnosci`` trafiał tekst zamiast kodu słownika
    ``TFormaPlatnosci`` (dokument odrzucałby KSeF).
    """
    draft = _draft("FV/MOBILNA/1", payment_due_date=date(2026, 1, 31), payment_method="mobilna")
    assert "<FormaPlatnosci>7</FormaPlatnosci>" in draft.to_xml(xsd_validate=True).decode("utf-8")

    typed = replace(_payment_invoice(), payment_terms=PaymentTerms(method="mobilna"))
    assert "<FormaPlatnosci>7</FormaPlatnosci>" in typed.to_xml(xsd_validate=True).decode("utf-8")


def test_basic_xml_validation_reports_the_missing_element() -> None:
    """Walidacja kształtu musi wskazywać KONKRETNY brakujący element.

    Dotychczasowy test wołał `_basic_xml_validation(ET.Element("Faktura"))`, co
    rzuca również przy liście wymaganych elementów skróconej do samego
    ``Naglowek`` — brakowało wszystkich czterech, więc mutacja tej listy (np.
    usunięcie ``Podmiot2``) przechodziła niezauważona.
    """
    root = ET.Element(_q("Faktura"))
    ET.SubElement(root, _q("Naglowek"))

    with pytest.raises(FA3XmlValidationError) as missing_parties:
        _basic_xml_validation(root)
    assert _missing_elements(missing_parties.value) == "Podmiot1, Podmiot2, Fa"

    ET.SubElement(root, _q("Podmiot1"))
    ET.SubElement(root, _q("Podmiot2"))

    with pytest.raises(FA3XmlValidationError) as missing_fa:
        _basic_xml_validation(root)
    assert _missing_elements(missing_fa.value) == "Fa"

    ET.SubElement(root, _q("Fa"))
    _basic_xml_validation(root)


def _missing_elements(error: FA3XmlValidationError) -> str:
    """Lista brakujących elementów z komunikatu (bez treści komunikatu)."""
    return str(error).rsplit(": ", 1)[-1]


def test_xsd_validation_accepts_basic_generated_invoice_and_rejects_invalid_xml() -> None:
    draft = _draft("FV/XSD/1")

    xml = draft.to_xml(xsd_validate=True)
    validate_fa3_xml_xsd(xml.decode("utf-8"))

    with pytest.raises(FA3XmlValidationError):
        validate_fa3_xml_xsd(b"<Faktura />")


def test_schema_resolver_is_fail_closed_for_unknown_schemas() -> None:
    """Resolver nie może oddać nieznanej nazwy domyślnemu resolverowi lxml.

    Zwrócenie `None` sprawiało, że `xsd:include`/`xsd:import` z obcym adresem
    był pobierany z sieci (libxml2 ma własny klient HTTP, więc `no_network`
    i podmiana `socket.socket` tego nie łapią) — dowód w
    `test_xsd_validation_never_reaches_the_network`.
    """
    from lxml import etree

    resolver = _schema_resolver(etree)

    with pytest.raises(FA3XmlValidationError, match="bundlowanych"):
        resolver.resolve("NieznanySchemat.xsd", None, None)
    with pytest.raises(FA3XmlValidationError, match="bundlowanych"):
        resolver.resolve("http://127.0.0.1:9/remote.xsd", None, None)


def test_xsd_validation_never_reaches_the_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Walidacja nie może otworzyć żadnego połączenia — nawet przy `include` z URL-em.

    Serwer loopback jest tu jedynym wiarygodnym detektorem: żądania z libxml2 nie
    przechodzą przez moduł `socket` Pythona, więc sam `monkeypatch` na
    `socket.socket` nie dowodzi braku sieci (przed naprawą resolver zwracał `None`
    i serwer dostawał żądanie `GET /remote.xsd`).
    """
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from lxml import etree

    received: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - nazwa wymagana przez http.server
            received.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            self.end_headers()
            self.wfile.write(b'<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema"/>')

        def log_message(self, *args: Any) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    opened: list[str] = []
    original_socket = socket.socket

    def _spy(*args: Any, **kwargs: Any) -> Any:
        opened.append("socket")
        return original_socket(*args, **kwargs)

    monkeypatch.setattr(socket, "socket", _spy)
    try:
        schema_url = f"http://127.0.0.1:{server.server_address[1]}/remote.xsd"
        parser = etree.XMLParser()
        parser.resolvers.add(_schema_resolver(etree))
        remote_include = (
            '<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema">'
            f'<xsd:include schemaLocation="{schema_url}"/>'
            "</xsd:schema>"
        )

        hard_error = False
        try:
            etree.XMLSchema(etree.fromstring(remote_include.encode("utf-8"), parser))
        except (FA3XmlValidationError, etree.XMLSchemaParseError):
            hard_error = True
        # Poprawny dokument nadal waliduje się bez sięgania do sieci.
        validate_fa3_xml_xsd(_draft("FV/XSD/NET").to_xml())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert received == [], f"walidacja pobrała zasób z sieci: {received}"
    assert hard_error, "obcy `xsd:include` musi kończyć się twardym błędem"
    assert opened == [], "walidacja próbowała otworzyć gniazdo"


def test_xsd_coverage_audit_reports_the_whole_schema() -> None:
    """Audyt musi widzieć CAŁY schemat, a statusy muszą pochodzić z serializatora.

    Wcześniejsza wersja walkera nie rozwiązywała `type="tns:X"`, więc widziała
    298 z 402 ścieżek (¼ schematu, w tym elementy wymagane), a status pokrycia
    brała z mapy dopasowywanej prefiksem `"/Faktura"` — dzięki czemu każda
    ścieżka, także wymyślona, była „pokryta" i `UNSUPPORTED` nie występowało.
    """
    report = audit_fa3_xsd_coverage(_audit_evidence_xml_cases())

    paths = {entry.path: entry.status for entry in report.coverage}
    assert len(report.elements) == 402, "audyt nie widzi całego schematu"
    assert len(paths) == len({element.path for element in report.elements})

    # Elementy, które SDK faktycznie emituje, muszą mieć status inny niż UNSUPPORTED.
    for path in (
        "/Faktura/Podmiot1",
        "/Faktura/Podmiot2",
        "/Faktura/Podmiot3",
        "/Faktura/PodmiotUpowazniony",
        "/Faktura/Naglowek/KodFormularza",
        "/Faktura/Naglowek/WariantFormularza",
        "/Faktura/Podmiot1/DaneIdentyfikacyjne/NIP",
        "/Faktura/Fa/Adnotacje",
        "/Faktura/Fa/FaWiersz",
        "/Faktura/Fa/Podmiot1K",
        "/Faktura/Fa/Platnosc/RachunekBankowy/NrRB",
        "/Faktura/Fa/P_15",
        "/Faktura/Zalacznik/BlokDanych/MetaDane",
    ):
        assert paths[path] is not CoverageStatus.UNSUPPORTED, path

    # Kontakty podmiotu upoważnionego mają w schemacie własne znaczniki
    # (`EmailPU`/`TelefonPU`), a nie `Email`/`Telefon`.
    assert paths["/Faktura/PodmiotUpowazniony/DaneKontaktowe/EmailPU"] is not (
        CoverageStatus.UNSUPPORTED
    )
    assert paths["/Faktura/PodmiotUpowazniony/DaneKontaktowe/TelefonPU"] is not (
        CoverageStatus.UNSUPPORTED
    )

    assert not report.by_status(CoverageStatus.RAW_EXTENSION)


def test_xsd_audit_statuses_follow_the_serializer() -> None:
    """Status `UNSUPPORTED` musi być osiągalny, a `SUPPORTED` wymaga dowodu."""
    report = audit_fa3_xsd_coverage()
    statuses = {entry.status for entry in report.coverage}
    # Bez dowodu z testów nie ma `SUPPORTED` — tylko `PARTIALLY_SUPPORTED`.
    assert CoverageStatus.SUPPORTED not in statuses
    # Serializer wypisuje wszystkie elementy schematu FA(3), więc na realnym
    # schemacie `UNSUPPORTED` nie występuje — jest to fakt o SDK (patrz
    # `test_xsd_audit_emitted_tags_come_from_real_emission_sites`), a nie skutek
    # rozpoznawania znaczników. Status musi być OSIĄGALNY dla elementu, którego
    # serializer nie zna, inaczej byłby fikcją.
    assert not report.by_status(CoverageStatus.UNSUPPORTED)
    entry = xsd_audit_module._entry_for_element(
        XsdElement("/Faktura/Fa/TotallyUnknownField", "TotallyUnknownField", None, "1", "1"),
        evidence_sources=(),
    )
    assert entry.status is CoverageStatus.UNSUPPORTED

    with_evidence = audit_fa3_xsd_coverage(_audit_evidence_xml_cases())
    with_evidence_by_path = {item.path: item for item in with_evidence.coverage}
    # Dowód z testów podnosi status do `SUPPORTED`, a brak dowodu zostawia
    # `PARTIALLY_SUPPORTED` — raport nie jest więc jednorodny.
    assert with_evidence_by_path["/Faktura/Fa/FaWiersz/P_7"].status is CoverageStatus.SUPPORTED
    assert (
        with_evidence_by_path["/Faktura/Podmiot3/DaneIdentyfikacyjne/IDWew"].status
        is CoverageStatus.PARTIALLY_SUPPORTED
    )
    assert len(with_evidence.by_status(CoverageStatus.SUPPORTED)) > 300


def test_xsd_audit_emitted_tags_come_from_real_emission_sites() -> None:
    """Zbiór znaczników to dokładnie nazwy elementów, które serializer wypisuje.

    Poprzednia ekstrakcja dopasowywała dowolny literał z wielkiej litery, więc do
    zbioru trafiały napisy, które znacznikami nie są — m.in. nazwa atrybutu
    ``Typ`` z ``column.set("Typ", column_type)`` w tabeli załącznika. Taki
    fałszywy znacznik maskowałby realną lukę w pokryciu schematu.
    """
    emitted = xsd_audit_module._emitted_tags()
    schema_names = {element.name for element in parse_fa3_xsd_elements()}

    assert schema_names <= emitted
    assert not emitted - schema_names, "zbiór znaczników zawiera napisy spoza schematu"
    assert "Typ" not in emitted

    # Każdy znacznik ma właściciela w `xml.py`, więc raport może wskazać handler.
    sites = xsd_audit_module._emission_sites()
    assert all(any(owners) for owners in sites.values())
    assert sites["WarunkiTransakcji"] == ("_domain_transaction_terms",)
    assert "_domain_transport" in sites["Transport"]
    # Znaczniki z tabeli modułowej (`_TAX_SUMMARY_ORDER`) przypisujemy funkcji,
    # która tę tabelę wykorzystuje, a nie „poziomowi modułu".
    assert sites["P_13_1"][0] == "_tax_summary"

    # Stała tekstowa z modułu nie jest tabelą znaczników, choć wygląda jak nazwa
    # elementu — inaczej do zbioru wróciłyby napisy spoza miejsc emisji.
    assert xsd_audit_module._module_tag_constants(ast.parse('KOD = "KodWaluty"')) == {}
    assert xsd_audit_module._module_tag_constants(ast.parse('KODY = ("23", "8")')) == {}
    assert xsd_audit_module._module_tag_constants(ast.parse('TABELA = ("P_16", "P_17")')) == {
        "TABELA": ("P_16", "P_17")
    }


def test_xsd_audit_reports_drift_when_the_serializer_loses_a_tag() -> None:
    """Utrata znacznika w serializerze musi dać `UNSUPPORTED`, nie „jakoś pokryte".

    Symulujemy dryf schematu (albo regresję w `xml.py`): mapa miejsc emisji bez
    ``P_22BT``, czyli bez stawki akcyzy nowego środka transportu. Wcześniejszy
    audyt nie umiał pokazać takiej luki, bo status brał z mapy dopasowywanej
    prefiksem ``/Faktura``.
    """
    sites = xsd_audit_module._EMISSION_SITES
    try:
        xsd_audit_module._EMISSION_SITES = {
            tag: owners for tag, owners in xsd_audit_module._scan_emissions(
                xsd_audit_module._xml_module_tree()
            ).items() if tag != "P_22BT"
        }
        report = audit_fa3_xsd_coverage()
    finally:
        xsd_audit_module._EMISSION_SITES = sites

    by_path = {entry.path: entry for entry in report.coverage}
    transport_tax = "/Faktura/Fa/Adnotacje/NoweSrodkiTransportu/NowySrodekTransportu/P_22BT"
    assert by_path[transport_tax].status is CoverageStatus.UNSUPPORTED
    assert [entry.path for entry in report.by_status(CoverageStatus.UNSUPPORTED)] == [
        transport_tax
    ]


def test_xsd_audit_maps_handlers_and_domain_fields() -> None:
    report = audit_fa3_xsd_coverage()
    by_path = {entry.path: entry for entry in report.coverage}
    assert by_path["/Faktura/Fa/FaWiersz/P_7"].handler == "_domain_line"
    assert by_path["/Faktura/Zalacznik/BlokDanych"].handler == "_attachment_block"
    assert by_path["/Faktura/Fa/FaWiersz/P_7"].domain_field == "invoice.Fa.FaWiersz.P_7"

    # Sekcje, które wcześniej wpadały do `_domain_invoice` przez dopasowanie
    # prefiksu ścieżki, mają w `xml.py` własne funkcje tworzące elementy.
    assert by_path["/Faktura/Fa/WarunkiTransakcji"].handler == "_domain_transaction_terms"
    assert by_path["/Faktura/Fa/WarunkiTransakcji/WalutaUmowna"].handler == (
        "_domain_transaction_terms"
    )
    assert by_path["/Faktura/Fa/WarunkiTransakcji/Transport"].handler == "_domain_transport"
    assert by_path["/Faktura/Fa/WarunkiTransakcji/Transport/RodzajTransportu"].handler == (
        "_domain_transport"
    )
    assert by_path["/Faktura/Fa/P_15"].handler == "_tax_summary"
    assert by_path["/Faktura/Fa/Podmiot1K/Adres/AdresL1"].handler == "_address"

    # Raport nie zmyśla nazw: każdy handler to funkcja z `xml.py`.
    functions = {
        node.name
        for node in ast.walk(xsd_audit_module._xml_module_tree())
        if isinstance(node, ast.FunctionDef)
    }
    assert {entry.handler for entry in report.coverage} <= functions


def test_xsd_enum_values_match_public_fa3_enums() -> None:
    elements = {element.path: element for element in audit_fa3_xsd_coverage().elements}

    assert set(elements["/Faktura/Fa/FaWiersz/P_12"].enum_values) == {
        "23",
        "22",
        "8",
        "7",
        "5",
        "4",
        "3",
        "0 KR",
        "0 WDT",
        "0 EX",
        "zw",
        "oo",
        "np I",
        "np II",
    }
    assert set(elements["/Faktura/Fa/Platnosc/FormaPlatnosci"].enum_values) == {
        method.value for method in PaymentMethod
    }
    assert set(elements["/Faktura/Fa/FaWiersz/GTU"].enum_values) == {
        code.value for code in GTUCode
    }
    assert set(elements["/Faktura/Fa/FaWiersz/Procedura"].enum_values) == {
        procedure.value for procedure in LineProcedure
    }
    assert set(
        elements["/Faktura/Fa/WarunkiTransakcji/Transport/RodzajTransportu"].enum_values
    ) == {kind.value for kind in TransportKind}


def test_business_enum_values_match_fa3_xsd_semantics() -> None:
    assert AuthorizedPartyRole.ENFORCEMENT_AUTHORITY.value == "1"
    assert AuthorizedPartyRole.BAILIFF.value == "2"
    assert AuthorizedPartyRole.REPRESENTATIVE.value == "3"

    assert ThirdPartyRole.FACTOR.value == "1"
    assert ThirdPartyRole.RECIPIENT.value == "2"
    assert ThirdPartyRole.ORIGINAL_ENTITY.value == "3"
    assert ThirdPartyRole.ADDITIONAL_BUYER.value == "4"
    assert ThirdPartyRole.INVOICE_ISSUER.value == "5"
    assert ThirdPartyRole.PAYER.value == "6"
    assert ThirdPartyRole.JST_SELLER.value == "7"
    assert ThirdPartyRole.JST_SUBUNIT.value == "8"
    assert ThirdPartyRole.VAT_GROUP_SELLER.value == "9"
    assert ThirdPartyRole.VAT_GROUP_MEMBER.value == "10"
    assert ThirdPartyRole.EMPLOYEE.value == "11"
    assert ThirdPartyRole.OTHER.value == "other"

    assert PaymentMethod.MOBILE.value == "7"
    assert not hasattr(PaymentMethod, "COMPENSATION")
    assert TransportKind.INLAND_WATERWAY.value == "8"
    assert not hasattr(TransportKind, "OTHER")


def test_fa3_business_semantics_for_roles_np_ii_payment_and_transport() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    authorized = Party.polish_company(nip="2222222222", name="Przedstawiciel", address="Adres P")
    original_entity = Party.polish_company(nip="3333333333", name="Pierwotny", address="Adres O")
    other_party = Party.foreign_company(
        identifier="EXT-1",
        country_code="US",
        name="Inny",
        address="Adres I",
    )

    invoice = (
        FA3Invoice.basic("FV/SEM/1")
        .issued_on(date(2026, 5, 16))
        .seller(seller)
        .buyer(buyer)
        .authorized_party(authorized, AuthorizedPartyRole.REPRESENTATIVE)
        .add_party(original_entity, ThirdPartyRole.ORIGINAL_ENTITY)
        .add_party(
            replace(other_party, other_role_description="broker techniczny"),
            ThirdPartyRole.OTHER,
        )
        .add_service_line(
            "Usluga art. 100",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("np II"),
        )
        .payment_due(date(2026, 6, 1), method=PaymentMethod.MOBILE)
        .transport("other", other_kind_description="dron")
        .transport(TransportKind.INLAND_WATERWAY)
        .build()
    )

    assert VatClass.from_rate_code("np II").summary_fields[0] == "P_13_9"
    assert VatClass.service_article_100().summary_fields[0] == "P_13_9"
    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")
    assert "<RolaPU>3</RolaPU>" in xml
    assert "<Rola>3</Rola>" in xml
    assert "<RolaInna>1</RolaInna>" in xml
    assert "<OpisRoli>broker techniczny</OpisRoli>" in xml
    assert "<P_13_9>100.00</P_13_9>" in xml
    assert "<P_13_8>" not in xml
    assert "<FormaPlatnosci>7</FormaPlatnosci>" in xml
    assert "<TransportInny>1</TransportInny>" in xml
    assert "<OpisInnegoTransportu>dron</OpisInnegoTransportu>" in xml
    assert "<RodzajTransportu>8</RodzajTransportu>" in xml


def test_other_third_party_role_requires_description() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    other_party = Party.foreign_company(
        identifier="EXT-1",
        country_code="US",
        name="Inny",
        address="Adres I",
    )

    with pytest.raises(ValueError, match="other_role_description"):
        (
            FA3Invoice.basic("FV/SEM/2")
            .issued_on(date(2026, 5, 16))
            .seller(seller)
            .buyer(buyer)
            .add_party(other_party, ThirdPartyRole.OTHER)
            .add_service_line("Usluga", quantity="1", unit_net_price="100")
            .build()
        )


def test_serializer_rejects_other_third_party_role_without_description() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    other_party = replace(
        Party.foreign_company(
            identifier="EXT-1",
            country_code="US",
            name="Inny",
            address="Adres I",
        ),
        role=ThirdPartyRole.OTHER,
    )
    invoice = (
        FA3Invoice.basic("FV/SEM/3")
        .issued_on(date(2026, 5, 16))
        .seller(seller)
        .buyer(buyer)
        .add_service_line("Usluga", quantity="1", unit_net_price="100")
        .build()
    )

    malformed = replace(invoice, additional_parties=(other_party,))
    with pytest.raises(FA3XmlValidationError, match="RolaInna"):
        malformed.to_xml(validate=False)


def test_domain_invoice_builds_discount_annotations_parties_payment_and_attachment_xml() -> None:
    seller = Party.polish_company(
        nip="1234567890",
        name="Sprzedawca",
        address=Address.polish("ul. Prosta 1, 00-001 Warszawa"),
        contacts=(Contact(email="seller@example.com"),),
    )
    buyer = Party.eu_company(
        vat_id="123456789",
        country_code="DE",
        name="Buyer GmbH",
        address=Address.foreign("DE", "Hauptstrasse 1, Berlin"),
    )
    extra = Party.polish_company(
        nip="2222222222",
        name="Odbiorca",
        address=Address.polish("ul. Odbiorcy 2"),
    )
    invoice = (
        FA3Invoice.basic("FV/API/1")
        .issued_on(date(2026, 1, 15))
        .issue_place("Warszawa")
        .seller(seller)
        .buyer(buyer)
        .add_party(extra, ThirdPartyRole.RECIPIENT)
        .add_line(
            "Usługa A",
            quantity="2",
            unit_net_price="100",
            tax=VatClass.xii("12"),
            discount=Discount.percent("10"),
            gtu="GTU_12",
            procedure="WSTO_EE",
            annex_15=True,
        )
        .add_line(
            "Usługa zwolniona",
            quantity="1",
            unit_net_price="50",
            tax=VatClass.exempt("art. 43 ust. 1 ustawy"),
        )
        .annotations(Annotation.split_payment(), Annotation.cash_method())
        .payment(
            PaymentTerms.transfer(
                due_date=date(2026, 1, 31),
                bank_account=BankAccount(number="12345678901234567890123456"),
            )
        )
        .settlement_details(
            Settlement(
                deductions=(SettlementAdjustment.create("10", "Rabat dokumentu"),),
                amount_due=decimal_from_value("241.60", field_name="do_zaplaty"),
            )
        )
        .attachment(
            Attachment(
                (
                    AttachmentBlock(
                        header="Rozliczenie",
                        metadata=(("źródło", "SDK"),),
                        paragraphs=("Opis dodatkowy",),
                        tables=(
                            AttachmentTable(
                                headers=("Nazwa", "Kwota"),
                                rows=(("Rabat", "10.00"),),
                                column_types=("txt", "dec"),
                            ),
                        ),
                    ),
                )
            )
        )
        .build()
    )

    xml = invoice.to_xml().decode("utf-8")

    assert "<KodUE>DE</KodUE>" in xml
    assert "<Podmiot3>" in xml
    # `P_10` to obniżka na JEDNOSTKĘ (10% ze 100 = 10), a `P_11` = 2 × (100 − 10).
    # Semantyka zgodna z oficjalnym `FA_3_Przykład_4.xml`.
    assert "<P_10>10</P_10>" in xml
    assert "<P_11>180.00</P_11>" in xml
    assert "<P_13_" in xml
    assert "<P_14_" in xml
    assert "<P_13_7>50.00</P_13_7>" in xml
    assert "<P_18A>1</P_18A>" in xml
    assert "<P_19A>art. 43 ust. 1 ustawy</P_19A>" in xml
    assert "<RachunekBankowy>" in xml
    assert "<Odliczenia>" in xml
    assert "<Zalacznik>" in xml


def test_domain_correction_and_partial_payment_are_xsd_valid() -> None:
    invoice = (
        FA3Invoice.correction("KOR/API/1")
        .issued_on(date(2026, 2, 1))
        .seller(
            Party.polish_company(
                nip="1234567890",
                name="Sprzedawca",
                address="ul. Prosta 1",
            )
        )
        .buyer(Party.polish_company(nip="1111111111", name="Nabywca", address="ul. Testowa 2"))
        .corrects("FV/API/1", date(2026, 1, 15), reason="Rabat po sprzedaży")
        .add_line(
            "Korekta usługi",
            quantity="1",
            unit_net_price="10",
            tax=VatClass.xii("12"),
            net_amount=decimal_from_value("-10", field_name="netto"),
            vat_amount=decimal_from_value("-2.30", field_name="vat"),
            gross_amount=decimal_from_value("-12.30", field_name="brutto"),
            before_correction=True,
        )
        .payment(
            PaymentTerms(
                partial_payments=(
                    PartialPayment.create("12.30", date(2026, 2, 2), method="przelew"),
                )
            )
        )
        .build()
    )

    xml = invoice.to_xml(xsd_validate=True)

    assert b"<RodzajFaktury>KOR</RodzajFaktury>" in xml
    assert b"<StanPrzed>1</StanPrzed>" in xml
    assert b"<ZaplataCzesciowa>" in xml


def test_variant_factories_return_specific_builders() -> None:
    assert isinstance(FA3Invoice.basic("FV/1"), BasicInvoiceBuilder)
    assert isinstance(FA3Invoice.correction("KOR/1"), CorrectionInvoiceBuilder)
    assert isinstance(FA3Invoice.settlement("ROZ/1"), SettlementInvoiceBuilder)


def test_convenient_basic_builder_uses_enums_and_transaction_sections() -> None:
    invoice = (
        FA3Invoice.basic("FV/BUILDER/1")
        .issued_on(date(2026, 1, 15))
        .seller(Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S"))
        .buyer(Party.eu_company(vat_id="123456789", country_code="DE", name="Buyer", address="B"))
        .add_service_line(
            "Usługa wdrożeniowa",
            quantity="1",
            unit_net_price="1000.00",
            tax=VatClass.standard_23(),
            discount=Discount.percent("10"),
            gtu=GTUCode.GTU_12,
            procedure=LineProcedure.WSTO_EE,
        )
        .split_payment()
        .payment_due(date(2026, 1, 31), method=PaymentMethod.TRANSFER)
        .bank_account("12345678901234567890123456")
        .contract(number="UM/1/2026", date=date(2026, 1, 1))
        .warehouse_document("WZ/1/2026")
        .transport(TransportKind.ROAD, order_number="TR/1")
        .build()
    )

    xml = invoice.to_xml().decode("utf-8")

    assert "<RodzajFaktury>VAT</RodzajFaktury>" in xml
    assert "<FormaPlatnosci>6</FormaPlatnosci>" in xml
    assert "<GTU>GTU_12</GTU>" in xml
    assert "<Procedura>WSTO_EE</Procedura>" in xml
    assert "<WarunkiTransakcji>" in xml
    assert "<Transport>" in xml
    assert "<WZ>WZ/1/2026</WZ>" in xml


def test_domain_line_emits_p_11_vat_without_manual_override() -> None:
    invoice = (
        FA3Invoice.basic("FV/VAT/ROW/1")
        .issued_on(date(2026, 1, 15))
        .seller(Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S"))
        .buyer(Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N"))
        .add_service_line(
            "Usługa",
            quantity="1",
            unit_net_price="100.00",
            tax=VatClass.standard_23(),
        )
        .build()
    )

    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")

    assert "<P_11>100.00</P_11>" in xml
    assert "<P_11Vat>23.00</P_11Vat>" in xml


def test_transaction_terms_allow_explicit_toggle_and_clear() -> None:
    invoice = (
        FA3Invoice.basic("FV/TERMS/1")
        .issued_on(date(2026, 1, 15))
        .seller(Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S"))
        .buyer(Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N"))
        .add_service_line("Usługa", quantity="1", unit_net_price="100.00")
        .transaction_terms(
            delivery_terms="EXW",
            contractual_rate="4.123456",
            contractual_currency="eur",
            intermediary=True,
        )
        .transaction_terms(
            delivery_terms=None,
            contractual_rate=None,
            contractual_currency=None,
            intermediary=False,
        )
        .build()
    )

    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")

    assert invoice.transaction_terms is not None
    assert invoice.transaction_terms.delivery_terms is None
    assert invoice.transaction_terms.contractual_rate is None
    assert invoice.transaction_terms.contractual_currency is None
    assert invoice.transaction_terms.intermediary is False
    assert "<PodmiotPosredniczacy>1</PodmiotPosredniczacy>" not in xml
    assert "<WarunkiDostawy>" not in xml
    assert "<KursUmowny>" not in xml
    assert "<WalutaUmowna>" not in xml


def test_correction_builder_supports_many_refs_corrected_parties_and_before_after() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    invoice = (
        FA3Invoice.correction("KOR/BUILDER/1")
        .issued_on(date(2026, 2, 1))
        .seller(seller)
        .buyer(buyer)
        .corrects_many(
            (
                CorrectionReference("FV/1/2026", date(2026, 1, 1)),
                CorrectionReference("FV/2/2026", date(2026, 1, 2)),
            ),
            reason="Rabat po sprzedaży",
            correction_type=CorrectionType.TAX_BASE_OR_TAX,
        )
        .corrected_seller(seller)
        .with_section(CorrectedAdvanceState.create("10.00", currency_rate="4.12"))
        .with_section(CorrectedAdvanceState.create("10.00", currency_rate="4.12"))
        .corrected_buyer(replace(buyer, buyer_id="BUYER-K"))
        .add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Usługa",
                quantity="1",
                unit_net_price="1000.00",
                tax=VatClass.standard_23(),
            ),
            after=InvoiceLine.service(
                "Usługa",
                quantity="1",
                unit_net_price="900.00",
                tax=VatClass.standard_23(),
            ),
        )
        .build()
    )

    xml = invoice.to_xml().decode("utf-8")

    assert xml.count("<DaneFaKorygowanej>") == 2
    assert "<TypKorekty>1</TypKorekty>" in xml
    assert "<Podmiot1K>" in xml
    assert "<Podmiot2K>" in xml
    assert "<StanPrzed>1</StanPrzed>" in xml


def test_correction_before_after_uses_delta_totals_and_xsd_valid() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")

    invoice = (
        FA3Invoice.correction("KOR/DELTA/1")
        .issued_on(date(2026, 2, 1))
        .seller(seller)
        .buyer(buyer)
        .corrects_invoice(
            number="FV/BASE/1",
            issue_date=date(2026, 1, 15),
            reason="Rabat po sprzedaży",
        )
        .add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Usługa",
                quantity="1",
                unit_net_price="100.00",
                tax=VatClass.standard_23(),
            ),
            after=InvoiceLine.service(
                "Usługa",
                quantity="1",
                unit_net_price="80.00",
                tax=VatClass.standard_23(),
            ),
        )
        .build()
    )

    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")

    assert invoice.total_net == Decimal("-20.00")
    assert invoice.total_vat == Decimal("-4.60")
    assert invoice.total_gross == Decimal("-24.60")
    assert "<P_13_1>-20.00</P_13_1>" in xml
    assert "<P_14_1>-4.60</P_14_1>" in xml
    assert "<P_15>-24.60</P_15>" in xml
    assert "<StanPrzed>1</StanPrzed>" in xml


def test_advance_order_line_auto_recalculates_total_gross_for_multiple_rows() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = Party.polish_company(nip="1111111111", name="Buyer", address="Addr")

    invoice = (
        FA3Invoice.advance("ZAL/ORDER/AUTO/1")
        .issued_on(date(2026, 1, 1))
        .seller(seller)
        .buyer(buyer)
        .order_line("L1", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .order_line("L2", quantity="1", unit_net_price="200", tax=VatClass.standard_23())
        .build()
    )
    xml = invoice.to_xml().decode("utf-8")

    assert invoice.order is not None
    assert invoice.order.total_gross == Decimal("369.00")
    assert "<WartoscZamowienia>369.00</WartoscZamowienia>" in xml


def test_advance_order_explicit_total_is_preserved_after_adding_more_rows() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = Party.polish_company(nip="1111111111", name="Buyer", address="Addr")

    invoice = (
        FA3Invoice.advance("ZAL/ORDER/EXPLICIT/1")
        .issued_on(date(2026, 1, 1))
        .seller(seller)
        .buyer(buyer)
        .order(total_gross="999.99")
        .order_line("L1", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .order_line("L2", quantity="1", unit_net_price="200", tax=VatClass.standard_23())
        .build()
    )
    xml = invoice.to_xml().decode("utf-8")

    assert invoice.order is not None
    assert invoice.order.total_gross == Decimal("999.99")
    assert "<WartoscZamowienia>999.99</WartoscZamowienia>" in xml


def test_settlement_amount_due_must_match_invoice_plus_adjustments() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = Party.polish_company(nip="1111111111", name="Buyer", address="Addr")
    consistent = (
        FA3Invoice.basic("FV/SETTLEMENT/CONSISTENT/1")
        .issued_on(date(2026, 1, 1))
        .seller(seller)
        .buyer(buyer)
        .add_service_line("L1", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .settlement_details(
            Settlement(
                charges=(SettlementAdjustment.create("10", "Charge"),),
                deductions=(SettlementAdjustment.create("3", "Deduction"),),
                amount_due=Decimal("130.00"),
            )
        )
        .build()
    )
    assert "<DoZaplaty>130.00</DoZaplaty>" in consistent.to_xml(xsd_validate=True).decode("utf-8")

    inconsistent_builder = (
        FA3Invoice.basic("FV/SETTLEMENT/INCONSISTENT/1")
        .issued_on(date(2026, 1, 1))
        .seller(seller)
        .buyer(buyer)
        .add_service_line("L1", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .settlement_details(
            Settlement(
                charges=(SettlementAdjustment.create("10", "Charge"),),
                deductions=(SettlementAdjustment.create("3", "Deduction"),),
                amount_due=Decimal("999.00"),
            )
        )
    )
    with pytest.raises(ValueError, match="Rozliczenie niespójne"):
        inconsistent_builder.build()


def test_correction_period_and_invoice_override_are_explicit_only() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")

    base_builder = (
        FA3Invoice.correction("KOR/EXPLICIT/1")
        .issued_on(date(2026, 2, 1))
        .seller(seller)
        .buyer(buyer)
        .corrects_invoice(
            number="FV/BASE/1",
            issue_date=date(2026, 1, 15),
            reason="Rabat po sprzedaży",
        )
        .add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Usługa",
                quantity="1",
                unit_net_price="100.00",
                tax=VatClass.standard_23(),
            ),
            after=InvoiceLine.service(
                "Usługa",
                quantity="1",
                unit_net_price="80.00",
                tax=VatClass.standard_23(),
            ),
        )
    )

    xml_default = base_builder.build().to_xml(xsd_validate=True).decode("utf-8")
    assert "<DaneFaKorygowanej>" in xml_default
    assert "<OkresFaKorygowanej>" not in xml_default
    assert "<NrFaKorygowany>" not in xml_default

    xml_period = (
        base_builder.corrected_period("2026-01").build().to_xml(xsd_validate=True).decode("utf-8")
    )
    assert "<OkresFaKorygowanej>2026-01</OkresFaKorygowanej>" in xml_period
    assert "<NrFaKorygowany>" not in xml_period

    xml_number = (
        base_builder
        .corrected_period("")
        .corrected_invoice_number_override("FV/KOR/POPRAWNY/1")
        .build()
        .to_xml(xsd_validate=True)
        .decode("utf-8")
    )
    assert "<NrFaKorygowany>FV/KOR/POPRAWNY/1</NrFaKorygowany>" in xml_number
    assert "<OkresFaKorygowanej>" not in xml_number

    xml_both = (
        base_builder
        .corrected_period("2026-Q1")
        .corrected_invoice_number_override("FV/KOR/POPRAWNY/2")
        .build()
        .to_xml(xsd_validate=True)
        .decode("utf-8")
    )
    assert "<OkresFaKorygowanej>2026-Q1</OkresFaKorygowanej>" in xml_both
    assert "<NrFaKorygowany>FV/KOR/POPRAWNY/2</NrFaKorygowany>" in xml_both


def test_advance_and_settlement_builders_generate_order_and_references() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    advance = (
        FA3Invoice.advance("ZAL/BUILDER/1")
        .issued_on(date(2026, 1, 10))
        .seller(seller)
        .buyer(buyer)
        .advance_payment(amount="1230.00", tax=VatClass.standard_23())
        .order(total_gross="5000.00")
        .order_line(
            "Usługa",
            quantity="1",
            unit_net_price="4065.04",
            tax=VatClass.standard_23(),
        )
        .build()
    )
    settlement = (
        FA3Invoice.settlement("ROZ/BUILDER/1")
        .issued_on(date(2026, 2, 10))
        .seller(seller)
        .buyer(buyer)
        .settles_advance(invoice_number="ZAL/BUILDER/1")
        .remaining_to_pay("3770.00")
        .add_service_line(
            "Usługa końcowa",
            quantity="1",
            unit_net_price="3065.04",
            tax=VatClass.standard_23(),
        )
        .build()
    )

    advance_xml = advance.to_xml(xsd_validate=True).decode("utf-8")
    settlement_xml = settlement.to_xml(xsd_validate=True).decode("utf-8")

    assert "<RodzajFaktury>ZAL</RodzajFaktury>" in advance_xml
    assert "<ZaliczkaCzesciowa>" in advance_xml
    assert "<P_13_1>1000.00</P_13_1>" in advance_xml
    assert "<P_14_1>230.00</P_14_1>" in advance_xml
    assert "<P_15>1230.00</P_15>" in advance_xml
    assert "<P_15Z>1230.00</P_15Z>" in advance_xml
    assert "<Zamowienie>" in advance_xml
    assert "<ZamowienieWiersz>" in advance_xml
    assert "<RodzajFaktury>ROZ</RodzajFaktury>" in settlement_xml
    assert "<FakturaZaliczkowa>" in settlement_xml
    assert "<DoZaplaty>3770.00</DoZaplaty>" in settlement_xml


def test_advance_payment_business_totals_are_xsd_valid_without_invoice_lines() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    builder = FA3Invoice.advance("ZAL/BIZ/1")
    builder.issued_on(date(2026, 1, 10))
    builder.currency("EUR")
    builder.foreign_currency_rate("4")
    builder.seller(seller)
    builder.buyer(buyer)
    builder.advance_payment(amount="1230.00", tax=VatClass.standard_23())
    builder.advance_payment(amount="100.00", tax=VatClass.exempt("art. 43"))
    invoice = builder.build()

    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")

    assert invoice.total_net == Decimal("1100.00")
    assert invoice.total_vat == Decimal("230.00")
    assert invoice.total_gross == Decimal("1330.00")
    assert "<P_13_1>1000.00</P_13_1>" in xml
    assert "<P_14_1>230.00</P_14_1>" in xml
    assert "<P_14_1W>920.00</P_14_1W>" in xml
    assert "<P_13_7>100.00</P_13_7>" in xml
    assert "<P_15>1330.00</P_15>" in xml
    assert "<P_15Z>1230.00</P_15Z>" in xml
    assert "<P_15Z>100.00</P_15Z>" in xml
    assert "<FaWiersz>" not in xml


def test_foreign_currency_vat_w_fields_are_business_amounts_not_override_deltas() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    foreign_invoice = (
        FA3Invoice.basic("FV/EUR/1")
        .issued_on(date(2026, 1, 10))
        .currency("EUR")
        .foreign_currency_rate("4")
        .seller(seller)
        .buyer(buyer)
        .add_service_line("Usluga", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    pln_override_invoice = (
        FA3Invoice.basic("FV/PLN/OVERRIDE/1")
        .issued_on(date(2026, 1, 10))
        .seller(seller)
        .buyer(buyer)
        .add_service_line(
            "Usluga",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.standard_23(),
            vat_amount=decimal_from_value("30.00", field_name="vat"),
        )
        .build()
    )

    foreign_xml = foreign_invoice.to_xml(xsd_validate=True).decode("utf-8")
    pln_xml = pln_override_invoice.to_xml(xsd_validate=True).decode("utf-8")

    assert "<P_14_1>23.00</P_14_1>" in foreign_xml
    assert "<P_14_1W>92.00</P_14_1W>" in foreign_xml
    assert "<KursWalutyZ>4</KursWalutyZ>" in foreign_xml
    assert "<P_14_1>30.00</P_14_1>" in pln_xml
    assert "<P_14_1W>" not in pln_xml


def test_full_typed_sdk_sections_are_xsd_valid() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    invoice = (
        FA3Invoice.basic("FV/FULL/1")
        .issued_on(date(2026, 3, 1))
        .seller(seller)
        .buyer(buyer)
        .foreign_currency_rate("4.123456")
        .fiscal_receipt_invoice()
        .related_party_transaction()
        .additional_description("projekt", "FA3 full typed SDK")
        .with_section(AdditionalDescription.key_value("kanał", "API"))
        .new_transport(
            NewTransportMeans(
                allowed_date=date(2026, 2, 20),
                row_number=1,
                kind="land",
                mileage="1000",
                serial_number="VIN123",
                make="Marka",
                model="Model",
            )
        )
        .add_goods_line(
            "Pojazd",
            quantity="1",
            unit_net_price="100000",
            unit_gross_price=decimal_from_value("123000", field_name="brutto"),
            tax=VatClass.standard_23(),
            identifiers=LineIdentifiers(
                unique_id="line-1",
                internal_index="SKU-1",
                gtin="1234567890123",
                pkwiu="62.01",
                cn="8703",
                pkob="123",
            ),
        )
        .payment_due_description(14, "dni", "data wystawienia")
        .payment(
            PaymentTerms(
                due_terms=(PaymentDue.description(14, "dni", "data wystawienia"),),
                method=PaymentMethod.TRANSFER.value,
                bank_accounts=(BankAccount(number="12345678901234567890123456"),),
                payment_link="https://pay.example.com/pay?IPKSeF=123ABCDEFGHIJ",
                ipksef="123ABCDEFGHIJ",
            )
        )
        .contract(number="UM/FULL/1", date=date(2026, 2, 1))
        .order_reference(number="ZAM/FULL/1", date=date(2026, 2, 2))
        .batch_number("PARTIA-1")
        .transaction_terms(
            delivery_terms="DAP",
            contractual_rate="4.123456",
            contractual_currency="EUR",
            intermediary=True,
        )
        .transport(
            TransportKind.ROAD,
            carrier=buyer,
            order_number="TR/FULL/1",
            cargo_description="1",
            package_unit="paleta",
            ship_from=Address.polish("Magazyn A"),
            ship_to=Address.polish("Magazyn B"),
        )
        .excise_refund()
        .footer_info("Stopka faktury")
        .registry(Registry.krs_entry("0000123456", full_name="Sprzedawca sp. z o.o."))
        .attachment(
            Attachment(
                (
                    AttachmentBlock(
                        header="Załącznik",
                        metadata=(("typ", "pełny"),),
                        tables=(
                            AttachmentTable(
                                headers=("Nazwa", "Kwota"),
                                rows=(("Pojazd", "123000.00"),),
                                metadata=(("źródło", "SDK"),),
                                column_types=("txt", "dec"),
                                footer=("123000.00",),
                            ),
                        ),
                    ),
                )
            )
        )
        .build()
    )

    xml = invoice.to_xml().decode("utf-8")

    assert "<DodatkowyOpis>" in xml
    assert "<NowySrodekTransportu>" in xml
    assert "<TerminOpis>" in xml
    assert "<Stopka>" in xml
    assert "<TMetaDane>" in xml


def test_raw_xml_extension_is_rejected_in_full_typed_sdk() -> None:
    with pytest.raises(ValueError, match="RawXmlExtension"):
        (
            FA3Invoice.basic("FV/RAW/1")
            .issued_on(date(2026, 1, 1))
            .seller(Party.polish_company(nip="1234567890", name="Sprzedawca", address="A"))
            .buyer(Party.polish_company(nip="1111111111", name="Nabywca", address="B"))
            .add_service_line("Usługa", quantity="1", unit_net_price="100")
            .raw_extension("/Faktura/Stopka", "<Stopka />")
            .build()
        )


def test_builder_fluent_paths_cover_annotations_payments_and_typed_sections() -> None:
    seller = replace(
        Party.polish_company(
            nip="1234567890",
            name="Sprzedawca",
            address=Address.polish("Adres S", "Lokal 2", gln="5901234123457"),
            contacts=(Contact(email="seller@example.com", phone="123456789"),),
        ),
        taxpayer_prefix="PL",
        taxpayer_status="1",
        eori="EORI-S",
    )
    buyer = replace(
        Party.without_tax_id(name="Nabywca", address=Address.foreign("DE", "Buyer street")),
        correspondence_address=Address.foreign("DE", "Correspondence", gln="4001234567890"),
        contacts=(Contact(phone="987654321"),),
        customer_number="CUST-1",
        buyer_id="BUYER-1",
    )
    extra = replace(
        Party.foreign_company(
            identifier="EXT-1",
            country_code="US",
            name="External",
            address=Address.foreign("US", "External street"),
        ),
        role=ThirdPartyRole.OTHER,
        other_role_description="custom role",
        share=Decimal("25"),
        customer_number="EXTRA-1",
    )
    authorized = replace(
        Party.polish_company(nip="2222222222", name="Pełnomocnik", address="Adres PU"),
        authorized_role=AuthorizedPartyRole.BAILIFF,
        contacts=(Contact(phone="555555555"),),
    )
    block = AttachmentBlock(
        header="Blok",
        metadata=(("meta", "value"),),
        paragraphs=("Paragraf",),
        tables=(
            AttachmentTable(
                headers=("A", "B"),
                rows=(("1", "2"),),
                metadata=(("zrodlo", "SDK"),),
                column_types=("txt", "txt"),
                description="Tabela",
                footer=("Suma",),
            ),
        ),
    )

    invoice = (
        FA3Invoice.basic("FV/COV/1")
        .issued_on(date(2026, 4, 1))
        .currency("eur")
        .issue_place("Kraków")
        .sale_date(date(2026, 3, 31))
        .seller(seller)
        .buyer(buyer)
        .add_party(extra, ThirdPartyRole.OTHER)
        .authorized_party(authorized, AuthorizedPartyRole.BAILIFF)
        .add_goods_line(
            "Towar",
            quantity="2",
            unit_net_price="50",
            tax=VatClass.from_rate_code("4"),
            discount=Discount.amount("5"),
            identifiers=LineIdentifiers(
                unique_id="u1",
                internal_index="SKU",
                gtin="5901234123457",
                pkwiu="62.01",
                cn="1234",
                pkob="567",
            ),
            unit_gross_price=decimal_from_value("61.50", field_name="gross"),
            net_amount=decimal_from_value("95", field_name="net"),
            gross_amount=decimal_from_value("98.80", field_name="gross"),
            vat_amount=decimal_from_value("3.80", field_name="vat"),
            excise_amount=decimal_from_value("1.23", field_name="excise"),
            gtu=GTUCode.GTU_01,
            procedure=LineProcedure.IED,
            currency_rate=decimal_from_value("4.123456", field_name="currency_rate"),
            annex_15=True,
        )
        .cash_method()
        .self_billing()
        .reverse_charge()
        .margin(MarginProcedure.ART)
        .exemption("art. 43")
        .payment_due(date(2026, 4, 15), method=PaymentMethod.CARD)
        .payment_due_description(7, "dni", "odbiór")
        .paid(date(2026, 4, 2))
        .bank_account(
            "12345678901234567890123456",
            swift="TESTPLPW",
            own_bank_account="1",
            bank_name="Bank",
            description="konto główne",
        )
        .bank_account("99999999999999999999999999", factor=True)
        .cash_discount("2% za szybką płatność", "2.00")
        .transaction_terms(
            delivery_terms="EXW",
            contractual_rate="4.123456",
            contractual_currency="eur",
            intermediary=True,
        )
        .contract(number="UM/COV/1", date=date(2026, 3, 1))
        .order_reference(number="ZAM/COV/1", date=date(2026, 3, 2))
        .batch_number("PARTIA-COV")
        .transport(
            "other",
            other_kind_description="dron",
            carrier=buyer,
            order_number="TR/COV/1",
            other_cargo_description="ładunek specjalny",
            package_unit="karton",
            started_at=datetime(2026, 4, 1, 8, 30),
            finished_at=datetime(2026, 4, 1, 12, 0),
            ship_from=Address.polish("Magazyn A"),
            ship_via=(Address.polish("Hub"),),
            ship_to=Address.polish("Magazyn B"),
        )
        .additional_description("key", "value")
        .foreign_currency_rate("4.123456")
        .fiscal_receipt_invoice(False)
        .related_party_transaction(False)
        .excise_refund(False)
        .new_transport(
            NewTransportMeans(
                allowed_date=date(2026, 3, 1),
                row_number=1,
                kind="land",
                mileage="1000",
                serial_number="VIN123",
                make="Marka",
                model="Model",
            ),
            intra_eu=True,
        )
        .with_section(AdditionalDescription.key_value("second", "value"))
        .with_section(Footer.info("Info stopki"))
        .with_section(Footer.registry(Registry.regon_entry("123456789")))
        .with_section(ExciseRefund())
        .footer_info("Druga stopka")
        .registry(Registry.bdo_entry("000012345"))
        .attachment_block(block)
        .build()
    )

    xml = invoice.to_xml().decode("utf-8")

    assert "<PrefiksPodatnika>PL</PrefiksPodatnika>" in xml
    assert "<BrakID>1</BrakID>" in xml
    assert "<AdresKoresp>" in xml
    assert "<TelefonPU>555555555</TelefonPU>" in xml
    assert "<RolaInna>1</RolaInna>" in xml
    assert "<Zaplacono>1</Zaplacono>" in xml
    assert "<RachunekBankowyFaktora>" in xml
    assert "<Skonto>" in xml
    assert "<TransportInny>1</TransportInny>" in xml
    assert "<WysylkaPrzez>" in xml
    assert any(
        marker in xml for marker in ("<P_22B1>", "<P_22B2>", "<P_22B3>", "<P_22B4>")
    )
    assert "<P_22B>" in xml
    assert "<BDO>000012345</BDO>" in xml
    assert "<Tekst>" in xml
    assert "<Suma>" in xml

    with pytest.raises(TypeError, match="Unsupported FA\\(3\\) typed section"):
        FA3Invoice.basic("FV/UNSUPPORTED/1").with_section(object())

    simplified_builder = FA3Invoice.simplified("UPR/OK/1")
    simplified_builder.issued_on(date(2026, 1, 1))
    simplified_builder.seller(seller)
    simplified_builder.buyer(buyer)
    simplified_builder.add_service_line("Line", quantity="1", unit_net_price="100")
    simplified_builder.as_simplified_receipt_like()
    simplified = simplified_builder.build()
    assert simplified.total_gross == Decimal("123.00")

    triangular_builder = FA3Invoice.basic("FV/TRI/1")
    triangular_builder._merge_annotations(Annotation.simplified_triangular())
    assert triangular_builder._annotations.simplified_triangular is True


def test_domain_validation_and_value_object_branches() -> None:
    assert PartyIdentifier.internal("INT").validate("party.identifier") == []
    assert PartyIdentifier.none().validate("party.identifier") == []
    assert PartyIdentifier.foreign("EXT", country_code="us").country_code == "US"
    assert PartyIdentifier.eu_vat("", "123").validate("party.identifier")
    assert PartyIdentifier.polish_nip("").validate("party.identifier")
    assert Address.polish("").validate("party.address")
    assert Address("", country_code="").validate("party.address")
    assert Contact().validate("party.contact")
    assert Party.foreign_company(
        identifier="ABC",
        country_code="us",
        name="Foreign",
        address="Addr",
    ).identifier.country_code == "US"

    invalid_party = replace(
        Party.polish_company(nip="1234567890", name="", address=None),
        correspondence_address=Address("", country_code=""),
        contacts=(Contact(),),
        share=Decimal("150"),
    )
    issues = invalid_party.validate("party", address_required=True)
    assert any("nazwa" in issue.message for issue in issues)
    assert any("udział" in issue.message for issue in issues)

    assert Discount.percent("10").amount_for(Decimal("100")) == Decimal("10.00")
    assert Discount.amount("3").amount_for(Decimal("100")) == Decimal("3.00")
    assert Discount.amount("-1").validate("discount")
    assert Discount.percent("101").validate("discount")

    assert VatClass.from_vat_rate("zw").xml_rate == "zw"
    assert VatClass.from_vat_rate("23").xml_rate == "23"
    assert VatClass.from_vat_rate("22").xml_rate == "22"
    assert VatClass.from_vat_rate("8").xml_rate == "8"
    assert VatClass.from_vat_rate("7").xml_rate == "7"
    assert VatClass.from_vat_rate("5").xml_rate == "5"
    assert VatClass.from_vat_rate("0").xml_rate == "0 KR"
    # Stawki spoza TStawkaPodatku nie mogą być cicho przepuszczane do P_12.
    with pytest.raises(ValueError, match="(?i)nieobs"):
        VatClass.from_vat_rate("17")
    assert VatClass.from_vat_rate("4").summary_fields[0] == "P_13_4"
    assert VatClass.from_vat_rate("3").summary_fields[0] == "P_13_4"
    assert VatClass.from_rate_code("0 WDT").summary_fields[0] == "P_13_6_2"
    assert VatClass.from_rate_code("0 EX").summary_fields[0] == "P_13_6_3"
    assert VatClass.from_rate_code("oo").xml_rate == "oo"
    assert VatClass.from_rate_code("np II").xml_rate == "np II"
    assert VatClass.from_rate_code("3").xml_rate == "3"
    assert VatClass.outside_country().xml_rate == "np I"
    # Procedura marży nie podaje stawki — podstawa jest marża, nie obrót.
    assert VatClass.margin().xml_rate is None
    assert VatClass.xii("12").xii_rate == Decimal("12")
    with pytest.raises(ValueError, match="Nieobsługiwana"):
        VatClass.from_rate_code("bad")

    bad_line = InvoiceLine.service("", quantity="0", unit_net_price="-1")
    assert bad_line.validate("line")
    corrected = InvoiceLine.corrected_before("Before", quantity="1", unit_net_price="10")
    assert corrected.before_correction is True
    after_line = InvoiceLine.corrected_after("After", quantity="1", unit_net_price="10")
    assert after_line.before_correction is False

    line = InvoiceLine.service(
        "Summary",
        quantity="2",
        unit_net_price="100",
        tax=VatClass.standard_23(),
        discount=Discount.percent("10"),
    )
    summary = TaxSummary.from_lines((line,))
    assert summary.gross_total == Decimal("221.40")
    assert summary.lines[0].net_field == "P_13_1"


def test_invoice_validation_branches_and_legacy_builder_helpers() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = Party.polish_company(nip="1111111111", name="Buyer", address="Addr")
    line = InvoiceLine.service("Line", quantity="1", unit_net_price="100")

    invoice = FA3Invoice(
        invoice_number="",
        issue_date=None,  # type: ignore[arg-type]
        seller=replace(seller, address=None),
        buyer=replace(buyer, is_jst_subunit=True, is_vat_group_member=True),
        lines=(),
        additional_parties=(replace(buyer, role=None),),
        authorized_party=replace(seller, authorized_role=None),
        raw_extensions=(),
    )

    messages = [issue.message for issue in invoice.validate().errors]
    assert any("numer jest wymagany" in message for message in messages)
    assert any("data jest wymagana" in message for message in messages)
    assert any("co najmniej jednej pozycji" in message for message in messages)
    assert any("rola jest wymagana" in message for message in messages)
    assert any("JST wymaga" in message for message in messages)
    assert any("GV wymaga" in message for message in messages)

    correction = replace(
        invoice,
        invoice_number="KOR/1",
        issue_date=date(2026, 1, 1),
        seller=seller,
        buyer=buyer,
        lines=(line,),
        kind=FA3InvoiceKind.CORRECTION,
        additional_parties=(),
        authorized_party=None,
    )
    assert any("przyczyna korekty" in issue.message for issue in correction.validate().errors)
    assert any("fakturę korygowaną" in issue.message for issue in correction.validate().errors)

    settlement = replace(
        correction,
        kind=FA3InvoiceKind.SETTLEMENT,
        correction_reason=None,
        corrected_invoices=(),
    )
    assert any("fakturę zaliczkową" in issue.message for issue in settlement.validate().errors)

    raw = replace(
        settlement,
        kind=FA3InvoiceKind.BASIC,
        advance_invoices=(),
        raw_extensions=(object(),),  # type: ignore[arg-type]
    )
    assert any("RawXmlExtension" in issue.message for issue in raw.validate().errors)
    assert replace(raw, lines=(line,), raw_extensions=()).total_net == Decimal("100.00")
    assert replace(raw, lines=(line,), raw_extensions=()).total_vat == Decimal("23.00")

    builder = (
        FA3InvoiceBuilderV2("FV/V2/1", FA3InvoiceKind.BASIC)
        .issued_on(date(2026, 1, 1))
        .currency("eur")
        .issue_place("Warszawa")
        .sale_date(date(2026, 1, 2))
        .seller(seller)
        .buyer(buyer)
        .add_party(replace(buyer, role=ThirdPartyRole.RECIPIENT), ThirdPartyRole.RECIPIENT)
        .authorized_party(seller, AuthorizedPartyRole.REPRESENTATIVE)
        .add_line("Line", quantity="1", unit_net_price="100")
        .annotations(Annotation.self_billing())
        .annotation_set(AnnotationSet.default())
        .payment(PaymentTerms.transfer(due_date=date(2026, 2, 1)))
        .settlement_details(Settlement(charges=(SettlementAdjustment.create("1", "charge"),)))
        .attachment(Attachment.text("Header", "Paragraph"))
    )
    assert builder.validate().ok
    assert b"<RodzajFaktury>VAT</RodzajFaktury>" in builder.to_xml()

    correction_builder_v2 = FA3InvoiceBuilderV2("KOR/V2/1", FA3InvoiceKind.CORRECTION)
    assert correction_builder_v2.corrected_period("2026-01") is correction_builder_v2
    assert (
        correction_builder_v2.corrected_invoice_number_override("FV/KOR/POPRAWNY/1")
        is correction_builder_v2
    )

    invalid_builder = FA3InvoiceBuilderV2("", FA3InvoiceKind.BASIC)
    assert not invalid_builder.validate().ok


def test_correction_and_settlement_variant_edge_paths() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = Party.polish_company(nip="1111111111", name="Buyer", address="Addr")

    allowed_builder = FA3Invoice.simplified("UPR/LIMIT/OK")
    allowed_builder.issued_on(date(2026, 1, 1))
    allowed_builder.seller(seller)
    allowed_builder.buyer(buyer)
    allowed_builder.add_service_line(
        "Line",
        quantity="1",
        unit_net_price="450",
        tax=VatClass.exempt("art. 113"),
    )
    allowed_builder.as_simplified_receipt_like()
    allowed_invoice = allowed_builder.build()
    assert allowed_invoice.total_gross == Decimal("450.00")

    limited_builder = FA3Invoice.simplified("UPR/LIMIT/1")
    limited_builder.issued_on(date(2026, 1, 1))
    limited_builder.seller(seller)
    limited_builder.buyer(buyer)
    limited_builder.add_service_line("Line", quantity="1", unit_net_price="451")
    limited_builder.as_simplified_receipt_like()
    with pytest.raises(ValueError, match="450 PLN"):
        limited_builder.build()

    foreign_currency_builder = FA3Invoice.simplified("UPR/LIMIT/EUR")
    foreign_currency_builder.issued_on(date(2026, 1, 1))
    foreign_currency_builder.currency("EUR")
    foreign_currency_builder.seller(seller)
    foreign_currency_builder.buyer(buyer)
    foreign_currency_builder.add_service_line("Line", quantity="1", unit_net_price="100")
    foreign_currency_builder.as_simplified_receipt_like()
    with pytest.raises(ValueError, match="wymaga waluty PLN"):
        foreign_currency_builder.build()

    correction_builder = FA3Invoice.advance_correction("KOR/ZAL/1")
    correction_builder.issued_on(date(2026, 2, 1))
    correction_builder.seller(seller)
    correction_builder.buyer(buyer)
    correction_builder.corrects_invoice(
        number="ZAL/1",
        issue_date=date(2026, 1, 1),
        reason="Correction",
        correction_type=CorrectionType.OTHER,
        ksef_number="1111111111-20260101-AAAAAA-BBBBBB-01",
    )
    correction_builder.correction_type(CorrectionType.NO_TAX_IMPACT)
    correction_builder.corrected_advance_state("100", currency_rate="4.123456")
    correction_builder.advance_payment(amount="50", paid_on=date(2026, 1, 2), currency_rate="4.2")
    correction = correction_builder.build()
    correction_xml = correction.to_xml().decode("utf-8")
    assert "<NrKSeF>1</NrKSeF>" in correction_xml
    assert "<P_15ZK>100.00</P_15ZK>" in correction_xml
    assert "<KursWalutyZK>4.123456</KursWalutyZK>" in correction_xml
    assert "<KursWalutyZW>4.2</KursWalutyZW>" in correction_xml

    settlement_builder = FA3Invoice.settlement_correction("KOR/ROZ/1")
    settlement_builder.issued_on(date(2026, 2, 1))
    settlement_builder.seller(seller)
    settlement_builder.buyer(buyer)
    settlement_builder.corrects_invoice(
        number="ROZ/1",
        issue_date=date(2026, 1, 1),
        reason="Correction",
    )
    settlement_builder.settles_advances(
        (("ZAL/1", None), (None, "1111111111-20260101-AAAAAA-BBBBBB-01"))
    )
    settlement_builder.document_discount("10", reason="Discount")
    settlement_builder.remaining_to_pay("113")
    settlement_builder.add_service_line("Line", quantity="1", unit_net_price="100")
    settlement = settlement_builder.build()
    settlement_xml = settlement.to_xml().decode("utf-8")
    assert settlement_xml.count("<FakturaZaliczkowa>") == 2
    assert "<NrKSeFFaZaliczkowej>" in settlement_xml
    assert "<SumaOdliczen>10.00</SumaOdliczen>" in settlement_xml


def test_order_lines_internal_ids_default_transport_and_settle_amount_xml() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    # `IDWew` występuje wyłącznie w `TPodmiot3` - w `TPodmiot2` (nabywca) schemat
    # dopuszcza tylko NIP/KodUE+NrVatUE/KodKraju+NrID/BrakID, więc identyfikator
    # wewnętrzny niesie dodatkowy podmiot (Podmiot3) z rolą 8 (JST).
    buyer = Party.without_tax_id(name="Internal buyer", address="Addr")
    internal_party = replace(
        Party.without_tax_id(name="Internal party", address="Addr"),
        identifier=PartyIdentifier.internal("1111111111-00001"),
        role="8",
    )

    advance = (
        FA3Invoice.advance("ZAL/ORDER/1")
        .issued_on(date(2026, 1, 1))
        .seller(seller)
        .buyer(buyer)
        .add_party(internal_party, role="8")
        .advance_payment(amount="10")
        .order(total_gross="123")
        .order_line(
            "Order line",
            quantity="2",
            unit_net_price="50",
            tax=VatClass.xii("12"),
            discount=Discount.percent("10"),
            identifiers=LineIdentifiers(
                unique_id="order-line-1",
                internal_index="SKU-Z",
                gtin="5901234123457",
                pkwiu="62.01",
                cn="1234",
                pkob="5678",
            ),
            gtu=GTUCode.GTU_03,
            procedure=OrderLineProcedure.WSTO_EE,
            excise_amount="3.50",
            annex_15=True,
            before_correction=True,
        )
        .transaction_terms()
        .build()
    )
    advance = replace(
        advance,
        transaction_terms=TransactionTerms(transports=(Transport(),)),
        settlement_data=Settlement(amount_to_settle=Decimal("50.00")),
    )
    xml = advance.to_xml().decode("utf-8")

    assert "<IDWew>1111111111-00001</IDWew>" in xml
    assert "<DoRozliczenia>50.00</DoRozliczenia>" in xml
    assert "<RodzajTransportu>3</RodzajTransportu>" in xml
    assert "<UU_IDZ>order-line-1</UU_IDZ>" in xml
    assert "<IndeksZ>SKU-Z</IndeksZ>" in xml
    assert "<GTINZ>5901234123457</GTINZ>" in xml
    assert "<PKWiUZ>62.01</PKWiUZ>" in xml
    assert "<CNZ>1234</CNZ>" in xml
    assert "<PKOBZ>5678</PKOBZ>" in xml
    assert "<P_12Z_XII>12</P_12Z_XII>" in xml
    assert "<P_12Z_Zal_15>1</P_12Z_Zal_15>" in xml
    assert "<GTUZ>GTU_03</GTUZ>" in xml
    assert "<ProceduraZ>WSTO_EE</ProceduraZ>" in xml
    assert "<KwotaAkcyzyZ>3.50</KwotaAkcyzyZ>" in xml
    assert "<StanPrzedZ>1</StanPrzedZ>" in xml


def test_order_line_direct_enums_are_normalized_in_order_xml() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = Party.polish_company(nip="1111111111", name="Buyer", address="Addr")
    order_line = OrderLine(
        description="Order direct enum",
        quantity=Decimal("1"),
        unit_net_price=Decimal("100"),
        tax=VatClass.standard_23(),
        gtu=GTUCode.GTU_03,
        procedure=OrderLineProcedure.WSTO_EE,
    )
    invoice = (
        FA3Invoice.advance("ZAL/ORDER/ENUM/1")
        .issued_on(date(2026, 1, 1))
        .seller(seller)
        .buyer(buyer)
        .order(total_gross="123")
        .build()
    )
    invoice = replace(invoice, order=invoice.order and replace(invoice.order, lines=(order_line,)))
    xml = invoice.to_xml().decode("utf-8")

    assert "<GTUZ>GTU_03</GTUZ>" in xml
    assert "<ProceduraZ>WSTO_EE</ProceduraZ>" in xml


def test_section_factories_xsd_map_and_audit_edges(tmp_path: Path) -> None:
    assert AdvancePayment.partial("10", paid_on=date(2026, 1, 1)).amount == Decimal("10")
    assert CorrectedAdvanceState.create("10").currency_rate is None
    assert OrderLine.create(
        "Order",
        quantity="1",
        unit_net_price="100",
        gtu=GTUCode.GTU_02,
        procedure=OrderLineProcedure.IED,
        identifiers=LineIdentifiers(unique_id="order-1"),
        excise_amount="2",
        annex_15=True,
        before_correction=True,
    ).effective_vat_amount == Decimal("23.00")
    assert (
        OrderLine.create(
            "Order exempt",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.exempt("zw"),
        ).effective_vat_amount
        == Decimal("0.00")
    )
    assert Transport.create(
        None,
        ship_via=(Address.polish("Via"),),
    ).kind is None
    assert TransactionTerms(intermediary=True).intermediary is True
    assert PaymentDue.date(date(2026, 1, 1)).due_date == date(2026, 1, 1)

    assert SUPPORTED_BUILDER_PATHS["/Faktura"].startswith("full typed")
    assert RAW_EXTENSION_PATHS == {}
    assert UNSUPPORTED_PATHS == {}

    no_invoice_schema = tmp_path / "no-faktura.xsd"
    no_invoice_schema.write_text(
        '<xsd:schema xmlns:xsd="http://www.w3.org/2001/XMLSchema" />',
        encoding="utf-8",
    )
    assert parse_fa3_xsd_elements(no_invoice_schema) == []

    class FakeResolver:
        def resolve_filename(self, filename: str, context: object) -> tuple[str, object]:
            return filename, context

    class FakeEtree:
        Resolver = FakeResolver

    resolver = _schema_resolver(FakeEtree)
    with pytest.raises(FA3XmlValidationError, match="bundlowanych"):
        resolver.resolve("unknown.xsd", None, object())


def test_builder_section_error_and_attachment_helpers_cover_edges() -> None:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")

    builder = (
        FA3Invoice.basic("FV/EDGE/ATTACH")
        .issued_on(date(2026, 2, 1))
        .seller(seller)
        .buyer(buyer)
        .add_service_line("Srv", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
    )

    with pytest.raises(TypeError, match="Unsupported FA\\(3\\) typed section"):
        builder.with_section(object())

    invoice = (
        builder.attachment_text("Notatka", "Akapit 1", "Akapit 2")
        .attachment_table(
            header="Tabela",
            columns=("Nazwa", "Kwota"),
            rows=(("Pozycja", "100.00"),),
            description="Opis",
        )
        .build()
    )
    xml = invoice.to_xml().decode("utf-8")
    assert "<ZNaglowek>Tabela</ZNaglowek>" in xml
    assert "<NKom>Nazwa</NKom>" in xml
    assert "<WKom>100.00</WKom>" in xml


def test_serializer_error_and_remaining_xml_branches() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = Party.polish_company(nip="1111111111", name="Buyer", address="Addr")

    invalid = FA3Invoice(
        invoice_number="",
        issue_date=date(2026, 1, 1),
        seller=seller,
        buyer=buyer,
        lines=(),
    )
    with pytest.raises(FA3XmlValidationError, match="co najmniej jednej pozycji"):
        invalid.to_xml()

    bad_seller = replace(
        seller,
        identifier=PartyIdentifier.foreign("SELLER", country_code="DE"),
    )
    with pytest.raises(FA3XmlValidationError, match="Podmiot1"):
        replace(
            invalid,
            invoice_number="FV/BAD/1",
            seller=bad_seller,
            lines=(InvoiceLine.service("Line", quantity="1", unit_net_price="100"),),
        ).to_xml(validate=False)

    period_invoice = (
        FA3Invoice.basic("FV/PERIOD/1")
        .issued_on(date(2026, 1, 1))
        .period(date(2026, 1, 1), date(2026, 1, 31))
        .seller(seller)
        .buyer(buyer)
        .add_service_line(
            "Line",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.xii("12"),
            unique_id="line-period-1",
            service_date=date(2026, 1, 15),
        )
        .payment(
            PaymentTerms(
                partial_payments=(
                    PartialPayment.create(
                        "10",
                        date(2026, 1, 2),
                        method=PaymentMethod.CASH.value,
                    ),
                ),
                due_dates=(date(2026, 2, 1),),
                method=PaymentMethod.CASH.value,
            )
        )
        .build()
    )
    xml = period_invoice.to_xml().decode("utf-8")
    assert "<OkresFa>" in xml
    assert "<UU_ID>line-period-1</UU_ID>" in xml
    assert "<P_6A>2026-01-15</P_6A>" in xml
    assert "<P_12_XII>12</P_12_XII>" in xml
    assert "<FormaPlatnosci>1</FormaPlatnosci>" in xml
    assert "<ZnacznikZaplatyCzesciowej>1</ZnacznikZaplatyCzesciowej>" in xml
    assert "<PlatnoscInna>1</PlatnoscInna>" not in xml


def test_partial_payment_marker_uses_total_gross_to_select_1_or_2() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = Party.polish_company(nip="1111111111", name="Buyer", address="Addr")

    fully_paid = (
        FA3Invoice.basic("FV/PARTIAL/MARKER/2")
        .issued_on(date(2026, 1, 1))
        .seller(seller)
        .buyer(buyer)
        .add_service_line("Line", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .partially_paid("60", date(2026, 1, 2), method=PaymentMethod.TRANSFER)
        .partially_paid("63", date(2026, 1, 3), method=PaymentMethod.CARD)
        .build()
    )
    fully_paid_xml = fully_paid.to_xml().decode("utf-8")
    assert "<ZnacznikZaplatyCzesciowej>2</ZnacznikZaplatyCzesciowej>" in fully_paid_xml

    partially_paid = (
        FA3Invoice.basic("FV/PARTIAL/MARKER/1")
        .issued_on(date(2026, 1, 1))
        .seller(seller)
        .buyer(buyer)
        .add_service_line("Line", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .partially_paid("100", date(2026, 1, 2), method=PaymentMethod.TRANSFER)
        .build()
    )
    partially_paid_xml = partially_paid.to_xml().decode("utf-8")
    assert "<ZnacznikZaplatyCzesciowej>1</ZnacznikZaplatyCzesciowej>" in partially_paid_xml


def _draft(
    invoice_number: str,
    *,
    kind: FA3InvoiceKind = FA3InvoiceKind.BASIC,
    **extra: Any,
) -> FA3Draft:
    builder = FA3InvoiceBuilder(
        invoice_number=invoice_number,
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
        kind=kind,
        currency="PLN",
        issue_place="Warszawa",
        **extra,
    )
    builder.add_line("Usługa", quantity="1", unit_net_price="100", vat_rate="23")
    return builder.build()

def _audit_evidence_xml_cases() -> dict[str, bytes]:
    evidence: dict[str, bytes] = {}
    for kind, code, extra in ALL_INVOICE_KIND_CASES:
        draft = _draft(f"FV/AUD/{code}", kind=kind, **extra)
        evidence[f"kind:{kind.value}"] = draft.to_xml(xsd_validate=True)
    evidence["typed:full"] = _audit_attachment_invoice().to_xml(xsd_validate=True)
    evidence["typed:coverage"] = _audit_coverage_invoice().to_xml(xsd_validate=True)
    evidence["typed:coverage-rich"] = _audit_coverage_invoice_rich().to_xml(xsd_validate=True)
    evidence["typed:correction-parties"] = _audit_correction_parties_invoice().to_xml(
        xsd_validate=True
    )
    evidence["typed:order"] = _audit_order_invoice().to_xml(xsd_validate=True)
    evidence["typed:sections"] = _audit_sections_invoice().to_xml(xsd_validate=True)
    evidence["typed:full-strict"] = _audit_full_typed_strict_invoice().to_xml(
        xsd_validate=True
    )
    evidence["typed:convenient"] = _audit_convenient_builder_invoice().to_xml(
        xsd_validate=True
    )
    evidence["typed:period"] = _audit_period_invoice().to_xml(xsd_validate=True)
    evidence["typed:multi-vat"] = _audit_multi_vat_invoice().to_xml(xsd_validate=True)
    evidence["typed:order-detailed"] = _audit_order_detailed_invoice().to_xml(xsd_validate=True)
    evidence["typed:new-transport-variants"] = _audit_new_transport_variants_invoice().to_xml(
        xsd_validate=True
    )
    evidence["typed:margin-travel"] = _audit_margin_variant_invoice("travel").to_xml(
        xsd_validate=True
    )
    evidence["typed:margin-used"] = _audit_margin_variant_invoice("used_goods").to_xml(
        xsd_validate=True
    )
    evidence["typed:margin-art"] = _audit_margin_variant_invoice("art").to_xml(
        xsd_validate=True
    )
    evidence["typed:margin-collectibles"] = _audit_margin_variant_invoice("collectibles").to_xml(
        xsd_validate=True
    )
    evidence["typed:party-extended"] = _audit_party_extended_invoice().to_xml(xsd_validate=True)
    evidence["typed:correction-ksef"] = _audit_correction_ksef_invoice().to_xml(xsd_validate=True)
    evidence["typed:settlement-charges"] = _audit_settlement_charges_invoice().to_xml(
        xsd_validate=True
    )
    evidence["typed:advance-currency"] = _audit_advance_currency_invoice().to_xml(xsd_validate=True)
    evidence["typed:partial-payment-other"] = _audit_partial_payment_other_invoice().to_xml(
        xsd_validate=True
    )
    evidence["typed:exemption-directive"] = _audit_exemption_variant_invoice("directive").to_xml(
        xsd_validate=True
    )
    evidence["typed:exemption-other"] = _audit_exemption_variant_invoice("other").to_xml(
        xsd_validate=True
    )
    evidence["typed:summary-edge"] = _audit_summary_edge_invoice().to_xml(xsd_validate=True)
    return evidence


def _audit_full_typed_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.basic("FV/AUD/FULL")
        .issued_on(date(2026, 3, 1))
        .seller(seller)
        .buyer(buyer)
        .foreign_currency_rate("4.123456")
        .fiscal_receipt_invoice()
        .additional_description("projekt", "FA3 audit")
        .new_transport(
            NewTransportMeans(
                allowed_date=date(2026, 2, 20),
                row_number=1,
                kind="land",
                mileage="1000",
                serial_number="VIN123",
                make="Marka",
                model="Model",
            )
        )
        .add_goods_line("Pojazd", quantity="1", unit_net_price="100000", tax=VatClass.standard_23())
        .payment(
            PaymentTerms(
                due_terms=(PaymentDue.description(14, "dni", "data wystawienia"),),
                method=PaymentMethod.TRANSFER.value,
                bank_accounts=(BankAccount(number="12345678901234567890123456"),),
            )
        )
        .contract(number="UM/AUD/1", date=date(2026, 2, 1))
        .order_reference(number="ZAM/AUD/1", date=date(2026, 2, 2))
        .transaction_terms(
            delivery_terms="DAP",
            contractual_rate="4.123456",
            contractual_currency="EUR",
        )
        .transport(
            TransportKind.ROAD,
            carrier=buyer,
            order_number="TR/AUD/1",
            cargo_description="1",
        )
        .footer_info("Stopka audytu")
        .registry(Registry.krs_entry("0000123456", full_name="Sprzedawca sp. z o.o."))
        .attachment(
            Attachment(
                (
                    AttachmentBlock(
                        header="Załącznik",
                        tables=(
                            AttachmentTable(
                                headers=("Nazwa", "Kwota"),
                                rows=(("Pojazd", "123000.00"),),
                                column_types=("txt", "dec"),
                            ),
                        ),
                    ),
                )
            )
        )
        .build()
    )


def _audit_coverage_invoice() -> FA3Invoice:
    seller = replace(
        Party.polish_company(
            nip="1234567890",
            name="Sprzedawca",
            address=Address.polish("Adres S", "Lokal 2", gln="5901234123457"),
            contacts=(Contact(email="seller@example.com", phone="123456789"),),
        ),
        taxpayer_prefix="PL",
        taxpayer_status="1",
        eori="EORI-S",
    )
    buyer = replace(
        Party.without_tax_id(name="Nabywca", address=Address.foreign("DE", "Buyer street")),
        correspondence_address=Address.foreign("DE", "Correspondence", gln="4001234567890"),
        contacts=(Contact(phone="987654321"),),
    )
    return (
        FA3Invoice.basic("FV/AUD/COV")
        .issued_on(date(2026, 4, 1))
        .currency("eur")
        .issue_place("Kraków")
        .seller(seller)
        .buyer(buyer)
        .add_goods_line(
            "Towar",
            quantity="2",
            unit_net_price="50",
            tax=VatClass.from_rate_code("4"),
            gtu=GTUCode.GTU_01,
            procedure=LineProcedure.IED,
            annex_15=True,
        )
        .payment_due(date(2026, 4, 15), method=PaymentMethod.CARD)
        .build()
    )


def _audit_coverage_invoice_rich() -> FA3Invoice:
    seller = replace(
        Party.polish_company(
            nip="1234567890",
            name="Sprzedawca",
            address=Address.polish("Adres S", "Lokal 2", gln="5901234123457"),
            contacts=(Contact(email="seller@example.com", phone="123456789"),),
        ),
        taxpayer_prefix="PL",
        taxpayer_status="1",
        eori="EORI-S",
    )
    buyer = replace(
        Party.without_tax_id(name="Nabywca", address=Address.foreign("DE", "Buyer street")),
        correspondence_address=Address.foreign("DE", "Correspondence", gln="4001234567890"),
        contacts=(Contact(phone="987654321"),),
        customer_number="CUST-1",
        buyer_id="BUYER-1",
    )
    extra = replace(
        Party.foreign_company(
            identifier="EXT-1",
            country_code="US",
            name="External",
            address=Address.foreign("US", "External street"),
        ),
        role=ThirdPartyRole.OTHER,
        other_role_description="custom role",
        share=Decimal("25"),
        customer_number="EXTRA-1",
    )
    authorized = replace(
        Party.polish_company(nip="2222222222", name="Pelnomocnik", address="Adres PU"),
        authorized_role=AuthorizedPartyRole.BAILIFF,
        contacts=(Contact(phone="555555555"),),
    )
    block = AttachmentBlock(
        header="Blok",
        metadata=(("meta", "value"),),
        paragraphs=("Paragraf",),
        tables=(
            AttachmentTable(
                headers=("A", "B"),
                rows=(("1", "2"),),
                column_types=("txt", "txt"),
                description="Tabela",
                footer=("Suma",),
            ),
        ),
    )
    return (
        FA3Invoice.basic("FV/AUD/COV/RICH")
        .issued_on(date(2026, 4, 1))
        .currency("eur")
        .issue_place("Krakow")
        .sale_date(date(2026, 3, 31))
        .seller(seller)
        .buyer(buyer)
        .add_party(extra, ThirdPartyRole.OTHER)
        .authorized_party(authorized, AuthorizedPartyRole.BAILIFF)
        .add_goods_line(
            "Towar",
            quantity="2",
            unit_net_price="50",
            tax=VatClass.from_rate_code("4"),
            discount=Discount.amount("5"),
            identifiers=LineIdentifiers(
                unique_id="u1",
                internal_index="SKU",
                gtin="5901234123457",
                pkwiu="62.01",
                cn="1234",
                pkob="567",
            ),
            unit_gross_price=decimal_from_value("61.50", field_name="gross"),
            net_amount=decimal_from_value("95", field_name="net"),
            gross_amount=decimal_from_value("98.80", field_name="gross"),
            vat_amount=decimal_from_value("3.80", field_name="vat"),
            excise_amount=decimal_from_value("1.23", field_name="excise"),
            gtu=GTUCode.GTU_01,
            procedure=LineProcedure.IED,
            currency_rate=decimal_from_value("4.123456", field_name="currency_rate"),
            annex_15=True,
        )
        .cash_method()
        .self_billing()
        .reverse_charge()
        .margin(MarginProcedure.ART)
        .exemption("art. 43")
        .payment_due(date(2026, 4, 15), method=PaymentMethod.CARD)
        .payment_due_description(7, "dni", "odbior")
        .paid(date(2026, 4, 2))
        .bank_account(
            "12345678901234567890123456",
            swift="TESTPLPW",
            own_bank_account="1",
            bank_name="Bank",
            description="konto glowne",
        )
        .bank_account("99999999999999999999999999", factor=True)
        .cash_discount("2% za szybka platnosc", "2.00")
        .transaction_terms(
            delivery_terms="EXW",
            contractual_rate="4.123456",
            contractual_currency="eur",
            intermediary=True,
        )
        .contract(number="UM/COV/1", date=date(2026, 3, 1))
        .order_reference(number="ZAM/COV/1", date=date(2026, 3, 2))
        .batch_number("PARTIA-COV")
        .transport(
            "other",
            other_kind_description="dron",
            carrier=buyer,
            order_number="TR/COV/1",
            other_cargo_description="ladunek specjalny",
            package_unit="karton",
            started_at=datetime(2026, 4, 1, 8, 30),
            finished_at=datetime(2026, 4, 1, 12, 0),
            ship_from=Address.polish("Magazyn A"),
            ship_via=(Address.polish("Hub"),),
            ship_to=Address.polish("Magazyn B"),
        )
        .additional_description("key", "value")
        .foreign_currency_rate("4.123456")
        .fiscal_receipt_invoice(False)
        .related_party_transaction(False)
        .excise_refund(False)
        .new_transport(
            NewTransportMeans(
                allowed_date=date(2026, 3, 1),
                row_number=1,
                kind="water",
                hours_used="10",
                serial_number="WATER-1",
                make="Make",
                model="Model",
                color="Blue",
                registry_number="REG",
                manufacture_year="2026",
                value="100",
                tax_amount="23",
                taxable_base="100",
                tax_rate="23",
            ),
            intra_eu=True,
        )
        .with_section(
            NewTransportMeans(
                allowed_date=date(2026, 3, 2),
                row_number=2,
                kind="air",
                hours_used="5",
                serial_number="AIR-1",
            )
        )
        .with_section(
            NewTransportMeans(
                allowed_date=date(2026, 3, 3),
                row_number=3,
                kind="land",
                mileage="100",
                serial_number="LAND-1",
                approval_number="HOMOLOGACJA",
                engine_capacity="1998",
                engine_power="150",
                tax_rate="23",
            )
        )
        .with_section(AdditionalDescription.key_value("second", "value"))
        .with_section(Footer.info("Info stopki"))
        .with_section(Footer.registry(Registry.regon_entry("123456789")))
        .with_section(ExciseRefund())
        .footer_info("Druga stopka")
        .registry(Registry.bdo_entry("000012345"))
        .attachment_block(block)
        .build()
    )


def _audit_sections_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="ul. Prosta 1")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="ul. Odbiorcy 2")
    extra = Party.foreign_company(
        identifier="DE123456789",
        country_code="DE",
        name="Odbiorca DE",
        address=Address.foreign("DE", "Berlin, Hauptstrasse 1"),
    )
    return (
        FA3Invoice.basic("FV/AUD/SECTIONS")
        .issued_on(date(2026, 1, 15))
        .issue_place("Warszawa")
        .seller(seller)
        .buyer(buyer)
        .add_party(extra, ThirdPartyRole.RECIPIENT)
        .add_line(
            "Usluga A",
            quantity="2",
            unit_net_price="100",
            tax=VatClass.standard_23(),
            discount=Discount.percent("10"),
            gtu="GTU_12",
            procedure="WSTO_EE",
            annex_15=True,
        )
        .add_line(
            "Usluga zwolniona",
            quantity="1",
            unit_net_price="50",
            tax=VatClass.exempt("art. 43 ust. 1 ustawy"),
        )
        .annotations(Annotation.split_payment(), Annotation.cash_method())
        .payment(
            PaymentTerms.transfer(
                due_date=date(2026, 1, 31),
                bank_account=BankAccount(number="12345678901234567890123456"),
            )
        )
        .settlement_details(
            Settlement(
                deductions=(SettlementAdjustment.create("10", "Rabat dokumentu"),),
                amount_due=decimal_from_value("261.40", field_name="do_zaplaty"),
            )
        )
        .attachment(
            Attachment(
                (
                    AttachmentBlock(
                        header="Rozliczenie",
                        metadata=(("zrodlo", "SDK"),),
                        paragraphs=("Opis dodatkowy",),
                        tables=(
                            AttachmentTable(
                                headers=("Nazwa", "Kwota"),
                                rows=(("Rabat", "10.00"),),
                                metadata=(("zrodlo", "SDK"),),
                                column_types=("txt", "dec"),
                            ),
                        ),
                    ),
                )
            )
        )
        .build()
    )


def _audit_full_typed_strict_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.basic("FV/AUD/FULL/STRICT")
        .issued_on(date(2026, 3, 1))
        .seller(seller)
        .buyer(buyer)
        .foreign_currency_rate("4.123456")
        .fiscal_receipt_invoice()
        .related_party_transaction()
        .additional_description("projekt", "FA3 full typed SDK")
        .with_section(AdditionalDescription.key_value("kanal", "API"))
        .new_transport(
            NewTransportMeans(
                allowed_date=date(2026, 2, 20),
                row_number=1,
                kind="land",
                mileage="1000",
                serial_number="VIN123",
                make="Marka",
                model="Model",
            )
        )
        .add_goods_line(
            "Pojazd",
            quantity="1",
            unit_net_price="100000",
            unit_gross_price=decimal_from_value("123000", field_name="brutto"),
            tax=VatClass.standard_23(),
            identifiers=LineIdentifiers(
                unique_id="line-1",
                internal_index="SKU-1",
                gtin="1234567890123",
                pkwiu="62.01",
                cn="8703",
                pkob="123",
            ),
        )
        .payment_due_description(14, "dni", "data wystawienia")
        .payment(
            PaymentTerms(
                due_terms=(PaymentDue.description(14, "dni", "data wystawienia"),),
                method=PaymentMethod.TRANSFER.value,
                bank_accounts=(BankAccount(number="12345678901234567890123456"),),
                payment_link="https://pay.example.com/pay?IPKSeF=123ABCDEFGHIJ",
                ipksef="123ABCDEFGHIJ",
            )
        )
        .contract(number="UM/FULL/1", date=date(2026, 2, 1))
        .order_reference(number="ZAM/FULL/1", date=date(2026, 2, 2))
        .batch_number("PARTIA-1")
        .transaction_terms(
            delivery_terms="DAP",
            contractual_rate="4.123456",
            contractual_currency="EUR",
            intermediary=True,
        )
        .transport(
            TransportKind.ROAD,
            carrier=buyer,
            order_number="TR/FULL/1",
            cargo_description="1",
            package_unit="paleta",
            ship_from=Address.polish("Magazyn A"),
            ship_to=Address.polish("Magazyn B"),
        )
        .excise_refund()
        .footer_info("Stopka faktury")
        .registry(Registry.krs_entry("0000123456", full_name="Sprzedawca sp. z o.o."))
        .attachment(
            Attachment(
                (
                    AttachmentBlock(
                        header="Zalacznik",
                        metadata=(("typ", "pelny"),),
                        tables=(
                            AttachmentTable(
                                headers=("Nazwa", "Kwota"),
                                rows=(("Pojazd", "123000.00"),),
                                metadata=(("zrodlo", "SDK"),),
                                column_types=("txt", "dec"),
                                footer=("123000.00",),
                            ),
                        ),
                    ),
                )
            )
        )
        .build()
    )


def _audit_convenient_builder_invoice() -> FA3Invoice:
    return (
        FA3Invoice.basic("FV/BUILDER/AUD/1")
        .issued_on(date(2026, 1, 15))
        .seller(Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S"))
        .buyer(Party.eu_company(vat_id="123456789", country_code="DE", name="Buyer", address="B"))
        .add_service_line(
            "Usluga wdrozeniowa",
            quantity="1",
            unit_net_price="1000.00",
            tax=VatClass.standard_23(),
            discount=Discount.percent("10"),
            gtu=GTUCode.GTU_12,
            procedure=LineProcedure.WSTO_EE,
        )
        .split_payment()
        .payment_due(date(2026, 1, 31), method=PaymentMethod.TRANSFER)
        .bank_account("12345678901234567890123456")
        .contract(number="UM/1/2026", date=date(2026, 1, 1))
        .warehouse_document("WZ/1/2026")
        .transport(TransportKind.ROAD, order_number="TR/1")
        .build()
    )


def _audit_period_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.basic("FV/AUD/PERIOD")
        .issued_on(date(2026, 1, 31))
        .period(date(2026, 1, 1), date(2026, 1, 31))
        .seller(seller)
        .buyer(buyer)
        .add_service_line(
            "Line",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.xii("12"),
            unique_id="line-period-1",
            service_date=date(2026, 1, 15),
        )
        .payment(
            PaymentTerms(
                partial_payments=(
                    PartialPayment.create("10", date(2026, 1, 2), method=PaymentMethod.CASH.value),
                ),
                due_dates=(date(2026, 2, 1),),
                other_method_description="kompensata",
            )
        )
        .build()
    )


def _audit_multi_vat_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.basic("FV/AUD/VAT")
        .issued_on(date(2026, 2, 1))
        .currency("EUR")
        .foreign_currency_rate("4")
        .seller(seller)
        .buyer(buyer)
        .add_service_line("S23", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .add_service_line(
            "S8",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("8"),
        )
        .add_service_line(
            "S5",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("5"),
        )
        .add_service_line(
            "S4",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("4"),
        )
        .add_service_line(
            "S0WDT",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("0 WDT"),
        )
        .add_service_line(
            "S0EX",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("0 EX"),
        )
        .add_service_line(
            "S0KR",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("0 KR"),
        )
        .add_service_line(
            "SNP1",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("np I"),
        )
        .add_service_line(
            "SNP2",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("np II"),
        )
        .build()
    )


def _audit_order_detailed_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.advance("FV/AUD/ORDER/DETAIL")
        .issued_on(date(2026, 2, 1))
        .seller(seller)
        .buyer(buyer)
        .order(total_gross="5000.00")
        .order_line(
            "Pozycja zamowienia",
            quantity="1",
            unit_net_price="4065.04",
            tax=VatClass.xii("12"),
            identifiers=LineIdentifiers(
                unique_id="u1",
                internal_index="SKU",
                gtin="5901234123457",
                pkwiu="62.01",
                cn="1234",
                pkob="567",
            ),
            gtu=GTUCode.GTU_12,
            procedure=OrderLineProcedure.IED,
            excise_amount=decimal_from_value("1.23", field_name="akcyza"),
            annex_15=True,
            before_correction=True,
        )
        .order_line(
            "Pozycja zamowienia standard",
            quantity="1",
            unit_net_price="100.00",
            tax=VatClass.standard_23(),
        )
        .build()
    )


def _audit_new_transport_variants_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.basic("FV/AUD/NST")
        .issued_on(date(2026, 2, 1))
        .seller(seller)
        .buyer(buyer)
        .add_service_line("NST", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .new_transport(
            NewTransportMeans(
                allowed_date=date(2026, 3, 1),
                row_number=1,
                kind="land",
                mileage="100",
                serial_number="VIN-1",
                tax_rate="23",
                make="Marka",
                model="Model",
                color="Blue",
                registry_number="REG-1",
                manufacture_year="2026",
            ),
            intra_eu=True,
        )
        .with_section(
            NewTransportMeans(
                allowed_date=date(2026, 3, 2),
                row_number=2,
                kind="land",
                mileage="101",
                engine_capacity="2000",
                tax_rate="23",
            )
        )
        .with_section(
            NewTransportMeans(
                allowed_date=date(2026, 3, 3),
                row_number=3,
                kind="land",
                mileage="102",
                engine_power="150",
                tax_rate="23",
            )
        )
        .with_section(
            NewTransportMeans(
                allowed_date=date(2026, 3, 4),
                row_number=4,
                kind="land",
                mileage="103",
                approval_number="HOMOLOG",
                tax_rate="23",
            )
        )
        .with_section(
            NewTransportMeans(
                allowed_date=date(2026, 3, 5),
                row_number=5,
                kind="water",
                hours_used="10",
                serial_number="WATER-1",
            )
        )
        .with_section(
            NewTransportMeans(
                allowed_date=date(2026, 3, 6),
                row_number=6,
                kind="air",
                hours_used="5",
                serial_number="AIR-1",
            )
        )
        .build()
    )


def _audit_margin_variant_invoice(kind: str) -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.basic(f"FV/AUD/MARGIN/{kind}")
        .issued_on(date(2026, 2, 1))
        .seller(seller)
        .buyer(buyer)
        .add_service_line("Marza", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .margin(kind)
        .build()
    )


def _audit_party_extended_invoice() -> FA3Invoice:
    seller = replace(
        Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S"),
        correspondence_address=Address.polish("Adres Koresp"),
    )
    buyer = replace(
        Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N"),
        eori="EORI-BUYER",
    )
    extra = replace(
        Party.foreign_company(
            identifier="EXT-2",
            country_code="DE",
            name="Third Party",
            address=Address.foreign("DE", "Addr"),
        ),
        eori="EORI-3",
        correspondence_address=Address.foreign("DE", "Addr K"),
        contacts=(Contact(email="third@example.com", phone="111222333"),),
        customer_number="CUST-3",
        buyer_id="ID-3",
    )
    authorized = replace(
        Party.polish_company(nip="2222222222", name="Authorized", address="Auth A"),
        eori="EORI-AUTH",
        correspondence_address=Address.polish("Auth K"),
        contacts=(Contact(email="auth@example.com", phone="222333444"),),
    )
    return (
        FA3Invoice.basic("FV/AUD/PARTY")
        .issued_on(date(2026, 2, 2))
        .seller(seller)
        .buyer(buyer)
        .add_party(extra, ThirdPartyRole.RECIPIENT)
        .authorized_party(authorized, AuthorizedPartyRole.BAILIFF)
        .add_service_line("Party", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )


def _audit_correction_ksef_invoice() -> FA3Invoice:
    seller = replace(
        Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S"),
        taxpayer_prefix="PL",
    )
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    builder: Any = FA3Invoice.settlement_correction("KOR/ROZ/AUD")
    return (
        builder
        .issued_on(date(2026, 2, 15))
        .seller(seller)
        .buyer(buyer)
        .remaining_to_pay("-12.30")
        .corrects(
            "FV/OLD/1",
            date(2026, 1, 10),
            reason="Korekta",
            ksef_number="1234567890-20260110-AAAAAA-BBBBBB-CC",
        )
        .corrected_seller(seller)
        .corrected_period("2026-01")
        .corrected_invoice_number_override("FV/OLD/CORRECT/1")
        .with_section(CorrectedAdvanceState.create("50.00", currency_rate="4.123456"))
        .settles_advance(ksef_number="1234567890-20260109-AAAAAA-BBBBBB-CC")
        .add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Przed",
                quantity="1",
                unit_net_price="100",
                tax=VatClass.standard_23(),
            ),
            after=InvoiceLine.service(
                "Po",
                quantity="1",
                unit_net_price="90",
                tax=VatClass.standard_23(),
            ),
        )
        .build()
    )


def _audit_settlement_charges_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.settlement("ROZ/AUD/CHARGE")
        .issued_on(date(2026, 2, 20))
        .seller(seller)
        .buyer(buyer)
        .settles_advance(ksef_number="1234567890-20260219-AAAAAA-BBBBBB-CC")
        .settlement_details(
            Settlement(
                charges=(SettlementAdjustment.create("15.00", "Korekta"),),
                amount_to_settle=decimal_from_value("200.00", field_name="do_rozliczenia"),
            )
        )
        .add_service_line(
            "Rozliczenie",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.standard_23(),
        )
        .build()
    )


def _audit_advance_currency_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.advance("ZAL/AUD/CUR")
        .issued_on(date(2026, 2, 5))
        .seller(seller)
        .buyer(buyer)
        .advance_payment(
            amount="1230.00",
            tax=VatClass.standard_23(),
            paid_on=date(2026, 2, 4),
            currency_rate="4.12",
        )
        .add_service_line(
            "Zaliczka",
            quantity="1",
            unit_net_price="1000",
            tax=VatClass.standard_23(),
        )
        .build()
    )


def _audit_partial_payment_other_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.basic("FV/AUD/PAY/PART")
        .issued_on(date(2026, 2, 6))
        .seller(seller)
        .buyer(buyer)
        .add_service_line("Pay", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .partially_paid("10", date(2026, 2, 7), other_method_description="kompensata")
        .bank_account("99999999999999999999999999", factor=True)
        .cash_discount("rabat", "1.00")
        .build()
    )


def _audit_exemption_variant_invoice(kind: str) -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.basic(f"FV/AUD/EX/{kind}")
        .issued_on(date(2026, 2, 6))
        .seller(seller)
        .buyer(buyer)
        .add_service_line(
            "Exempt",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.exempt("podstawa", basis_type=kind),
        )
        .build()
    )


def _audit_summary_edge_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.basic("FV/AUD/SUMMARY")
        .issued_on(date(2026, 2, 8))
        .seller(seller)
        .buyer(buyer)
        .add_line(
            "Srv100",
            quantity="1",
            unit_net_price="100",
            tax=TaxCategory(TaxCategoryKind.SERVICE_ARTICLE_100, None, "np I"),
        )
        .add_line(
            "Reverse",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.reverse_charge(),
        )
        .add_line(
            "Margin",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.margin(),
        )
        .add_line(
            "Adj23",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.standard_23(),
            vat_amount=decimal_from_value("30.00", field_name="vat"),
        )
        .add_line(
            "Adj8",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.reduced_8(),
            vat_amount=decimal_from_value("12.00", field_name="vat"),
        )
        .add_line(
            "Adj5",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.reduced_5(),
            vat_amount=decimal_from_value("9.00", field_name="vat"),
        )
        .add_line(
            "AdjFlat",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.from_rate_code("4"),
            vat_amount=decimal_from_value("8.00", field_name="vat"),
        )
        .build()
    )


def _audit_attachment_invoice() -> FA3Invoice:
    seller = Party.polish_company(
        nip="1234567890",
        name="Sprzedawca",
        address=Address.polish("ul. Prosta 1"),
    )
    buyer = Party.polish_company(
        nip="1111111111",
        name="Nabywca",
        address=Address.polish("ul. Odbiorcy 2"),
    )
    extra = Party.foreign_company(
        identifier="DE123456789",
        country_code="DE",
        name="Odbiorca DE",
        address=Address.foreign("DE", "Berlin, Hauptstrasse 1"),
    )
    return (
        FA3Invoice.basic("FV/AUD/ATT")
        .issued_on(date(2026, 1, 15))
        .issue_place("Warszawa")
        .seller(seller)
        .buyer(buyer)
        .add_party(extra, ThirdPartyRole.RECIPIENT)
        .add_line(
            "Us�uga A",
            quantity="2",
            unit_net_price="100",
            tax=VatClass.standard_23(),
            discount=Discount.percent("10"),
            gtu="GTU_12",
            procedure="WSTO_EE",
            annex_15=True,
        )
        .add_line(
            "Us�uga zwolniona",
            quantity="1",
            unit_net_price="50",
            tax=VatClass.exempt("art. 43 ust. 1 ustawy"),
        )
        .annotations(Annotation.split_payment(), Annotation.cash_method())
        .payment(
            PaymentTerms.transfer(
                due_date=date(2026, 1, 31),
                bank_account=BankAccount(number="12345678901234567890123456"),
            )
        )
        .settlement_details(
            Settlement(
                deductions=(SettlementAdjustment.create("10", "Rabat dokumentu"),),
                amount_due=decimal_from_value("261.40", field_name="do_zaplaty"),
            )
        )
        .attachment(
            Attachment(
                (
                    AttachmentBlock(
                        header="Rozliczenie",
                        metadata=(("�r�d�o", "SDK"),),
                        paragraphs=("Opis dodatkowy",),
                        tables=(
                            AttachmentTable(
                                headers=("Nazwa", "Kwota"),
                                rows=(("Rabat", "10.00"),),
                                column_types=("txt", "dec"),
                            ),
                        ),
                    ),
                )
            )
        )
        .build()
    )


def _audit_correction_parties_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.correction("KOR/AUD/1")
        .issued_on(date(2026, 2, 1))
        .seller(seller)
        .buyer(buyer)
        .corrects_many(
            (
                CorrectionReference("FV/1/2026", date(2026, 1, 1)),
                CorrectionReference("FV/2/2026", date(2026, 1, 2)),
            ),
            reason="Rabat po sprzeda�y",
            correction_type=CorrectionType.TAX_BASE_OR_TAX,
        )
        .corrected_seller(seller)
        .corrected_buyer(replace(buyer, buyer_id="BUYER-K"))
        .add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Us�uga",
                quantity="1",
                unit_net_price="1000.00",
                tax=VatClass.standard_23(),
            ),
            after=InvoiceLine.service(
                "Us�uga",
                quantity="1",
                unit_net_price="900.00",
                tax=VatClass.standard_23(),
            ),
        )
        .build()
    )


def _audit_order_invoice() -> FA3Invoice:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")
    return (
        FA3Invoice.advance("ZAL/AUD/1")
        .issued_on(date(2026, 2, 1))
        .seller(seller)
        .buyer(buyer)
        .add_service_line(
            "Us�uga zaliczkowa",
            quantity="1",
            unit_net_price="1000",
            tax=VatClass.standard_23(),
        )
        .order_reference(number="ZAM/1", date=date(2026, 1, 20))
        .build()
    )


# ---------------------------------------------------------------------------
# Regresje z bug review v0.18.1: rozliczenie stawek VAT w ścieżce draftu.
#
# Draft (`FA3InvoiceBuilder`/`FA3Draft`) wpisywał całe netto i VAT faktury do
# `P_13_1`/`P_14_1` (pola stawki podstawowej 23/22%) niezależnie od stawek
# pozycji, więc np. faktura ze stawką 8% deklarowała sprzedaż opodatkowaną
# stawką podstawową z VAT 8.00 od bazy 100.00.
# ---------------------------------------------------------------------------

DRAFT_RATE_BUCKETS = (
    ("23", "P_13_1", "P_14_1"),
    ("22", "P_13_1", "P_14_1"),
    ("8", "P_13_2", "P_14_2"),
    ("7", "P_13_2", "P_14_2"),
    ("5", "P_13_3", "P_14_3"),
    ("4", "P_13_4", "P_14_4"),
    ("3", "P_13_4", "P_14_4"),
)

# Wszystkie pola podsumowania stawek w kolejności wymuszonej przez xs:sequence.
_ALL_TAX_SUMMARY_TAGS = (
    "P_13_1",
    "P_14_1",
    "P_13_2",
    "P_14_2",
    "P_13_3",
    "P_14_3",
    "P_13_4",
    "P_14_4",
    "P_13_5",
    "P_14_5",
    "P_13_6_1",
    "P_13_6_2",
    "P_13_6_3",
    "P_13_7",
    "P_13_8",
    "P_13_9",
    "P_13_10",
    "P_13_11",
)


def _draft_for_rate(rate: str, *, net: str = "100", quantity: str = "1") -> FA3Draft:
    builder = FA3InvoiceBuilder(
        invoice_number=f"FV/RATE/{rate}",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Usługa", quantity=quantity, unit_net_price=net, vat_rate=rate)
    return builder.build()


def _tag_texts(xml: bytes) -> dict[str, str]:
    root = ET.fromstring(xml)
    ns = {"fa": root.tag.split("}")[0].strip("{")}
    found: dict[str, str] = {}
    for tag in ("P_11", "P_12", "P_15", "P_19", "P_19A", "P_19N", *_ALL_TAX_SUMMARY_TAGS):
        node = root.find(f".//fa:{tag}", ns)
        if node is not None and node.text is not None:
            found[tag] = node.text
    return found


@pytest.mark.parametrize(("rate", "net_tag", "vat_tag"), DRAFT_RATE_BUCKETS)
def test_draft_puts_each_rate_into_its_own_summary_bucket(
    rate: str, net_tag: str, vat_tag: str
) -> None:
    draft = _draft_for_rate(rate)
    assert str(draft.total_net) == "100.00"
    xml = draft.to_xml(xsd_validate=True)
    found = _tag_texts(xml)
    assert found[net_tag] == "100.00", found
    expected_vat = money(Decimal("100.00") * Decimal(rate) / Decimal("100"))
    assert found[vat_tag] == f"{expected_vat:.2f}", found
    # Netto i VAT muszą trafić dokładnie w jeden koszyk — nie do P_13_1 "po drodze".
    present_net_tags = {tag for tag in _ALL_TAX_SUMMARY_TAGS if tag in found and "P_13" in tag}
    assert present_net_tags == {net_tag}, found
    present_vat_tags = {tag for tag in _ALL_TAX_SUMMARY_TAGS if tag in found and "P_14" in tag}
    assert present_vat_tags == {vat_tag}, found


def test_draft_totals_match_the_summary_buckets() -> None:
    """`total_net`/`total_vat`/`total_gross` muszą zgadzać się z tym, co idzie do XML."""
    draft = _draft_for_rate("8")
    found = _tag_texts(draft.to_xml(xsd_validate=True))
    assert f"{draft.total_net:.2f}" == found["P_13_2"]
    assert f"{draft.total_vat:.2f}" == found["P_14_2"]
    assert f"{draft.total_gross:.2f}" == found["P_15"]


def test_draft_summary_is_not_hardcoded_to_the_basic_rate() -> None:
    """Stawka 8% nie może być deklarowana w polach stawki podstawowej."""
    found = _tag_texts(_draft_for_rate("8").to_xml(xsd_validate=True))
    assert "P_13_1" not in found
    assert "P_14_1" not in found
    assert found["P_13_2"] == "100.00"
    assert found["P_14_2"] == "8.00"
    assert found["P_15"] == "108.00"


def test_draft_zero_rate_uses_a_valid_p12_code_and_zero_bucket() -> None:
    found = _tag_texts(_draft_for_rate("0").to_xml(xsd_validate=True))
    # TStawkaPodatku nie zawiera gołego "0" - XSD wymaga "0 KR"/"0 WDT"/"0 EX".
    assert found["P_12"] == "0 KR"
    assert found["P_13_6_1"] == "100.00"
    assert "P_14_1" not in found
    assert found["P_15"] == "100.00"


def test_draft_multi_rate_invoice_buckets_each_line() -> None:
    builder = FA3InvoiceBuilder(
        invoice_number="FV/MULTI",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("23%", quantity="1", unit_net_price="100", vat_rate="23")
    builder.add_line("8%", quantity="2", unit_net_price="100", vat_rate="8")
    draft = builder.build()
    found = _tag_texts(draft.to_xml(xsd_validate=True))
    assert found["P_13_1"] == "100.00"
    assert found["P_14_1"] == "23.00"
    assert found["P_13_2"] == "200.00"
    assert found["P_14_2"] == "16.00"
    assert found["P_15"] == "339.00"
    # Suma koszyków netto i VAT musi dać P_15.
    net_total = Decimal(found["P_13_1"]) + Decimal(found["P_13_2"])
    vat_total = Decimal(found["P_14_1"]) + Decimal(found["P_14_2"])
    assert net_total + vat_total == Decimal(found["P_15"])


def test_draft_sums_identical_rates_across_lines() -> None:
    builder = FA3InvoiceBuilder(
        invoice_number="FV/SAME-RATE",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("A", quantity="1", unit_net_price="100", vat_rate="8")
    builder.add_line("B", quantity="1", unit_net_price="50", vat_rate="8")
    found = _tag_texts(builder.build().to_xml(xsd_validate=True))
    assert found["P_13_2"] == "150.00"
    assert found["P_14_2"] == "12.00"


def test_draft_exempt_line_requires_exemption_basis() -> None:
    """Pozycja ``zw`` nie może iść do P_13_1, a adnotacja P_19N byłaby sprzeczna."""
    builder = FA3InvoiceBuilder(
        invoice_number="FV/ZW/BAD",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Zwolniona", quantity="1", unit_net_price="100", vat_rate="zw")
    with pytest.raises(ValueError, match="podstawy prawnej"):
        builder.build()

    # `FA3Draft` da się też zbudować bez walidacji (np. przez `from_dict`), więc
    # kontrakt walidacyjny draftu również musi zgłaszać brak podstawy prawnej.
    draft = FA3Draft(
        invoice_number="FV/ZW/BAD",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
        lines=[
            FA3Line(
                description="Zwolniona",
                quantity=Decimal("1"),
                unit="szt",
                unit_net_price=Decimal("100"),
                vat_rate=None,
            )
        ],
    )
    errors, _warnings = draft.validate()
    assert any("podstawy prawnej" in issue.message for issue in errors), [
        issue.message for issue in errors
    ]
    with pytest.raises((ValueError, FA3XmlValidationError)):
        draft.to_xml()


def test_draft_exempt_line_with_basis_uses_p13_7_and_p19a() -> None:
    builder = FA3InvoiceBuilder(
        invoice_number="FV/ZW/OK",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line(
        "Zwolniona",
        quantity="1",
        unit_net_price="100",
        vat_rate="zw",
        exemption_basis="art. 43 ust. 1 ustawy",
    )
    draft = builder.build()
    errors, _warnings = draft.validate()
    assert errors == [], [issue.message for issue in errors]
    xml = draft.to_xml(xsd_validate=True)
    found = _tag_texts(xml)
    assert found["P_12"] == "zw"
    assert found["P_13_7"] == "100.00"
    assert found["P_15"] == "100.00"
    assert "P_14_1" not in found
    assert found["P_19"] == "1"
    assert found["P_19A"] == "art. 43 ust. 1 ustawy"
    assert "P_19N" not in found


def test_draft_rejects_unsupported_vat_rate_before_serialization() -> None:
    """Stawka spoza TStawkaPodatku nie może cicho trafić do XML jako P_12."""
    builder = FA3InvoiceBuilder(
        invoice_number="FV/RATE/17",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Usługa", quantity="1", unit_net_price="100", vat_rate="17")
    with pytest.raises(ValueError, match="(?i)nieobs"):
        builder.build()


# ---------------------------------------------------------------------------
# Regresja: `parse_vat_rate` gubił znak, więc reguła "stawka VAT nie może być
# ujemna" była nieosiągalna (``-23`` stawało się cichym ``23``).
# ---------------------------------------------------------------------------


def test_parse_vat_rate_keeps_the_sign() -> None:
    assert parse_vat_rate("-23") == Decimal("-23")
    assert parse_vat_rate(Decimal("-23")) == Decimal("-23")
    assert parse_vat_rate(-23) == Decimal("-23")
    assert parse_vat_rate("-100") == Decimal("-100")
    assert parse_vat_rate("23") == Decimal("23")
    assert parse_vat_rate(" 8 % ") == Decimal("8")
    assert parse_vat_rate("8") == Decimal("8")


def test_parse_vat_rate_exempt_markers_still_map_to_none() -> None:
    for marker in ("zw", "ZW", "zwolniony", "np", "nie podlega", None, ""):
        assert parse_vat_rate(marker) is None, marker


def test_parse_vat_rate_zero_rate_codes_map_to_zero() -> None:
    assert parse_vat_rate("0") == Decimal("0")
    assert parse_vat_rate("0 KR") == Decimal("0")
    assert parse_vat_rate("0 WDT") == Decimal("0")
    assert parse_vat_rate("0 EX") == Decimal("0")


def test_negative_vat_rate_is_reported_as_an_error() -> None:
    line = FA3Line(
        description="Korekta",
        quantity=Decimal("1"),
        unit="szt",
        unit_net_price=Decimal("100"),
        vat_rate=parse_vat_rate("-23"),
    )
    errors, _warnings = line.validate()
    assert any("ujemna" in issue.message for issue in errors), [e.message for e in errors]


def test_negative_vat_rate_is_rejected_by_draft_and_typed_paths() -> None:
    builder = FA3InvoiceBuilder(
        invoice_number="FV/NEG",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Usługa", quantity="1", unit_net_price="100", vat_rate="-23")
    with pytest.raises(ValueError, match="(?i)ujemna"):
        builder.build()

    # W ścieżce typowanej ujemna stawka jest odrzucana już przy budowie kategorii.
    with pytest.raises(ValueError, match="(?i)nieobs"):
        TaxCategory.from_vat_rate("-23")

    # Reguła "stawka VAT nie może być ujemna" musi być jednak osiągalna dla
    # kategorii zbudowanej wprost (np. z odczytu stanu sesji).
    typed_line = InvoiceLine.create(
        "Usługa",
        quantity="1",
        unit_net_price="100",
        tax=TaxCategory(TaxCategoryKind.STANDARD_23, Decimal("-23"), "-23"),
    )
    typed_errors = typed_line.validate("invoice.lines[0]")
    assert any("ujemna" in issue.message for issue in typed_errors), [
        e.message for e in typed_errors
    ]


def test_typed_invoice_with_negative_rate_is_rejected() -> None:
    builder = BasicInvoiceBuilder(invoice_number="FV/NEG/TYPED")
    builder.seller(
        InvoiceParty.polish_company(nip="1234567890", name="Sprzedawca", address="ul. Prosta 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="1111111111", name="Nabywca", address="ul. Testowa 2")
    )
    with pytest.raises(ValueError, match="(?i)nieobs"):
        builder.add_service_line(
            "Usługa",
            quantity="1",
            unit_net_price="100",
            tax=TaxCategory.from_vat_rate("-23"),
        )


# ---------------------------------------------------------------------------
# Regresja: override `net_amount` nie wchodził do podstawy VAT, więc dokument
# miał P_13_x + P_14_x != P_15 (netto 200 @23% dawało VAT 23.00 i brutto 123.00).
# ---------------------------------------------------------------------------


def test_net_amount_override_recomputes_vat_and_gross() -> None:
    line = FA3Line(
        description="Override netto",
        quantity=Decimal("1"),
        unit="szt",
        unit_net_price=Decimal("100"),
        vat_rate=Decimal("23"),
        net_amount=Decimal("200"),
    )
    assert line.effective_net_amount == Decimal("200.00")
    assert line.effective_vat_amount == Decimal("46.00")
    assert line.effective_gross_amount == Decimal("246.00")


def test_draft_with_net_amount_override_keeps_summary_consistent() -> None:
    builder = FA3InvoiceBuilder(
        invoice_number="FV/OVERRIDE",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line(
        "Usługa",
        quantity="1",
        unit_net_price="100",
        vat_rate="23",
        net_amount="200",
    )
    draft = builder.build()
    found = _tag_texts(draft.to_xml(xsd_validate=True))
    assert found["P_11"] == "200.00"
    assert found["P_13_1"] == "200.00"
    assert found["P_14_1"] == "46.00"
    assert found["P_15"] == "246.00"
    assert Decimal(found["P_13_1"]) + Decimal(found["P_14_1"]) == Decimal(found["P_15"])


def test_vat_amount_override_still_flows_into_gross() -> None:
    line = FA3Line(
        description="Override VAT",
        quantity=Decimal("1"),
        unit="szt",
        unit_net_price=Decimal("100"),
        vat_rate=Decimal("23"),
        vat_amount=Decimal("10"),
    )
    assert line.effective_net_amount == Decimal("100.00")
    assert line.effective_vat_amount == Decimal("10.00")
    assert line.effective_gross_amount == Decimal("110.00")


def test_gross_amount_override_wins_over_the_computed_gross() -> None:
    line = FA3Line(
        description="Override brutto",
        quantity=Decimal("1"),
        unit="szt",
        unit_net_price=Decimal("100"),
        vat_rate=Decimal("23"),
        net_amount=Decimal("200"),
        gross_amount=Decimal("999"),
    )
    assert line.effective_gross_amount == Decimal("999.00")


# ---------------------------------------------------------------------------
# Regresje z broszury MF "Information sheet on the FA(3) logical structure"
# (EN, sierpień 2026) - precyzja pól kwotowych i pola wymagane przez schemat.
#
# Precyzja (str. 6):
#   "Amounts are generally provided with a precision of up to 2 decimal places"
#   "For the fields P_8B, P_12_XII, P_8BZ, P_12Z_XII, KursWaluty, KursWalutyZK,
#    KursWalutyZW, KursWalutyZ, KursUmowny, and Udzial, values are provided with
#    up to 6 decimal places."
#   "Unit prices in P_9A, P_9B, P_9AZ, as well as discounts or reductions in
#    field P_10, may be expressed with up to 8 decimal places."
# Schemat: P_9A/P_9B/P_10/P_9AZ to `TKwotowy2` (fractionDigits=8), P_8B `TIlosci` (6).
# Regresja: `_amount2` formatował te pola do 2 miejsc, więc 1.005 szło jako 1.00.
# ---------------------------------------------------------------------------

_VALID_PAYMENT_LINK = "https://pay.example.com/invoice?IPKSeF=123abc456DEFG"
_VALID_IPKSEF = "123abc456DEFG"


def _tag_text(xml_text: str, tag: str) -> str | None:
    match = re.search(rf"<{tag}>([^<]*)</{tag}>", xml_text)
    return match.group(1) if match else None


def _typed_line_xml(**line_kwargs: Any) -> str:
    """Buduje fakturę z jedną pozycją i zwraca XML jako tekst."""
    builder = BasicInvoiceBuilder(invoice_number="FV/PRECISION")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", **line_kwargs)
    return builder.build().to_xml(xsd_validate=True).decode("utf-8")


def _payment_invoice(invoice_number: str = "FV/PAYMENT") -> FA3Invoice:
    builder = BasicInvoiceBuilder(invoice_number=invoice_number)
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    return builder.build()


@pytest.mark.parametrize(
    ("unit_price", "expected_p9a"),
    [
        ("1.005", "1.005"),
        ("1.12345678", "1.12345678"),
        ("1.1234567", "1.1234567"),
        ("20.00", "20"),
        ("1.5", "1.5"),
    ],
)
def test_unit_price_keeps_up_to_eight_decimals(unit_price: str, expected_p9a: str) -> None:
    xml = _typed_line_xml(quantity="1", unit_net_price=unit_price)
    assert _tag_text(xml, "P_9A") == expected_p9a, xml[:600]


def test_unit_price_precision_is_not_silently_rounded() -> None:
    """Cena 1.005 nie może stać się 1.00 — to zmienia wartość faktury."""
    xml = _typed_line_xml(quantity="1", unit_net_price="1.005")
    assert _tag_text(xml, "P_9A") == "1.005"
    assert _tag_text(xml, "P_11") == "1.01"


def test_unit_price_with_nine_decimals_is_rejected() -> None:
    with pytest.raises(FA3XmlValidationError):
        _typed_line_xml(quantity="1", unit_net_price="1.123456789")


def test_quantity_keeps_up_to_six_decimals() -> None:
    xml = _typed_line_xml(quantity="1.123456", unit_net_price="10")
    assert _tag_text(xml, "P_8B") == "1.123456"


def test_quantity_with_seven_decimals_is_normalised_to_six() -> None:
    """`TIlosci` dopuszcza 6 miejsc, więc nadmiar jest zaokrąglany, nie odrzucany.

    Broszura MF (str. 6) wylicza `P_8B` wśród pól z limitem 6 miejsc; schemat
    egzekwuje to wzorcem, więc wcześniej taka ilość dawała XML odrzucany przez KSeF.
    """
    xml = _typed_line_xml(quantity="1.1234567", unit_net_price="10")
    assert _tag_text(xml, "P_8B") == "1.123457"


def test_exchange_rate_with_seven_decimals_is_normalised_to_six() -> None:
    """`KursWaluty` ma ten sam limit 6 miejsc co `P_8B`."""
    xml = _typed_line_xml(quantity="1", unit_net_price="10", currency_rate="4.1234567")
    assert _tag_text(xml, "KursWaluty") == "4.123457"


def test_aggregate_amounts_use_two_decimals() -> None:
    xml = _typed_line_xml(quantity="3", unit_net_price="10")
    assert _tag_text(xml, "P_11") == "30.00"
    assert _tag_text(xml, "P_13_1") == "30.00"
    assert _tag_text(xml, "P_14_1") == "6.90"
    assert _tag_text(xml, "P_15") == "36.90"


def test_draft_unit_price_keeps_eight_decimals() -> None:
    builder = FA3InvoiceBuilder(
        invoice_number="FV/PRECISION/DRAFT",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Usługa", quantity="1", unit_net_price="1.005", vat_rate="23")
    xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
    assert _tag_text(xml, "P_9A") == "1.005"
    assert _tag_text(xml, "P_11") == "1.01"


def test_draft_quantity_keeps_six_decimals_and_is_not_money_formatted() -> None:
    builder = FA3InvoiceBuilder(
        invoice_number="FV/PRECISION/DRAFT-QTY",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Usługa", quantity="0.125", unit_net_price="1000", vat_rate="23")
    xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
    assert _tag_text(xml, "P_8B") == "0.125"
    assert _tag_text(xml, "P_11") == "125.00"


def test_valid_payment_link_and_ipksef_pass_validation() -> None:
    invoice = replace(
        _payment_invoice(),
        payment_terms=PaymentTerms(payment_link=_VALID_PAYMENT_LINK, ipksef=_VALID_IPKSEF),
    )
    errors = invoice.validate().errors
    assert not errors, [issue.message for issue in errors]
    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")
    assert f"<LinkDoPlatnosci>{_VALID_PAYMENT_LINK}</LinkDoPlatnosci>" in xml
    assert f"<IPKSeF>{_VALID_IPKSEF}</IPKSeF>" in xml


def test_payment_link_without_ipksef_is_reported() -> None:
    """Dowolny URL przechodził walidację i wywalał się dopiero na schemacie."""
    invoice = replace(
        _payment_invoice(),
        payment_terms=PaymentTerms(payment_link="https://pay.example.com/invoice"),
    )
    errors = invoice.validate().errors
    assert any("payment_link" in issue.message for issue in errors), [
        issue.message for issue in errors
    ]
    with pytest.raises(FA3XmlValidationError):
        invoice.to_xml(xsd_validate=True)


def test_ipksef_with_wrong_shape_is_reported() -> None:
    invoice = replace(_payment_invoice(), payment_terms=PaymentTerms(ipksef="123"))
    errors = invoice.validate().errors
    assert any("ipksef" in issue.message for issue in errors), [
        issue.message for issue in errors
    ]


def test_contractual_currency_pln_is_reported() -> None:
    """`WalutaUmowna` nie może być PLN - schemat tego nie wymusza."""
    invoice = replace(
        _payment_invoice("FV/WAL-UMOWNA"),
        transaction_terms=TransactionTerms(
            contractual_rate=Decimal("4.5"), contractual_currency="PLN"
        ),
    )
    errors = invoice.validate().errors
    assert any("WalutaUmowna" in issue.message for issue in errors), [
        issue.message for issue in errors
    ]


def test_contractual_currency_foreign_is_accepted() -> None:
    invoice = replace(
        _payment_invoice("FV/WAL-UMOWNA-OK"),
        transaction_terms=TransactionTerms(
            contractual_rate=Decimal("4.5"), contractual_currency="EUR"
        ),
    )
    errors = invoice.validate().errors
    assert not errors, [issue.message for issue in errors]
    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")
    assert "<WalutaUmowna>EUR</WalutaUmowna>" in xml


# ---------------------------------------------------------------------------
# Regresje z audytu kodu wobec broszury MF FA(3): pola i konstrukcje, które
# schemat wymaga, a SDK pomijał - XML był odrzucany dopiero przez KSeF.
# ---------------------------------------------------------------------------


def test_attachment_text_emits_required_metadata() -> None:
    """`BlokDanych/MetaDane` jest w schemacie wymagane (minOccurs=1)."""
    builder = BasicInvoiceBuilder(invoice_number="FV/ZAL")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    builder.attachment_text("Nagłówek", "Akapit 1")
    invoice = builder.build()
    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")
    assert "<MetaDane>" in xml
    assert "<ZWartosc>Zalacznik</ZWartosc>" in xml
    assert "<Akapit>Akapit 1</Akapit>" in xml


def test_attachment_block_without_metadata_still_validates() -> None:
    """Ręcznie zbudowany blok bez metadanych też nie może łamać schematu."""
    invoice = replace(
        _payment_invoice("FV/ZAL-BLOCK"),
        attachment=Attachment((AttachmentBlock(header="H", paragraphs=("p",)),)),
    )
    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")
    assert "<BlokDanych>" in xml
    assert "<MetaDane>" in xml


def test_order_without_lines_is_rejected() -> None:
    """`Zamowienie` wymaga co najmniej jednego `ZamowienieWiersz`."""
    builder = BasicInvoiceBuilder(invoice_number="FV/ZAM")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    invoice = replace(builder.build(), order=Order.create("123.00"))
    with pytest.raises(FA3XmlValidationError, match="ZamowienieWiersz"):
        invoice.to_xml(xsd_validate=True)


def test_transport_carrier_without_address_is_rejected() -> None:
    """`AdresPrzewoznika` jest wymagany wewnątrz `Przewoznik`."""
    invoice = replace(
        _payment_invoice("FV/PRZEWOZNIK"),
        transaction_terms=TransactionTerms(
            transports=(
                Transport(
                    kind=TransportKind.ROAD,
                    carrier=InvoiceParty.polish_company(nip="9999999999", name="Przewoźnik"),
                ),
            )
        ),
    )
    with pytest.raises(FA3XmlValidationError, match="AdresPrzewoznika"):
        invoice.to_xml(xsd_validate=True)


def test_internal_identifier_is_rejected_for_the_buyer() -> None:
    """`IDWew` występuje tylko w `TPodmiot3`; nabywca go nie może nieść."""
    builder = BasicInvoiceBuilder(invoice_number="FV/IDWEW")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        replace(
            InvoiceParty.without_tax_id(name="Nabywca", address="ul. B 2"),
            identifier=PartyIdentifier.internal("1111111111-00001"),
        )
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    with pytest.raises(FA3XmlValidationError, match="IDWew"):
        builder.build().to_xml(xsd_validate=True)


def test_internal_identifier_is_allowed_for_a_third_party() -> None:
    builder = BasicInvoiceBuilder(invoice_number="FV/IDWEW-OK")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    builder.add_party(
        replace(
            InvoiceParty.without_tax_id(name="Oddział", address="ul. C 3"),
            identifier=PartyIdentifier.internal("1111111111-00001"),
        ),
        role="8",
    )
    xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
    assert "<IDWew>1111111111-00001</IDWew>" in xml


# --- 0% w draftcie: kod stawki musi przetrwać round-trip -------------------


@pytest.mark.parametrize(
    ("code", "bucket"),
    [("0 KR", "P_13_6_1"), ("0 WDT", "P_13_6_2"), ("0 EX", "P_13_6_3")],
)
def test_draft_zero_rate_subtypes_keep_their_code_and_bucket(code: str, bucket: str) -> None:
    """`0 WDT`/`0 EX` nie mogą być spłaszczane do krajowej stawki 0%."""
    builder = FA3InvoiceBuilder(
        invoice_number=f"FV/{code}",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Usługa", quantity="1", unit_net_price="100", vat_rate=code)
    draft = builder.build()
    assert draft.lines[0].vat_code == code
    found = _tag_texts(draft.to_xml(xsd_validate=True))
    assert found["P_12"] == code
    assert found[bucket] == "100.00"


def test_draft_zero_rate_code_survives_json_round_trip() -> None:
    draft = FA3Draft.from_dict(
        {
            "numer_faktury": "FV/WDT",
            "data_wystawienia": "2026-01-15",
            "sprzedawca": {"nazwa": "S", "nip": "1234567890"},
            "nabywca": {"nazwa": "B", "nip": "1111111111"},
            "pozycje": [{"opis": "WDT", "ilosc": 1, "cena_netto": 100, "vat": "0 WDT"}],
        }
    )
    assert draft.lines[0].vat_code == "0 WDT"
    assert draft.lines[0].to_dict()["vat"] == "0 WDT"


def test_draft_unknown_zero_rate_code_is_rejected() -> None:
    with pytest.raises(ValueError, match="(?i)zerowej"):
        FA3Line.from_dict({"opis": "L", "ilosc": 1, "cena_netto": 1, "vat": "0 XX"})


def test_draft_exempt_line_to_dict_uses_zw() -> None:
    line = FA3Line(
        description="Zwolniona",
        quantity=Decimal("1"),
        unit="szt",
        unit_net_price=Decimal("100"),
        vat_rate=None,
        exemption_basis="art. 43",
    )
    assert line.to_dict()["vat"] == "zw"


def test_draft_legacy_line_without_vat_code_falls_back_to_rate() -> None:
    """Starsze obiekty bez `vat_code` muszą nadal serializować się poprawnie."""
    line = FA3Line(
        description="Usługa",
        quantity=Decimal("1"),
        unit="szt",
        unit_net_price=Decimal("100"),
        vat_rate=Decimal("23"),
    )
    assert line.vat_code is None
    builder = FA3InvoiceBuilder(
        invoice_number="FV/LEGACY",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Usługa", quantity="1", unit_net_price="100", vat_rate="23")
    legacy = replace(builder.build(), lines=[line])
    found = _tag_texts(legacy.to_xml(xsd_validate=True))
    assert found["P_12"] == "23"
    assert found["P_13_1"] == "100.00"


def test_draft_legacy_zero_rate_without_code_uses_domestic_bucket() -> None:
    line = FA3Line(
        description="Gratis",
        quantity=Decimal("1"),
        unit="szt",
        unit_net_price=Decimal("100"),
        vat_rate=Decimal("0"),
    )
    assert line.vat_code is None
    builder = FA3InvoiceBuilder(
        invoice_number="FV/LEGACY-ZERO",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    builder.add_line("Gratis", quantity="1", unit_net_price="100", vat_rate="0")
    legacy = replace(builder.build(), lines=[line])
    found = _tag_texts(legacy.to_xml(xsd_validate=True))
    assert found["P_12"] == "0 KR"
    assert found["P_13_6_1"] == "100.00"


def test_parse_vat_code_accepts_decimal_and_none() -> None:
    assert parse_vat_code(None) is None
    assert parse_vat_code(Decimal("23")) == "23"
    assert parse_vat_code(23) == "23"


# ---------------------------------------------------------------------------
# Regresje z audytu branchu: kody stawek bez procentu, spójność vat_code,
# walidacja niezależna od flagi biznesowej, znaki niedozwolone w XML.
# ---------------------------------------------------------------------------



def _facets_tree() -> ET.Element:
    """Drzewo faktury zbudowanej przez publiczne API (do testów silnika facetów)."""
    builder = BasicInvoiceBuilder(invoice_number="FV/FACETS-TREE")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    return ET.fromstring(builder.build().to_xml().decode("utf-8"))

def test_parse_vat_code_normalises_numeric_zero() -> None:
    """`0.0`/`0e0`/`0,0` muszą dać pełny kod `0 KR`, nie gołe `"0"`.

    Gołe `"0"` nie należy do `TStawkaPodatku`, więc KSeF odrzucał taki dokument
    (`SCHEMAV_CVC_ENUMERATION_VALID`), a `validate()` był zielony.
    """
    for value in ("0", "0.0", "0,0", "0e0", "0E-7", "0.0%", Decimal("0.0"), 0, 0.0):
        assert parse_vat_code(value) == "0 KR", value


def test_parse_vat_code_accepts_non_percent_codes() -> None:
    """`oo`, `np I`, `np II` nie mają stawki procentowej — muszą przejść dosłownie."""
    assert parse_vat_code("oo") == "oo"
    assert parse_vat_code("np I") == "np I"
    assert parse_vat_code("np II") == "np II"
    assert parse_vat_code("np 1") == "np I"
    assert parse_vat_code("np ii") == "np II"
    assert parse_vat_rate("oo") is None
    assert parse_vat_rate("np I") is None


def test_looks_like_zero_handles_junk() -> None:
    """Wartość nieliczbowa nie może być uznana za stawkę zerową."""
    assert _looks_like_zero("0.0") is True
    assert _looks_like_zero("23") is False
    assert _looks_like_zero("zw") is False


@pytest.mark.parametrize(
    ("code", "bucket"),
    [("oo", "P_13_10"), ("np I", "P_13_8"), ("np II", "P_13_9"), ("zw", "P_13_7")],
)
def test_draft_non_percent_codes_get_their_own_bucket(code: str, bucket: str) -> None:
    """Odwrotne obciążenie i sprzedaż poza terytorium nie mogą iść do zwolnienia."""
    builder = FA3InvoiceBuilder(
        invoice_number=f"FV/{code}",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
        buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Testowa 2"),
    )
    kwargs: dict[str, str] = {"vat_rate": code}
    if code == "zw":
        kwargs["exemption_basis"] = "art. 43 ust. 1 pkt 1"
    builder.add_line("Usługa", quantity="1", unit_net_price="100", **kwargs)
    found = _tag_texts(builder.build().to_xml(xsd_validate=True))
    assert found["P_12"] == code
    assert found[bucket] == "100.00"
    assert "P_14_1" not in found


def test_draft_rejects_unknown_rate_code() -> None:
    """Kod spoza `TStawkaPodatku` musi zostać odrzucony, a nie trafić do XML."""
    with pytest.raises(ValueError, match="(?i)nieobs"):
        _draft_bucket("0 XX", Decimal("0"))


def test_draft_bucket_rejects_unknown_code() -> None:
    with pytest.raises(ValueError, match="(?i)nieobs"):
        _draft_bucket("99", None)


def test_amount_rounds_half_up_like_money() -> None:
    """Zapisywanie kwot musi używać tego samego trybu zaokrąglania co `money()`.

    `f"{value:.2f}"` zaokrąglało ROUND_HALF_EVEN, więc obciążenie 0.005 dawało
    `0.00` przy `SumaObciazen = 0.01` — dokument przeczył sam sobie.
    """
    assert _amount(Decimal("0.005")) == "0.01"
    assert _amount(Decimal("1.005")) == "1.01"
    assert _amount(Decimal("100")) == "100.00"
    assert _amount("12.5") == "12.50"


def test_amount2_accepts_string_and_decimal() -> None:
    assert _amount2("1.12345678") == "1.12345678"
    assert _amount2(Decimal("100")) == "100"


def test_money_maps_decimal_invalid_operation_to_a_readable_error() -> None:
    """`quantize` na wartości dłuższej niż 28 cyfr rzucał surowe `InvalidOperation`.

    Kontekst `decimal` ma precyzję 28 cyfr, więc `money(Decimal("1E+26"))` kończyło
    się wyjątkiem biblioteki standardowej zamiast błędem walidacji z nazwą pola.
    """
    for value in ("1E+26", "1E+40", "1" * 27, "NaN", "Infinity", "-Infinity"):
        with pytest.raises(ValueError, match="nie jest poprawną liczbą dziesiętną"):
            money(Decimal(value), field_name="unit_net_price")


def test_money_keeps_working_below_the_decimal_precision() -> None:
    """26 cyfr mieści się w precyzji kontekstu — zachowanie musi zostać bez zmian."""
    assert money(Decimal("1" * 26)) == Decimal("1" * 26 + ".00")
    assert money(Decimal("1.005")) == Decimal("1.01")


def test_rate6_maps_precision_overflow_to_a_validation_error() -> None:
    """`_rate6` kwantyzuje do 6 miejsc, więc 28 cyfr przekraczało precyzję kontekstu."""
    from ksef_client.documents.fa3.xml import _rate6

    for value in ("1E+26", "1E+40", "1" * 30):
        with pytest.raises(FA3XmlValidationError, match="nie jest poprawną liczbą dziesiętną"):
            _rate6(value, field_name="KursWaluty")
    assert _rate6("1.2345678901", field_name="KursWaluty") == "1.234568"


def test_decimal_rejects_non_finite_values_instead_of_emitting_nan() -> None:
    """`Decimal("NaN")` przechodzi `to_integral_value()`, więc do XML trafiałoby `NaN`."""
    from ksef_client.documents.fa3.xml import _decimal

    value = _decimal(Decimal("123.456"), field_name="P_11")
    assert value == "123.456"
    with pytest.raises(FA3XmlValidationError, match="Pole 'P_8B'"):
        _decimal(Decimal("NaN"), field_name="P_8B")


def test_decimal_from_value_rejects_non_finite_and_unconvertible_values() -> None:
    """Wejście do walidacji nie może przepuszczać `NaN`/`Infinity` ani rzucać wyjątku STDLIB."""
    for value in ("NaN", "Infinity", "-Infinity", Decimal("NaN"), float("nan")):
        with pytest.raises(ValueError, match="Pole 'ilosc'"):
            decimal_from_value(value, field_name="ilosc")
    with pytest.raises(ValueError, match="musi być liczbą"):
        decimal_from_value(True, field_name="ilosc")


@pytest.mark.parametrize("unit_net_price", ["1E+26", "1E+40"])
def test_draft_unit_price_beyond_decimal_precision_is_rejected_by_validation(
    unit_net_price: str,
) -> None:
    """Ścieżka użytkownika: `unit_net_price` bez precyzji `decimal` musi dać `ValueError`."""
    builder = BasicInvoiceBuilder(invoice_number="FV/PREC")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2"))
    builder.add_service_line("Usługa", quantity="1", unit_net_price=unit_net_price)

    with pytest.raises(ValueError, match="(?i)nie jest poprawną liczbą"):
        builder.build().to_xml()


def test_payment_due_description_requires_the_integer_lexical_form() -> None:
    """`<Ilosc>` to `xsd:integer`: `30.0` przechodziło kontrolę wartości, a XSD je odrzucał."""
    builder = BasicInvoiceBuilder(invoice_number="FV/ILOSC")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2"))
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    builder.payment_due_description(30.0, "dni", "data wystawienia")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Ilosc"):
        builder.build().to_xml()


def test_extract_xml_paths_handles_deep_documents() -> None:
    """Audyt schematu nie może się wywracać na głębokim dokumencie (1500 poziomów)."""
    depth = 1500
    body = "".join(f"<FaWiersz><P_7>w{i}</P_7>" for i in range(depth)) + "</FaWiersz>" * depth
    xml = (
        '<Faktura xmlns="http://crd.gov.pl/wzor/2025/06/25/13775/">' + body + "</Faktura>"
    )

    paths = xsd_audit_module.extract_xml_paths(xml)

    assert len(paths) == 2 * depth + 1
    assert "/Faktura" in paths
    assert "/Faktura/" + "/".join(["FaWiersz"] * depth) in paths
    assert "/Faktura/" + "/".join(["FaWiersz"] * depth) + "/P_7" in paths


def test_xml_illegal_control_character_is_reported() -> None:
    """Znaki spoza produkcji `Char` XML 1.0 dają bajty, których nie przyjmie parser."""
    root = _facets_tree()
    description = root.find(f".//{_q('P_7')}")
    assert description is not None
    description.text = "Usługa\x0bopis"
    issues = validate_xml_facets(root)
    assert any("niedozwolone w XML 1.0" in issue.message for issue in issues)
    assert any("U+000B" in issue.message for issue in issues)


def test_empty_required_text_is_reported() -> None:
    """`minLength=1`: pusty element nie może przejść jako „brak wartości"."""
    root = _facets_tree()
    description = root.find(f".//{_q('P_7')}")
    assert description is not None
    description.text = ""
    issues = validate_xml_facets(root)
    assert any("mniejsza niż minimum" in issue.message for issue in issues)


def test_facet_check_runs_even_without_business_validation() -> None:
    """`validate=False` wyłącza walidację biznesową, ale nie kontrolę schematu.

    Inaczej `to_xml(validate=False)` (domyślne `xsd_validate=False`) wypuszczało
    dokument łamiący kontrakt bez żadnego sygnału.
    """
    builder = BasicInvoiceBuilder(invoice_number="FV/FACETS-OFF")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    invoice = builder.build()
    broken = invoice.to_xml().decode("utf-8").replace("<P_12>23</P_12>", "<P_12>99</P_12>")
    root = ET.fromstring(broken)
    assert validate_xml_facets(root)

    # Kontrola schematu jest nadal wyłączalna świadomie.
    xml = replace(invoice, lines=()).to_xml(validate=False, facets=False)
    assert xml


def test_validation_error_message_names_element_and_rule() -> None:
    """Komunikat `to_xml()` musi wskazywać ścieżkę elementu, nie surowy SCHEMAV."""
    builder = BasicInvoiceBuilder(invoice_number="FV/FACETS-MSG")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    invoice = builder.build()
    xml = invoice.to_xml().decode("utf-8").replace("<P_12>23</P_12>", "<P_12>99</P_12>")
    root = ET.fromstring(xml)
    issues = validate_xml_facets(root)
    assert issues and all(issue.path.startswith("Faktura") for issue in issues)
    assert any(issue.element == "P_12" for issue in issues)


def test_draft_non_percent_line_does_not_require_exemption_basis() -> None:
    """`np I`/`np II`/`oo` to nie zwolnienie — nie wolno żądać podstawy prawnej."""
    for code in ("np I", "np II", "oo"):
        builder = FA3InvoiceBuilder(
            invoice_number=f"FV/{code}",
            issue_date=date(2026, 1, 15),
            seller=FA3Party(name="S", tax_id="1234567890", address="ul. A 1"),
            buyer=FA3Party(name="B", tax_id="1111111111", address="ul. B 2"),
        )
        builder.add_line("Usługa", quantity="1", unit_net_price="100", vat_rate=code)
        draft = builder.build()
        errors, _warnings = draft.validate()
        assert not errors, (code, [e.message for e in errors])


def test_draft_exempt_line_still_requires_exemption_basis() -> None:
    builder = FA3InvoiceBuilder(
        invoice_number="FV/zw",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1234567890", address="ul. A 1"),
        buyer=FA3Party(name="B", tax_id="1111111111", address="ul. B 2"),
    )
    builder.add_line("Usługa", quantity="1", unit_net_price="100", vat_rate="zw")
    # `build()` rzuca, więc sprawdzamy walidację na poziomie szkicu.
    from ksef_client.documents.fa3.models import FA3Draft

    draft = FA3Draft(
        invoice_number="FV/zw",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1234567890", address="ul. A 1"),
        buyer=FA3Party(name="B", tax_id="1111111111", address="ul. B 2"),
        lines=builder._lines,
    )
    errors, _warnings = draft.validate()
    assert any("podstawy prawnej" in issue.message for issue in errors)


def test_illegal_character_reporting_deduplicates_codes() -> None:
    """Ten sam niedozwolony znak zgłaszamy raz, żeby komunikat był czytelny."""
    from ksef_client.documents.fa3.validation.engine import _illegal_xml_characters

    assert _illegal_xml_characters("a\x0bb\x0bc") == [0x0B]
    assert _illegal_xml_characters("poprawny tekst") == []


def test_draft_bucket_rejects_unsupported_numeric_rate() -> None:
    """Stawka liczbowa spoza tabeli (np. 17%) musi zostać zgłoszona, nie wysłana."""
    with pytest.raises(ValueError, match="(?i)nieobs"):
        _draft_bucket(None, Decimal("17"))


def test_xsd_audit_covers_raw_extension_unsupported_and_notes() -> None:
    """Gałęzie audytu: mapa raw/unsupported, dobór handlera, dopasowanie i noty.

    `RAW_EXTENSION_PATHS` i `UNSUPPORTED_PATHS` są puste, bo SDK nie ma takich
    ścieżek (patrz docstring `xsd_map`), więc obie gałęzie — i zapasowy handler —
    są ćwiczone przez monkeypatch tych nazw.
    """
    raw_map = xsd_audit_module.RAW_EXTENSION_PATHS
    unsupported_map = xsd_audit_module.UNSUPPORTED_PATHS
    try:
        xsd_audit_module.RAW_EXTENSION_PATHS = {"/Faktura/Raw": "raw handler"}
        xsd_audit_module.UNSUPPORTED_PATHS = {"/Faktura/Nope": "unsupported handler"}
        raw_entry = xsd_audit_module._entry_for_element(
            XsdElement("/Faktura/Raw", "Raw", None, "1", "1"), evidence_sources=()
        )
        unsupported_entry = xsd_audit_module._entry_for_element(
            XsdElement("/Faktura/Nope", "Nope", None, "1", "1"), evidence_sources=()
        )
        nested = xsd_audit_module._entry_for_element(
            XsdElement("/Faktura/Raw/Dziecko", "Dziecko", None, "1", "1"), evidence_sources=()
        )
        assert raw_entry.status is CoverageStatus.RAW_EXTENSION
        assert unsupported_entry.status is CoverageStatus.UNSUPPORTED
        assert nested.status is CoverageStatus.RAW_EXTENSION
    finally:
        xsd_audit_module.RAW_EXTENSION_PATHS = raw_map
        xsd_audit_module.UNSUPPORTED_PATHS = unsupported_map

    # Handler dla znacznika, którego nie ma w typowanym serializatorze (albo nie
    # ma go wcale), musi mieć sensowny zapas: najpierw funkcja spoza typowanej
    # ścieżki, a dopiero potem `_domain_invoice`. Mapa miejsc emisji jest
    # podstawiana, bo na realnym `xml.py` takich znaczników nie ma.
    sites_map = xsd_audit_module._EMISSION_SITES
    try:
        xsd_audit_module._EMISSION_SITES = {
            "TylkoDraft": ("_party",),
            "BezWlasciciela": ("",),
        }
        assert xsd_audit_module._handler_name("/Faktura/TylkoDraft") == "_party"
        assert xsd_audit_module._handler_name("/Faktura/BezWlasciciela") == "_domain_invoice"
        assert xsd_audit_module._handler_name("/Faktura/Nieznany/Tag") == "_domain_invoice"
    finally:
        xsd_audit_module._EMISSION_SITES = sites_map

    # Noty dla poszczególnych sekcji dokumentu (kluczowe jest, by nota niosła
    # informację o SEKCJI, a nie o samym statusie).
    notes = {
        xsd_audit_module._coverage_note(
            path, status=CoverageStatus.PARTIALLY_SUPPORTED, evidence_sources=()
        )
        for path in (
            "/Faktura",
            "/Faktura/Fa/Adnotacje/Zwolnienie/P_19A",
            "/Faktura/Fa/Platnosc/Termin",
            "/Faktura/Fa/FaWiersz/P_7",
            "/Faktura/Fa/Zamowienie/ZamowienieWiersz/P_7Z",
            "/Faktura/Fa/P_15",
        )
    }
    assert xsd_audit_module._coverage_note(
        "/Faktura", status=CoverageStatus.PARTIALLY_SUPPORTED, evidence_sources=()
    ) == "root invoice document"
    assert "typed annotation section" in notes
    assert "typed payment section" in notes
    assert "typed line section" in notes
    assert "element emitted by the serializer" in " ".join(notes)
    # Nota domyślna pojawia się, gdy element nie należy do znanej sekcji.
    assert xsd_audit_module._coverage_note(
        "/Faktura/Naglowek", status=CoverageStatus.SUPPORTED, evidence_sources=()
    ) == "typed SDK model and serializer coverage"
    assert xsd_audit_module._coverage_note(
        "/Faktura/Fa/P_15", status=CoverageStatus.SUPPORTED, evidence_sources=("x",)
    ) == "validated by scenarios: x"
    assert "not emitted" in xsd_audit_module._coverage_note(
        "/Faktura/Fa/P_15", status=CoverageStatus.UNSUPPORTED, evidence_sources=()
    )
    assert xsd_audit_module._local_xml_name("{ns}Element") == "Element"
    assert xsd_audit_module._local_xml_name("Element") == "Element"
    assert xsd_audit_module._local_type_name(None) is None


def test_dodatkowy_opis_can_point_at_a_line() -> None:
    """`DodatkowyOpis/NrWiersza` wiąże informację z konkretną pozycją faktury."""
    builder = BasicInvoiceBuilder(invoice_number="FV/DOD")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    builder.additional_description("Licznik", "11/2023/KTW", row_number=1)
    xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
    assert "<DodatkowyOpis><NrWiersza>1</NrWiersza><Klucz>Licznik</Klucz>" in xml


def test_gross_amount_inconsistent_with_net_plus_vat_is_rejected() -> None:
    """Brutto różne od netto + VAT daje `P_15 != P_13 + P_14` — KSeF to odrzuca."""
    builder = BasicInvoiceBuilder(invoice_number="FV/GROSS-ERR")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line(
        "Usługa",
        quantity="1",
        unit_net_price="100",
        tax=VatClass.standard_23(),
        gross_amount=Decimal("999"),
    )
    with pytest.raises(ValueError, match="(?i)brutto"):
        builder.build()


def test_gross_amount_consistent_with_net_plus_vat_is_accepted() -> None:
    builder = BasicInvoiceBuilder(invoice_number="FV/GROSS-OK")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line(
        "Usługa",
        quantity="1",
        unit_net_price="100",
        tax=VatClass.standard_23(),
        gross_amount=Decimal("123"),
    )
    xml = builder.build().to_xml(xsd_validate=True).decode("utf-8")
    assert "<P_13_1>100.00</P_13_1>" in xml
    assert "<P_14_1>23.00</P_14_1>" in xml
    assert "<P_15>123.00</P_15>" in xml


def test_draft_gross_amount_inconsistent_with_net_plus_vat_is_rejected() -> None:
    """Ścieżka szkiców musi odrzucać brutto różne od netto + VAT (P_15 != P_13 + P_14)."""
    builder = FA3InvoiceBuilder(
        invoice_number="FV/GROSS-DRAFT",
        issue_date=date(2026, 1, 15),
        seller=FA3Party(name="S", tax_id="1234567890", address="ul. A 1"),
        buyer=FA3Party(name="B", tax_id="1111111111", address="ul. B 2"),
    )
    builder.add_line(
        "Usługa",
        quantity="1",
        unit_net_price="100",
        vat_rate="23",
        gross_amount="999",
    )
    with pytest.raises(ValueError, match="(?i)brutto"):
        builder.build()


def test_numeric_pattern_from_schema_is_enforced() -> None:
    """Zapis liczby musi odpowiadać wzorcowi schematu, nie tylko mieć 2 miejsca.

    `Decimal("007.50")`, `"1E+3"` i `"1."` przechodziły przez kontrolę precyzji,
    a KSeF odrzucał dokument (`SCHEMAV_CVC_PATTERN_VALID` / `CVC_DATATYPE_VALID`).
    """
    from ksef_client.documents.fa3.validation.engine import _check_text
    from ksef_client.documents.fa3.validation.facets import ILOSCI, KWOTOWY, KWOTOWY2

    for value in ("007.50", "1E+3", "1.", "+1.00", "1,50"):
        assert _check_text(value, KWOTOWY, "p", "P_15"), value
    for value in ("0", "0.5", "-0.5", "123.45", "-123.45", "1234567890123456.99"):
        assert not _check_text(value, KWOTOWY, "p", "P_15"), value
    # Zbyt długa część całkowita (schemat: 16 cyfr dla TKwotowy).
    assert _check_text("12345678901234567.00", KWOTOWY, "p", "P_15")
    assert _check_text("1.1234567", ILOSCI, "p", "P_8B")
    assert not _check_text("1.12345678", KWOTOWY2, "p", "P_9A")


def test_paired_contractual_rate_and_currency_must_be_given_together() -> None:
    """Jedno pole z pary było cicho pomijane, więc wartość znikała z dokumentu."""
    cases: tuple[dict[str, str], ...] = (
        {"contractual_rate": "4.55"},
        {"contractual_currency": "EUR"},
    )
    for kwargs in cases:
        builder = BasicInvoiceBuilder(invoice_number="FV/KU")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
        )
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        builder.transaction_terms(**kwargs)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="(?i)umown"):
            builder.build()


def test_skonto_requires_both_terms_and_amount() -> None:
    """`Skonto` ma dwa wymagane pola; jedno bez drugiego było cicho pomijane."""
    builder = BasicInvoiceBuilder(invoice_number="FV/SK")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(
        InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
    )
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    # `cash_discount()` wymaga obu argumentów, więc niepełną parę budujemy wprost.
    builder.payment(PaymentTerms(cash_discount_amount="5.00"))
    with pytest.raises(ValueError, match="(?i)skonto"):
        builder.build()


def test_attachment_table_type_and_shape_are_validated() -> None:
    """`Kol/@Typ` oraz liczba kolumn/wierszy były niepilnowane."""
    from ksef_client.documents.fa3.domain import (
        Attachment,
        AttachmentBlock,
        AttachmentTable,
    )

    def invoice_with(table: AttachmentTable):
        builder = BasicInvoiceBuilder(invoice_number="FV/TAB-V")
        builder.seller(
            InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
        )
        builder.buyer(
            InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2")
        )
        builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
        return replace(
            builder.build(),
            attachment=Attachment((AttachmentBlock(header="H", tables=(table,)),)),
        )

    invalid = [
        AttachmentTable(headers=("A",), rows=(("1",),), column_types=("bogus",)),
        AttachmentTable(headers=("A", "B"), rows=(("1", "2"),), column_types=("txt",)),
        AttachmentTable(headers=(), rows=(("1",),)),
        AttachmentTable(headers=("A",), rows=()),
        AttachmentTable(headers=tuple(f"k{i}" for i in range(21)), rows=(("1",) * 21,)),
        AttachmentTable(headers=("A",), rows=tuple(("1",) for _ in range(1001))),
        AttachmentTable(headers=("A",), rows=(("1",) * 21,)),
        AttachmentTable(headers=("A",), rows=(("1",),), footer=("1",) * 21),
    ]
    for table in invalid:
        errors = invoice_with(table).validate().errors
        assert errors, table
    assert not invoice_with(
        AttachmentTable(headers=("A",), rows=(("1",),), column_types=("txt",))
    ).validate().errors


def test_facet_describe_covers_minimum_length_and_minimum() -> None:
    """`Facet.describe()` musi opisywać także dolne granice długości i wartości."""
    from ksef_client.documents.fa3.validation.facets import Facet, FacetKind

    assert "co najmniej 3 znaków" in Facet(
        FacetKind.STRING, "X", minimum_length=3
    ).describe()
    assert "minimum 1" in Facet(FacetKind.DECIMAL, "X", minimum=Decimal("1")).describe()
    assert "maksymalnie 16 cyfr części całkowitej" in Facet(
        FacetKind.DECIMAL, "X", integer_digits=16
    ).describe()


# --- Regresje FA(3): ROZ w walucie obcej, `P_15` szkicu i pola korekty ---------


def _fa_elements(xml: bytes) -> dict[str, str]:
    """Mapa „nazwa elementu -> tekst" dla wszystkich elementów FA(3) dokumentu.

    `_tag_texts` zna wyłącznie koszyki podsumowania i kilka znaczników, a te
    regresje dotyczą też `P_14_xW`, `DoZaplaty`, `P_15ZK` i `NrFaKorygowany`.
    """
    root = ET.fromstring(xml)
    namespace = root.tag.split("}")[0].strip("{")
    prefix = f"{{{namespace}}}"
    found: dict[str, str] = {}
    for element in root.iter():
        if isinstance(element.tag, str) and element.tag.startswith(prefix):
            found[element.tag[len(prefix) :]] = element.text or ""
    return found


def _invoice_parties() -> tuple[Any, Any]:
    return (
        Party.polish_company(nip="1111111111", name="S", address="ul. Testowa 1"),
        Party.polish_company(nip="2222222222", name="N", address="ul. Kupiec 2"),
    )


def _scale_settlement_invoice(
    builder: Any,
    *,
    currency: str = "USD",
    rate: str | None = "4.000000",
) -> FA3Invoice:
    """ROZ/KOR_ROZ z wierszami 307500@8% + 4500@23% i kwotą do zapłaty 307635."""
    seller, buyer = _invoice_parties()
    builder.issued_on(date(2026, 3, 1)).seller(seller).buyer(buyer).currency(currency)
    if rate is not None:
        builder.foreign_currency_rate(rate)
    builder.settles_advance(invoice_number="FZ/1").remaining_to_pay("307635")
    builder.add_goods_line(
        "8%", quantity="1", unit_net_price="307500", tax=VatClass.reduced_8()
    )
    builder.add_goods_line("23%", quantity="1", unit_net_price="4500", tax=VatClass.standard_23())
    return builder.build()


def test_settlement_in_foreign_currency_scales_the_foreign_mirror() -> None:
    """`P_14_xW` musi być tą samą proporcją co `P_14_x` (ROZ w USD, kurs 4.0).

    Przed naprawą `_scale_settlement_summary` skalowało wyłącznie koszyki złotowe,
    więc dokument deklarował `P_14_2` = 22414.21 przy `P_14_2W` = 98400.00
    i `P_14_1` = 943.04 przy `P_14_1W` = 4140.00 — czyli pełne kwoty z wierszy,
    sprzeczne z koszykami złotowymi w tym samym dokumencie (audyt `p13_confirm` Z4).
    """
    invoice = _scale_settlement_invoice(FA3Invoice.settlement("FR/USD/SCALE"))
    found = _fa_elements(invoice.to_xml(xsd_validate=True))

    assert found["P_13_1"] == "4100.16"
    assert found["P_14_1"] == "943.04"
    assert found["P_13_2"] == "280177.59"
    assert found["P_14_2"] == "22414.21"
    assert found["P_15"] == "307635.00"
    # Tożsamość `P_15 = ΣP_13_x + ΣP_14_x` nadal zachodzi co do grosza.
    baskets = sum(
        (Decimal(found[tag]) for tag in ("P_13_1", "P_14_1", "P_13_2", "P_14_2")),
        Decimal("0.00"),
    )
    assert baskets == Decimal(found["P_15"])
    # Lustro walutowe to TA SAMA proporcja; dopuszczamy grosz różnicy, bo obie
    # strony są zaokrąglane osobno (`money(Σvat×kurs×factor)` kontra
    # `money(money(Σvat×factor)×kurs)`).
    for vat_tag, foreign_tag in (("P_14_1", "P_14_1W"), ("P_14_2", "P_14_2W")):
        expected = Decimal(found[vat_tag]) * Decimal("4")
        assert abs(Decimal(found[foreign_tag]) - expected) <= Decimal("0.01"), foreign_tag
    # ... a nie pełna kwota z wierszy, jak przed naprawą.
    assert found["P_14_1W"] != "4140.00"
    assert found["P_14_2W"] != "98400.00"


def test_settlement_correction_in_foreign_currency_scales_the_foreign_mirror() -> None:
    """`KOR_ROZ` w walucie obcej idzie tą samą gałęzią (`SETTLEMENT_SCALE_KINDS`)."""
    builder = FA3Invoice.settlement_correction("KOR_ROZ/USD/SCALE")
    builder.corrects("FR/USD/1", date(2026, 2, 1), reason="Korekta rozliczenia")
    found = _fa_elements(
        _scale_settlement_invoice(builder).to_xml(xsd_validate=True)
    )

    assert found["PrzyczynaKorekty"] == "Korekta rozliczenia"
    assert found["P_15"] == "307635.00"
    assert abs(Decimal(found["P_14_2W"]) - Decimal(found["P_14_2"]) * 4) <= Decimal("0.01")
    assert found["P_14_2W"] != "98400.00"


def test_settlement_in_pln_emits_no_foreign_mirror_fields() -> None:
    """Kontrola: ROZ w PLN (próbka MF 14) bez zmian — pól `P_14_xW` nie ma wcale."""
    found = _fa_elements(
        _scale_settlement_invoice(
            FA3Invoice.settlement("FR/PLN/SCALE"),
            currency="PLN",
            rate=None,
        ).to_xml(xsd_validate=True)
    )

    assert found["P_13_1"] == "4100.16"
    assert found["P_14_1"] == "943.04"
    assert found["P_13_2"] == "280177.59"
    assert found["P_14_2"] == "22414.21"
    assert found["P_15"] == "307635.00"
    assert not [tag for tag in found if tag.startswith("P_14_") and tag.endswith("W")]


def _settlement_draft(
    kind: FA3InvoiceKind,
    settlement_amount: str,
    *,
    advance_reference: bool = True,
) -> FA3Draft:
    """Szkic rozliczeniowy/zaliczkowy: wiersze 200@23% + 50@8% (brutto 300.00)."""
    draft = FA3Draft(
        invoice_number=f"FV/DRAFT/{kind.xml_code}",
        issue_date=date(2026, 3, 1),
        seller=FA3Party(name="S", tax_id="1111111111", address="ul. T 1"),
        buyer=FA3Party(name="N", tax_id="2222222222", address="ul. K 2"),
        lines=[
            FA3Line(
                description="A",
                quantity=Decimal("1"),
                unit="szt",
                unit_net_price=Decimal("200"),
                vat_rate=Decimal("23"),
                vat_code="23",
            ),
            FA3Line(
                description="B",
                quantity=Decimal("1"),
                unit="szt",
                unit_net_price=Decimal("50"),
                vat_rate=Decimal("8"),
                vat_code="8",
            ),
        ],
        kind=kind,
        settlement_amount=Decimal(settlement_amount),
    )
    if kind is FA3InvoiceKind.SETTLEMENT_CORRECTION:
        # Rodzaj korygujący wymaga kompletu danych korekty (`_validate_kind_specific`).
        draft = replace(
            draft,
            correction_reason="Korekta rozliczenia",
            corrected_invoice_number="FR/1",
            corrected_invoice_date=date(2026, 2, 1),
        )
    if advance_reference:
        return replace(draft, advance_invoice_number="FZ/1")
    return draft


@pytest.mark.parametrize(
    "kind",
    [FA3InvoiceKind.SETTLEMENT, FA3InvoiceKind.SETTLEMENT_CORRECTION],
)
def test_draft_settlement_takes_p15_from_the_amount_due(kind: FA3InvoiceKind) -> None:
    """Szkic ROZ/KOR_ROZ: `P_15` == `DoZaplaty`, a koszyki są proporcją tej kwoty.

    Przed naprawą `_draft_tax_summary` brało `P_15` z samych wierszy (300.00),
    a `DoZaplaty` z `settlement_amount` (100.00), więc dokument przeczył sam
    sobie (reguła [ROZ-15]), a `validate()` o tym milczał (audyt `p13_confirm` Z2).
    """
    draft = _settlement_draft(kind, "100.00")

    assert draft.validate()[0] == []
    assert draft.total_gross == Decimal("300.00")
    found = _fa_elements(draft.to_xml(xsd_validate=True))

    assert found["P_15"] == "100.00"
    assert found["DoZaplaty"] == "100.00"
    baskets = sum(
        (Decimal(found[tag]) for tag in ("P_13_1", "P_14_1", "P_13_2", "P_14_2")),
        Decimal("0.00"),
    )
    assert baskets == Decimal(found["P_15"])


def test_draft_settlement_amount_equal_to_gross_keeps_the_baskets() -> None:
    """Zgodna kwota do zapłaty nie zmienia koszyków ani `P_15`."""
    draft = _settlement_draft(FA3InvoiceKind.SETTLEMENT, "300.00")
    found = _fa_elements(draft.to_xml(xsd_validate=True))

    assert found["P_15"] == found["DoZaplaty"] == "300.00"
    assert found["P_13_1"] == "200.00"
    assert found["P_14_1"] == "46.00"
    assert found["P_13_2"] == "50.00"
    assert found["P_14_2"] == "4.00"


def test_draft_settlement_amount_mismatch_is_reported_for_advance_kind() -> None:
    """`ZAL` z `settlement_amount` różnym od `P_15` musi zostać zgłoszony.

    `Rozliczenie/DoZaplaty` jest wtedy sprzeczne z `P_15` liczoną z wierszy,
    więc reguła [ROZ-15] nie ma jak zachodzić — ścieżka typowana zgłasza to samo
    (`FA3Invoice._validate_settlement_proportion`).
    """
    draft = _settlement_draft(FA3InvoiceKind.ADVANCE, "100.00", advance_reference=False)
    errors, _warnings = draft.validate()

    assert any("Rozliczenie niespójne" in issue.message for issue in errors)
    with pytest.raises(FA3XmlValidationError, match="Rozliczenie niespójne"):
        draft.to_xml()


def test_draft_advance_with_consistent_settlement_amount_is_accepted() -> None:
    """`ZAL`, w którym `DoZaplaty` zgadza się z `P_15`, nadal się buduje."""
    draft = _settlement_draft(FA3InvoiceKind.ADVANCE, "300.00", advance_reference=False)

    assert draft.validate()[0] == []
    found = _fa_elements(draft.to_xml(xsd_validate=True))
    assert found["P_15"] == found["DoZaplaty"] == "300.00"


def _basic_invoice_for_correction() -> FA3Invoice:
    seller, buyer = _invoice_parties()
    builder = FA3Invoice.basic("FV/KOR-NA-VAT")
    builder.issued_on(date(2026, 3, 1)).seller(seller).buyer(buyer)
    builder.add_goods_line("A", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
    return builder.build()


def test_correction_fields_are_emitted_for_a_basic_invoice() -> None:
    """Pola korekty nie mogą ginąć przy rodzaju innym niż KOR/KOR_ZAL/KOR_ROZ.

    Schemat FA(3) nie warunkuje ich rodzajem faktury, a serializator wychodził
    po samym `kind`: `validate().ok` było `True`, a w XML nie było ani
    `PrzyczynaKorekty`, ani `DaneFaKorygowanej`, ani `P_15ZK`, ani
    `NrFaKorygowany` (audyt `p17_correction_fields`).
    """
    invoice = replace(
        _basic_invoice_for_correction(),
        correction_reason="Korekta ceny",
        corrected_invoices=(CorrectionReference("FV/1", date(2026, 2, 1)),),
        corrected_advance_state=CorrectedAdvanceState.create("1230.00"),
        corrected_invoice_number_override="FV/0",
    )

    assert invoice.kind is FA3InvoiceKind.BASIC
    assert invoice.validate().ok
    found = _fa_elements(invoice.to_xml(xsd_validate=True))

    assert found["RodzajFaktury"] == "VAT"
    assert found["PrzyczynaKorekty"] == "Korekta ceny"
    assert found["NrFaKorygowany"] == "FV/0"
    assert found["P_15ZK"] == "1230.00"
    assert "DaneFaKorygowanej" in found


def test_correction_fields_are_emitted_through_the_v2_builder_for_a_basic_kind() -> None:
    """`FA3InvoiceBuilderV2.corrects(...)` przy rodzaju VAT też trafia do XML."""
    seller, buyer = _invoice_parties()
    builder = FA3InvoiceBuilderV2(invoice_number="FV/KOR-V2", kind=FA3InvoiceKind.BASIC)
    builder.issued_on(date(2026, 3, 1)).seller(seller).buyer(buyer)
    builder.add_line("A", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
    builder.corrects("FV/1", date(2026, 2, 1), reason="Korekta ceny")

    invoice = builder.build()
    assert invoice.correction_reason == "Korekta ceny"
    found = _fa_elements(builder.to_xml(xsd_validate=True))

    assert found["PrzyczynaKorekty"] == "Korekta ceny"
    assert "DaneFaKorygowanej" in found


def test_correction_fields_without_a_corrected_invoice_are_reported() -> None:
    """Bez `corrected_invoices` grupy korekty nie da się wypisać — musi być błąd.

    `DaneFaKorygowanej` jest w tej samej `xsd:sequence` WYMAGANE, więc emisja
    samego `PrzyczynaKorekty` dałaby dokument odrzucany przez schemat
    (`SCHEMAV_ELEMENT_CONTENT`). Zamiast cichej utraty danych `validate()`
    zgłasza błąd, a serializator bez walidacji nie wypisuje tej grupy.
    """
    invoice = replace(_basic_invoice_for_correction(), correction_reason="Korekta ceny")
    errors = invoice.validate().errors

    assert any("invoice.correction_reason" in issue.message for issue in errors)
    assert any("corrected_invoices" in issue.message for issue in errors)
    with pytest.raises(FA3XmlValidationError, match="bez faktury korygowanej"):
        invoice.to_xml()
    assert "PrzyczynaKorekty" not in _fa_elements(invoice.to_xml(validate=False))


def _correction_kind_builder(kind: FA3InvoiceKind) -> Any:
    seller, buyer = _invoice_parties()
    if kind is FA3InvoiceKind.CORRECTION:
        builder: Any = FA3Invoice.correction("KOR/REG/1")
    elif kind is FA3InvoiceKind.ADVANCE_CORRECTION:
        builder = FA3Invoice.advance_correction("KOR_ZAL/REG/1")
    else:
        builder = FA3Invoice.settlement_correction("KOR_ROZ/REG/1")
    builder.issued_on(date(2026, 3, 1)).seller(seller).buyer(buyer)
    builder.corrects("FV/1", date(2026, 2, 1), reason="Korekta ceny")
    builder.corrected_period("2026-01")
    builder.corrected_invoice_number_override("FV/0")
    if kind is FA3InvoiceKind.SETTLEMENT_CORRECTION:
        builder.corrected_advance_state("1230.00", currency_rate="4.123456")
        builder.settles_advance(invoice_number="FZ/1").remaining_to_pay("123.00")
    else:
        builder.add_service_line("A", quantity="1", unit_net_price="100")
    return builder


@pytest.mark.parametrize(
    "kind",
    [
        FA3InvoiceKind.CORRECTION,
        FA3InvoiceKind.ADVANCE_CORRECTION,
        FA3InvoiceKind.SETTLEMENT_CORRECTION,
    ],
)
def test_correction_kinds_still_emit_correction_fields(kind: FA3InvoiceKind) -> None:
    """KOR/KOR_ZAL/KOR_ROZ emitują pola korekty tak jak dotąd."""
    builder = _correction_kind_builder(kind)
    found = _fa_elements(builder.to_xml(xsd_validate=True))

    assert found["PrzyczynaKorekty"] == "Korekta ceny"
    assert found["OkresFaKorygowanej"] == "2026-01"
    assert found["NrFaKorygowany"] == "FV/0"
    assert "DaneFaKorygowanej" in found
    if kind is FA3InvoiceKind.SETTLEMENT_CORRECTION:
        assert found["P_15ZK"] == "1230.00"
        assert found["KursWalutyZK"] == "4.123456"


def test_draft_correction_group_follows_the_data_not_the_kind() -> None:
    """Szkic wypisuje grupę korekty z danych, a bez kompletu zgłasza utratę.

    `xml._correction` działa teraz jak `_domain_correction`: komplet danych
    (przyczyna + data + numer) wystarcza niezależnie od `RodzajFaktury`, a gdy
    kompletu nie ma, `validate()` mówi wprost, że grupy nie da się wypisać.
    """
    complete = replace(
        _settlement_draft(FA3InvoiceKind.BASIC, "300.00", advance_reference=False),
        correction_reason="Korekta ceny",
        corrected_invoice_number="FV/1",
        corrected_invoice_date=date(2026, 2, 1),
    )
    found = _fa_elements(complete.to_xml(xsd_validate=True))
    assert found["RodzajFaktury"] == "VAT"
    assert found["PrzyczynaKorekty"] == "Korekta ceny"
    assert found["NrFaKorygowanej"] == "FV/1"

    incomplete = replace(complete, corrected_invoice_date=None)
    errors, _warnings = incomplete.validate()
    assert any("grupy korekty nie da się wypisać" in issue.message for issue in errors)
    with pytest.raises(FA3XmlValidationError, match="grupy korekty nie da się wypisać"):
        incomplete.to_xml()
    assert "PrzyczynaKorekty" not in _fa_elements(incomplete.to_xml(validate=False))

