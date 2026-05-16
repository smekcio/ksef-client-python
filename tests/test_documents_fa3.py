from __future__ import annotations

import json
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
    TaxCategoryKind,
)
from ksef_client.documents.fa3.models import (
    FA3Line,
    FA3ValidationIssue,
    _coerce_optional_decimal,
    _first_non_empty_text,
    _optional_decimal,
    _optional_iso_date,
    _parse_iso_date,
    decimal_from_value,
    parse_vat_rate,
)
from ksef_client.documents.fa3.xml import (
    FA3XmlValidationError,
    _basic_xml_validation,
    _schema_resolver,
    _vat_rate,
    validate_fa3_xml_xsd,
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
    assert "<P_9A>0.00</P_9A>" in zero_draft.to_xml().decode("utf-8")
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
    assert len(party_errors) == 3

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
    assert str(exempt_line.effective_gross_amount) == "10.00"

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
        corrected_ksef_number="1234567890-20260101-AAAA-BB",
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
        advance_ksef_number="1234567890-20260101-AAAA-BB",
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
                ksef_number="1234567890-20260101-AAAA-BB",
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
        advance_ksef_number="1234567890-20260101-AAAA-BB",
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
        corrected_ksef_number="1234567890-20260101-AAAA-BB",
        advance_ksef_number="1234567890-20260102-AAAA-BB",
        settlement_amount=decimal_from_value("12.34", field_name="kwota"),
        payment_due_date=date(2026, 1, 31),
        payment_method="gotówka",
    )

    xml = draft.to_xml()
    xml_text = xml.decode("utf-8")

    assert b"<DataWystFaKorygowanej>2026-01-01</DataWystFaKorygowanej>" in xml
    assert b"<NrKSeF>1</NrKSeF>" in xml
    assert b"<NrKSeFFaZaliczkowej>1234567890-20260102-AAAA-BB</NrKSeFFaZaliczkowej>" in xml
    assert b"<DoZaplaty>12.34</DoZaplaty>" in xml
    assert b"<FormaPlatnosci>1</FormaPlatnosci>" in xml
    assert b"<Zaliczka>" not in xml
    assert xml_text.index("<DataWystFaKorygowanej>") < xml_text.index("<NrFaKorygowanej>")
    assert xml_text.index("<FakturaZaliczkowa>") < xml_text.index("<FaWiersz>")
    assert xml_text.index("<FaWiersz>") < xml_text.index("<Rozliczenie>")
    assert xml_text.index("<Rozliczenie>") < xml_text.index("<Platnosc>")


def test_xsd_validation_accepts_basic_generated_invoice_and_rejects_invalid_xml() -> None:
    draft = _draft("FV/XSD/1")

    xml = draft.to_xml(xsd_validate=True)
    validate_fa3_xml_xsd(xml.decode("utf-8"))

    with pytest.raises(FA3XmlValidationError):
        validate_fa3_xml_xsd(b"<Faktura />")


def test_schema_resolver_ignores_unknown_schema() -> None:
    from lxml import etree

    resolver = _schema_resolver(etree)

    assert resolver.resolve("NieznanySchemat.xsd", None, None) is None


def test_xsd_coverage_audit_lists_key_fa3_sections() -> None:
    report = audit_fa3_xsd_coverage(_audit_evidence_xml_cases())

    paths = {entry.path: entry.status for entry in report.coverage}
    supported = report.by_status(CoverageStatus.SUPPORTED)
    partial = report.by_status(CoverageStatus.PARTIALLY_SUPPORTED)
    unsupported = report.by_status(CoverageStatus.UNSUPPORTED)
    raw_extension = report.by_status(CoverageStatus.RAW_EXTENSION)
    missing = (*raw_extension, *unsupported, *partial)
    section_counts: dict[str, int] = {}
    for entry in missing:
        section = "/".join(entry.path.split("/")[:4])
        section_counts[section] = section_counts.get(section, 0) + 1
    section_debug = ", ".join(
        f"{section}={count}" for section, count in sorted(section_counts.items())
    )
    missing_paths = ", ".join(entry.path for entry in missing)

    assert len(paths) == len({element.path for element in report.elements})
    assert not raw_extension, f"RAW_EXTENSION paths: {missing_paths}"
    assert not unsupported, f"UNSUPPORTED paths: {missing_paths}"
    assert not partial, f"PARTIAL paths by section: {section_debug}; paths: {missing_paths}"
    assert len(supported) == len(report.elements) == 298
    assert paths["/Faktura/Podmiot1"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Podmiot2"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/Adnotacje"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/FaWiersz"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/Podmiot1K"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/Podmiot2K"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/WarunkiTransakcji"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Zalacznik"] is CoverageStatus.SUPPORTED
    coverage_by_path = {entry.path: entry for entry in report.coverage}
    assert coverage_by_path["/Faktura/Fa/WarunkiTransakcji"].evidence_sources
    assert coverage_by_path["/Faktura/Zalacznik"].evidence_sources


def test_xsd_coverage_audit_without_evidence_reports_missing_proof() -> None:
    report = audit_fa3_xsd_coverage()
    assert report.by_status(CoverageStatus.SUPPORTED) == ()
    assert report.by_status(CoverageStatus.PARTIALLY_SUPPORTED)


def test_xsd_audit_helper_branches_for_notes_and_path_matching() -> None:
    assert xsd_audit_module._local_xml_name("{ns}Tag") == "Tag"
    assert xsd_audit_module._local_xml_name("Tag") == "Tag"

    assert xsd_audit_module._match_path("/A/B", {"/A": "root"}) == "root"
    assert xsd_audit_module._match_path("/X", {"/A": "root"}) is None

    assert (
        xsd_audit_module._coverage_note(
            "/Faktura",
            status=CoverageStatus.SUPPORTED,
            evidence_sources=(),
        )
        == "root invoice document"
    )
    assert (
        xsd_audit_module._coverage_note(
            "/Faktura/Fa/Adnotacje/P_16",
            status=CoverageStatus.SUPPORTED,
            evidence_sources=(),
        )
        == "typed annotation section"
    )
    assert (
        xsd_audit_module._coverage_note(
            "/Faktura/Fa/Platnosc/TerminPlatnosci",
            status=CoverageStatus.SUPPORTED,
            evidence_sources=(),
        )
        == "typed payment section"
    )
    assert (
        xsd_audit_module._coverage_note(
            "/Faktura/Fa/FaWiersz/P_7",
            status=CoverageStatus.SUPPORTED,
            evidence_sources=(),
        )
        == "typed line section"
    )
    assert (
        xsd_audit_module._coverage_note(
            "/Faktura/Fa/InnaSekcja",
            status=CoverageStatus.SUPPORTED,
            evidence_sources=(),
        )
        == "typed SDK model and serializer coverage"
    )


def test_xsd_audit_entry_statuses_cover_raw_and_unsupported_paths() -> None:
    raw_map = xsd_audit_module.RAW_EXTENSION_PATHS
    unsupported_map = xsd_audit_module.UNSUPPORTED_PATHS
    supported_map = xsd_audit_module.SUPPORTED_BUILDER_PATHS
    try:
        xsd_audit_module.RAW_EXTENSION_PATHS = {"/Faktura/Raw": "raw"}
        xsd_audit_module.UNSUPPORTED_PATHS = {"/Faktura/Nope": "unsupported"}
        xsd_audit_module.SUPPORTED_BUILDER_PATHS = {"/Faktura/Mapped": "mapped"}
        raw_entry = xsd_audit_module._entry_for_element(
            XsdElement("/Faktura/Raw", "Raw", None, "1", "1"),
            evidence_sources=(),
        )
        unsupported_entry = xsd_audit_module._entry_for_element(
            XsdElement("/Faktura/Nope", "Nope", None, "1", "1"),
            evidence_sources=(),
        )
        mapped_entry = xsd_audit_module._entry_for_element(
            XsdElement("/Faktura/Mapped", "Mapped", None, "1", "1"),
            evidence_sources=(),
        )
        no_map_entry = xsd_audit_module._entry_for_element(
            XsdElement("/Faktura/Unmapped", "Unmapped", None, "1", "1"),
            evidence_sources=(),
        )
        assert raw_entry.status is CoverageStatus.RAW_EXTENSION
        assert unsupported_entry.status is CoverageStatus.UNSUPPORTED
        assert mapped_entry.status is CoverageStatus.PARTIALLY_SUPPORTED
        assert no_map_entry.status is CoverageStatus.UNSUPPORTED
    finally:
        xsd_audit_module.RAW_EXTENSION_PATHS = raw_map
        xsd_audit_module.UNSUPPORTED_PATHS = unsupported_map
        xsd_audit_module.SUPPORTED_BUILDER_PATHS = supported_map


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
                amount_due=decimal_from_value("261.40", field_name="do_zaplaty"),
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
    assert "<P_10>20.00</P_10>" in xml
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
    assert "<Zamowienie>" in advance_xml
    assert "<ZamowienieWiersz>" in advance_xml
    assert "<RodzajFaktury>ROZ</RodzajFaktury>" in settlement_xml
    assert "<FakturaZaliczkowa>" in settlement_xml
    assert "<DoZaplaty>3770.00</DoZaplaty>" in settlement_xml


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
            TransportKind.OTHER,
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
        .with_section(CorrectedAdvanceState.create("10", currency_rate="4.1"))
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
    assert VatClass.from_vat_rate("17").xml_rate == "17"
    assert VatClass.from_rate_code("0 WDT").summary_fields[0] == "P_13_6_2"
    assert VatClass.from_rate_code("0 EX").summary_fields[0] == "P_13_6_3"
    assert VatClass.from_rate_code("oo").xml_rate == "oo"
    assert VatClass.from_rate_code("np II").xml_rate == "np II"
    assert VatClass.from_rate_code("3").xml_rate == "3"
    assert VatClass.outside_country().xml_rate == "np I"
    assert VatClass.margin().xml_rate == "np I"
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

    invalid_builder = FA3InvoiceBuilderV2("", FA3InvoiceKind.BASIC)
    assert not invalid_builder.validate().ok


def test_correction_and_settlement_variant_edge_paths() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = Party.polish_company(nip="1111111111", name="Buyer", address="Addr")

    limited_builder = FA3Invoice.simplified("UPR/LIMIT/1")
    limited_builder.issued_on(date(2026, 1, 1))
    limited_builder.seller(seller)
    limited_builder.buyer(buyer)
    limited_builder.add_service_line("Line", quantity="1", unit_net_price="451")
    limited_builder.as_simplified_receipt_like()
    with pytest.raises(ValueError, match="450 PLN"):
        limited_builder.build()

    correction_builder = FA3Invoice.advance_correction("KOR/ZAL/1")
    correction_builder.issued_on(date(2026, 2, 1))
    correction_builder.seller(seller)
    correction_builder.buyer(buyer)
    correction_builder.corrects_invoice(
        number="ZAL/1",
        issue_date=date(2026, 1, 1),
        reason="Correction",
        correction_type=CorrectionType.OTHER,
        ksef_number="123456789012345678901234567890123456",
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
        (("ZAL/1", None), (None, "123456789012345678901234567890123456"))
    )
    settlement_builder.document_discount("10", reason="Discount")
    settlement_builder.remaining_to_pay("90")
    settlement_builder.add_service_line("Line", quantity="1", unit_net_price="100")
    settlement = settlement_builder.build()
    settlement_xml = settlement.to_xml().decode("utf-8")
    assert settlement_xml.count("<FakturaZaliczkowa>") == 2
    assert "<NrKSeFFaZaliczkowej>" in settlement_xml
    assert "<SumaOdliczen>10.00</SumaOdliczen>" in settlement_xml


def test_order_lines_internal_ids_default_transport_and_settle_amount_xml() -> None:
    seller = Party.polish_company(nip="1234567890", name="Seller", address="Addr")
    buyer = replace(
        Party.without_tax_id(name="Internal buyer", address="Addr"),
        identifier=PartyIdentifier.internal("INT-1"),
    )

    advance = (
        FA3Invoice.advance("ZAL/ORDER/1")
        .issued_on(date(2026, 1, 1))
        .seller(seller)
        .buyer(buyer)
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

    assert "<IDWew>INT-1</IDWew>" in xml
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
    assert resolver.resolve("unknown.xsd", None, object()) is None


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
                other_method_description="other",
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
    assert "<PlatnoscInna>1</PlatnoscInna>" in xml


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
            TransportKind.OTHER,
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
        .with_section(CorrectedAdvanceState.create("10", currency_rate="4.1"))
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
                other_method_description="other",
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
        .remaining_to_pay("100.00")
        .corrects(
            "FV/OLD/1",
            date(2026, 1, 10),
            reason="Korekta",
            ksef_number="1234567890-20260110-AAAAAA-BBBBBB-CC",
        )
        .corrected_seller(seller)
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
