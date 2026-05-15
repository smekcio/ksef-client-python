from __future__ import annotations

import json
import zipfile
from dataclasses import replace
from datetime import date, datetime
from decimal import Decimal
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

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
    FA3Importer,
    FA3ImportError,
    FA3Invoice,
    FA3InvoiceBuilder,
    FA3InvoiceKind,
    FA3Party,
    FA3Template,
    Footer,
    GTUCode,
    ImportMode,
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
    TaxSummary,
    ThirdPartyRole,
    TransactionTerms,
    Transport,
    TransportKind,
    VatClass,
    audit_fa3_xsd_coverage,
    parse_fa3_xsd_elements,
)
from ksef_client.documents.fa3.domain import FA3InvoiceBuilderV2
from ksef_client.documents.fa3.importer import (
    _cell,
    _column_from_message,
    _optional_text,
    _parse_date,
    _parse_optional_date,
)
from ksef_client.documents.fa3.models import (
    FA3ImportResult,
    FA3InvalidRow,
    FA3Line,
    FA3ValidationIssue,
    _coerce_optional_decimal,
    _optional_decimal,
    _optional_iso_date,
    _parse_iso_date,
    decimal_from_value,
    parse_vat_rate,
)
from ksef_client.documents.fa3.template import REQUIRED_HEADERS, create_error_report_xlsx
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

openpyxl = pytest.importorskip("openpyxl")

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


def test_template_creates_polish_workbook_with_hidden_advanced_columns(tmp_path: Path) -> None:
    path = tmp_path / "fa3.xlsx"

    FA3Template.create_xlsx(path)

    wb = openpyxl.load_workbook(path)
    assert wb.sheetnames == ["Faktury", "Pomoc", "Słowniki"]
    ws = wb["Faktury"]
    assert ws.freeze_panes == "A3"
    assert ws.auto_filter.ref == "A2:AD2"
    headers = [ws.cell(row=2, column=index).value for index in range(1, len(REQUIRED_HEADERS) + 1)]
    assert headers == list(REQUIRED_HEADERS)
    assert ws.column_dimensions["X"].hidden is True
    assert wb["Słowniki"].sheet_state == "hidden"


def test_import_xlsx_groups_rows_and_inherits_header_fields(tmp_path: Path) -> None:
    path = tmp_path / "fa3.xlsx"
    FA3Template.create_xlsx(path, sample=False)
    wb = openpyxl.load_workbook(path)
    ws = wb["Faktury"]
    _write_row(
        ws,
        3,
        {
            "Numer faktury": "FV/1/2026",
            "Typ faktury": "podstawowa",
            "Data wystawienia": "2026-01-15",
            "Waluta": "PLN",
            "Miejsce wystawienia": "Warszawa",
            "NIP sprzedawcy": "1234567890",
            "Nazwa sprzedawcy": "Sprzedawca",
            "NIP nabywcy": "1111111111",
            "Nazwa nabywcy": "Nabywca",
            "Opis pozycji": "Usługa A",
            "Ilość": 2,
            "Jm": "szt",
            "Cena netto": 100,
            "VAT": "23",
        },
    )
    _write_row(
        ws,
        4,
        {
            "Numer faktury": "FV/1/2026",
            "Opis pozycji": "Usługa B",
            "Ilość": 1,
            "Jm": "szt",
            "Cena netto": 50,
            "VAT": "8",
        },
    )
    wb.save(path)

    result = FA3Importer.from_xlsx(path)

    assert result.errors == []
    assert len(result.valid_drafts) == 1
    draft = result.valid_drafts[0]
    assert draft.invoice_number == "FV/1/2026"
    assert len(draft.lines) == 2
    assert str(draft.total_net) == "250.00"
    assert str(draft.total_vat) == "50.00"
    assert draft.seller.name == "Sprzedawca"


def test_import_xlsx_reports_invalid_rows_and_writes_highlighted_report(tmp_path: Path) -> None:
    path = tmp_path / "fa3.xlsx"
    FA3Template.create_xlsx(path, sample=False)
    wb = openpyxl.load_workbook(path)
    ws = wb["Faktury"]
    _write_valid_row(ws, 3, "FV/OK/1")
    _write_valid_row(ws, 4, "FV/BAD/1", vat="oops")
    wb.save(path)

    result = FA3Importer.from_xlsx(path)

    assert [draft.invoice_number for draft in result.valid_drafts] == ["FV/OK/1"]
    assert result.invalid_rows[0].row_number == 4
    assert "musi być liczbą" in result.errors[0].message

    report_path = tmp_path / "raport.xlsx"
    result.to_error_report_xlsx(report_path)
    report = openpyxl.load_workbook(report_path)
    report_ws = report["Raport błędów"]
    assert report_ws.cell(row=4, column=len(REQUIRED_HEADERS) + 1).value == "Błąd"
    assert report_ws.cell(row=4, column=18).fill.fgColor.rgb == "00F8CBAD"


def test_import_xlsx_amount_override_is_warning_not_silent(tmp_path: Path) -> None:
    path = tmp_path / "fa3.xlsx"
    FA3Template.create_xlsx(path, sample=False)
    wb = openpyxl.load_workbook(path)
    ws = wb["Faktury"]
    _write_valid_row(ws, 3, "FV/WARN/1")
    _write_row(ws, 3, {"Wartość brutto": 130})
    wb.save(path)

    result = FA3Importer.from_xlsx(path)

    assert len(result.valid_drafts) == 1
    assert result.errors == []
    assert "override" in result.warnings[0].message
    assert str(result.valid_drafts[0].total_gross) == "130.00"

    report_path = tmp_path / "warning-report.xlsx"
    result.to_error_report_xlsx(report_path)
    report = openpyxl.load_workbook(report_path)
    assert report["Raport błędów"].cell(row=3, column=21).fill.fgColor.rgb == "00FFF2CC"


def test_import_modes_fail_fast_and_validate_only(tmp_path: Path) -> None:
    path = tmp_path / "fa3.xlsx"
    FA3Template.create_xlsx(path, sample=False)
    wb = openpyxl.load_workbook(path)
    ws = wb["Faktury"]
    _write_valid_row(ws, 3, "FV/VALIDATE/1")
    _write_valid_row(ws, 4, "FV/FAIL/1", issue_date="15/01/2026")
    wb.save(path)

    validate_only = FA3Importer.from_xlsx(path, mode=ImportMode.VALIDATE_ONLY)
    assert validate_only.valid_drafts == []
    assert validate_only.errors

    with pytest.raises(FA3ImportError):
        FA3Importer.from_xlsx(path, mode=ImportMode.FAIL_FAST)


def test_xlsx_reports_kind_specific_business_errors(tmp_path: Path) -> None:
    path = tmp_path / "fa3.xlsx"
    FA3Template.create_xlsx(path, sample=False)
    wb = openpyxl.load_workbook(path)
    ws = wb["Faktury"]
    _write_invoice_kind_row(ws, 3, FA3InvoiceKind.CORRECTION, "FV/KOR/NO-DATE")
    _write_row(ws, 3, {"Data faktury korygowanej": ""})
    _write_invoice_kind_row(ws, 4, FA3InvoiceKind.CORRECTION, "FV/KOR/NO-NUMBER")
    _write_row(
        ws,
        4,
        {
            "Numer faktury korygowanej": "",
            "Numer KSeF faktury korygowanej": "1234567890-20260101-AAAA-BB",
        },
    )
    _write_invoice_kind_row(ws, 5, FA3InvoiceKind.SETTLEMENT, "FV/ROZ/NO-ADVANCE")
    _write_row(ws, 5, {"Numer faktury zaliczkowej": ""})
    wb.save(path)

    result = FA3Importer.from_xlsx(path)

    assert result.valid_drafts == []
    messages = " ".join(issue.message for issue in result.errors)
    assert "data faktury korygowanej" in messages
    assert "numer faktury korygowanej" in messages
    assert "numer faktury zaliczkowej" in messages


def test_missing_required_template_column_is_structural_error(tmp_path: Path) -> None:
    path = tmp_path / "broken.xlsx"
    workbook = openpyxl.Workbook()
    workbook.active.title = "Faktury"
    workbook.active.cell(row=2, column=1, value="Numer faktury")
    workbook.save(path)

    result = FA3Importer.from_xlsx(path)

    assert result.valid_drafts == []
    assert "Brak kolumn" in result.errors[0].message


def test_reordered_template_headers_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "reordered.xlsx"
    FA3Template.create_xlsx(path, sample=False)
    wb = openpyxl.load_workbook(path)
    ws = wb["Faktury"]
    ws.cell(row=2, column=1).value = "Typ faktury"
    ws.cell(row=2, column=2).value = "Numer faktury"
    _write_valid_row(ws, 3, "FV/REORDER/1")
    wb.save(path)

    result = FA3Importer.from_xlsx(path)

    assert result.valid_drafts == []
    assert "kolejności" in result.errors[0].message


def test_missing_invoice_sheet_and_fail_fast_structural_error(tmp_path: Path) -> None:
    path = tmp_path / "broken.xlsx"
    workbook = openpyxl.Workbook()
    workbook.active.title = "Nie ten arkusz"
    workbook.save(path)

    result = FA3Importer.from_xlsx(path)
    assert "Brakuje arkusza" in result.errors[0].message

    with pytest.raises(FA3ImportError):
        FA3Importer.from_xlsx(path, mode=ImportMode.FAIL_FAST)


def test_xlsx_missing_invoice_number_and_line_required_fields(tmp_path: Path) -> None:
    path = tmp_path / "fa3.xlsx"
    FA3Template.create_xlsx(path, sample=False)
    wb = openpyxl.load_workbook(path)
    ws = wb["Faktury"]
    _write_valid_row(ws, 3, "")
    _write_valid_row(ws, 4, "FV/MISS/1")
    _write_row(ws, 4, {"Opis pozycji": ""})
    wb.save(path)

    result = FA3Importer.from_xlsx(path)

    assert [row.row_number for row in result.invalid_rows] == [3, 4]
    assert any(issue.column == "Numer faktury" for issue in result.errors)
    assert any(issue.column == "Opis pozycji" for issue in result.errors)

    with pytest.raises(FA3ImportError):
        FA3Importer.from_xlsx(path, mode=ImportMode.FAIL_FAST)


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


def test_json_import_invalid_payload_and_fail_fast(tmp_path: Path) -> None:
    json_path = tmp_path / "bad-shape.json"
    json_path.write_text(json.dumps({"faktury": [{"data_wystawienia": ""}]}), encoding="utf-8")

    result = FA3Importer.from_json(json_path)
    assert "JSON draft jest nieprawidłowy" in result.errors[0].message

    with pytest.raises(FA3ImportError):
        FA3Importer.from_json(json_path, mode=ImportMode.FAIL_FAST)


def test_json_import_valid_and_validate_only(tmp_path: Path) -> None:
    json_path = tmp_path / "ok.json"
    FA3BatchDraft((_draft("FV/JSON/OK"),)).to_json(json_path)

    result = FA3Importer.from_json(json_path)
    validate_only = FA3Importer.from_json(json_path, mode=ImportMode.VALIDATE_ONLY)

    assert [draft.invoice_number for draft in result.valid_drafts] == ["FV/JSON/OK"]
    assert validate_only.valid_drafts == []


@pytest.mark.parametrize(("kind", "code", "extra"), ALL_INVOICE_KIND_CASES)
def test_all_invoice_kinds_are_exported_to_xml(
    kind: FA3InvoiceKind,
    code: str,
    extra: dict[str, Any],
) -> None:
    draft = _draft(f"FV/{code}/1", kind=kind, **extra)

    xml = draft.to_xml()

    assert f"<RodzajFaktury>{code}</RodzajFaktury>".encode() in xml


@pytest.mark.parametrize(("kind", "code", "extra"), ALL_INVOICE_KIND_CASES)
def test_all_invoice_kinds_pass_xsd_validation(
    kind: FA3InvoiceKind,
    code: str,
    extra: dict[str, Any],
) -> None:
    draft = _draft(f"FV/{code}/XSD", kind=kind, **extra)

    xml = draft.to_xml(xsd_validate=True)

    assert f"<RodzajFaktury>{code}</RodzajFaktury>".encode() in xml


@pytest.mark.parametrize(("kind", "code", "_extra"), ALL_INVOICE_KIND_CASES)
def test_xlsx_import_all_invoice_kinds_can_export_xsd_valid_xml(
    tmp_path: Path,
    kind: FA3InvoiceKind,
    code: str,
    _extra: dict[str, Any],
) -> None:
    path = tmp_path / f"{code}.xlsx"
    FA3Template.create_xlsx(path, sample=False)
    wb = openpyxl.load_workbook(path)
    ws = wb["Faktury"]
    _write_invoice_kind_row(ws, 3, kind, f"FV/{code}/XLSX")
    wb.save(path)

    result = FA3Importer.from_xlsx(path)

    assert result.errors == []
    assert len(result.valid_drafts) == 1
    draft = result.valid_drafts[0]
    assert draft.kind is kind
    draft.to_xml(xsd_validate=True)


def test_json_import_reports_business_errors(tmp_path: Path) -> None:
    json_path = tmp_path / "bad.json"
    json_path.write_text(
        json.dumps(
            {
                "faktury": [
                    {
                        **_draft("FV/KOR/BAD").to_dict(),
                        "typ_faktury": "korygująca",
                        "korekta": {},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = FA3Importer.from_json(json_path)

    assert result.valid_drafts == []
    assert result.invalid_rows[0].invoice_number == "FV/KOR/BAD"
    assert "Korekta" in result.errors[0].message

    with pytest.raises(FA3ImportError):
        FA3Importer.from_json(json_path, mode=ImportMode.FAIL_FAST)


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
    with pytest.raises(ValueError, match="Nieznany typ"):
        FA3InvoiceKind.parse("dziwna")
    with pytest.raises(ValueError, match="wymagane"):
        decimal_from_value("", field_name="kwota")
    with pytest.raises(ValueError, match="Data jest wymagana"):
        _parse_iso_date("")

    assert _parse_iso_date(date(2026, 1, 15)) == date(2026, 1, 15)
    assert _optional_iso_date("2026-01-16") == date(2026, 1, 16)
    assert _parse_date(date(2026, 1, 17), "Data") == date(2026, 1, 17)
    assert _parse_date(datetime(2026, 1, 18), "Data") == date(2026, 1, 18)
    assert _parse_optional_date("2026-01-19", "Data") == date(2026, 1, 19)
    assert _optional_text(None) is None
    assert _cell({"__row_number__": 9}, None) == ""
    assert _cell({"__row_number__": 9}, "Nieistniejąca") == "wiersz 9, kolumna Nieistniejąca"
    assert _column_from_message("bez nazwy kolumny") is None
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

    bad_line = FA3Line(
        description="",
        quantity=decimal_from_value("0", field_name="ilosc"),
        unit="szt",
        unit_net_price=decimal_from_value("-1", field_name="cena"),
        vat_rate=decimal_from_value("-1", field_name="vat"),
    )
    assert len(bad_line.validate()[0]) == 4


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


def test_error_report_ignores_unknown_locations(tmp_path: Path) -> None:
    result = FA3ImportResult(
        invalid_rows=[
            FA3InvalidRow(
                row_number=3,
                invoice_number="FV/X",
                row_data={"Numer faktury": "FV/X"},
                errors=(FA3ValidationIssue("Błąd", row_number=3, column=None),),
            )
        ],
        warnings=[
            FA3ValidationIssue("Ostrzeżenie", row_number=99, column="VAT", severity="warning")
        ],
        source_rows=[{"__row_number__": 3, "Numer faktury": "FV/X"}],
        headers=list(REQUIRED_HEADERS),
    )

    path = tmp_path / "report.xlsx"
    create_error_report_xlsx(result, path)

    assert openpyxl.load_workbook(path)["Raport błędów"].cell(row=3, column=31).value == "Błąd"


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
    report = audit_fa3_xsd_coverage()

    paths = {entry.path: entry.status for entry in report.coverage}

    assert len(paths) == len({element.path for element in report.elements})
    assert not report.by_status(CoverageStatus.RAW_EXTENSION)
    assert not report.by_status(CoverageStatus.UNSUPPORTED)
    assert paths["/Faktura/Podmiot1"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Podmiot2"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/Adnotacje"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/FaWiersz"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/Podmiot1K"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/Podmiot2K"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/Zamowienie"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Fa/WarunkiTransakcji"] is CoverageStatus.SUPPORTED
    assert paths["/Faktura/Zalacznik"] is CoverageStatus.SUPPORTED


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
            tax=VatClass.standard_23(),
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

    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")

    assert "<KodUE>DE</KodUE>" in xml
    assert "<Podmiot3>" in xml
    assert "<P_10>20.00</P_10>" in xml
    assert "<P_13_1>180.00</P_13_1>" in xml
    assert "<P_14_1>41.40</P_14_1>" in xml
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
            tax=VatClass.standard_23(),
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

    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")

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

    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")

    assert xml.count("<DaneFaKorygowanej>") == 2
    assert "<TypKorekty>1</TypKorekty>" in xml
    assert "<Podmiot1K>" in xml
    assert "<Podmiot2K>" in xml
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

    xml = invoice.to_xml(xsd_validate=True).decode("utf-8")

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
        .partially_paid(
            "12.30",
            date(2026, 4, 3),
            other_method_description="barter",
        )
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
        .attachment_text("Tekst", "Akapit")
        .attachment_table(header="Tabela", columns=("A",), rows=(("1",),), description="Opis")
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
    assert "<P_22C>10</P_22C>" in xml
    assert "<P_22D>5</P_22D>" in xml
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
        .period(date(2026, 1, 1), date(2026, 1, 31))
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


def _write_valid_row(
    ws: Any,
    row: int,
    invoice_number: str,
    *,
    vat: str = "23",
    issue_date: str = "2026-01-15",
) -> None:
    _write_row(
        ws,
        row,
        {
            "Numer faktury": invoice_number,
            "Typ faktury": "podstawowa",
            "Data wystawienia": issue_date,
            "Waluta": "PLN",
            "Miejsce wystawienia": "Warszawa",
            "NIP sprzedawcy": "1234567890",
            "Nazwa sprzedawcy": "Sprzedawca",
            "NIP nabywcy": "1111111111",
            "Nazwa nabywcy": "Nabywca",
            "Opis pozycji": "Usługa",
            "Ilość": 1,
            "Jm": "szt",
            "Cena netto": 100,
            "VAT": vat,
        },
    )


def _write_invoice_kind_row(
    ws: Any,
    row: int,
    kind: FA3InvoiceKind,
    invoice_number: str,
) -> None:
    _write_valid_row(ws, row, invoice_number)
    values: dict[str, object] = {"Typ faktury": kind.value}
    if kind in {
        FA3InvoiceKind.CORRECTION,
        FA3InvoiceKind.ADVANCE_CORRECTION,
        FA3InvoiceKind.SETTLEMENT_CORRECTION,
    }:
        values.update(
            {
                "Przyczyna korekty": "Korekta",
                "Numer faktury korygowanej": "FV/OLD/1",
                "Data faktury korygowanej": "2026-01-01",
            }
        )
    if kind in {FA3InvoiceKind.SETTLEMENT, FA3InvoiceKind.SETTLEMENT_CORRECTION}:
        values.update(
            {
                "Numer faktury zaliczkowej": "FV/ZAL/1",
                "Kwota rozliczenia": 123,
            }
        )
    _write_row(ws, row, values)


def _write_row(ws: Any, row: int, values: dict[str, object]) -> None:
    for index, header in enumerate(REQUIRED_HEADERS, start=1):
        if header in values:
            ws.cell(row=row, column=index, value=values[header])


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
