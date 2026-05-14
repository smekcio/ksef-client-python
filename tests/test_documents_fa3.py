from __future__ import annotations

import json
import zipfile
from datetime import date, datetime
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from ksef_client.documents.fa3 import (
    FA3BatchDraft,
    FA3Draft,
    FA3Importer,
    FA3ImportError,
    FA3InvoiceBuilder,
    FA3InvoiceKind,
    FA3Party,
    FA3Template,
    ImportMode,
)
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
