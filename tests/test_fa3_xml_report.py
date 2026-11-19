from __future__ import annotations

from decimal import localcontext
from xml.etree import ElementTree as ET

import pytest

from ksef_client.documents.fa3 import FA3XmlReport, validate_invoice_xml
from ksef_client.documents.fa3 import report as validation
from ksef_client.documents.fa3.xml import FA3_NAMESPACE
from tests.test_fa3_parse import basic_invoice


@pytest.fixture
def xml():
    return basic_invoice("PRIVATE-FV-5").to_xml()


def test_report_reads_original_bytes_or_decoded_text(xml):
    decoded = xml.decode()
    utf16 = decoded.replace("encoding='utf-8'", "encoding='utf-16'").encode("utf-16")
    for source in (xml, bytearray(xml), decoded, utf16):
        assert validate_invoice_xml(source).to_dict() == {
            "valid": True,
            "issues": [],
            "truncated": False,
        }


def test_malformed_wrong_schema_and_limits(xml, monkeypatch):
    assert validate_invoice_xml(b"<other/>").issues[0].code == "NOT_FA3"
    assert validate_invoice_xml(b"<a>\n</b>").issues[0].line == 2
    assert validate_invoice_xml("<!DOCTYPE Faktura><Faktura/>".encode("utf-16")).issues[0].code == (
        "INVALID_XML"
    )
    monkeypatch.setattr(validation, "_MAX_ELEMENTS", 5)
    assert validate_invoice_xml(xml).issues[0].code == "XML_LIMIT"
    monkeypatch.setattr(validation, "MAX_XML_BYTES", 5)
    assert validate_invoice_xml(b"123456").issues[0].code == "XML_LIMIT"
    assert validate_invoice_xml("ąąą").issues[0].code == "XML_LIMIT"


def test_schema_reports_known_fields_line_and_safe_hint(xml):
    broken = xml.replace(b"<NIP>", b"\n<NIP>private-")
    result = validate_invoice_xml(broken)
    assert not result.valid and not result.truncated
    assert len(result.issues) == 2
    assert [issue.field for issue in result.issues] == ["NIP"] * 2
    first, second = (issue.line for issue in result.issues)
    assert first is not None and second is not None and first < second
    assert "10 cyfr" in result.issues[0].hint
    assert "private" not in str(result.to_dict()).lower()
    broken = xml.replace(b"<Naglowek>", b"<PrivateElement>").replace(
        b"</Naglowek>", b"</PrivateElement>"
    )
    issue = validate_invoice_xml(broken).issues[0]
    assert issue.field is None and "Naglowek" in issue.hint and "PrivateElement" not in repr(issue)


def test_xsd_invalid_suppresses_business_diagnostics_and_caps_report(xml, monkeypatch):
    monkeypatch.setattr(validation, "_MAX_ISSUES", 1)
    broken = xml.replace(b"<RodzajFaktury>VAT", b"<RodzajFaktury>KOR_ROZ")
    result = validate_invoice_xml(broken.replace(b"<NIP>", b"<NIP>x"))
    assert result.truncated and len(result.issues) == 1
    assert result.issues[0].code.startswith("SCHEMAV_")


def test_references_and_roles_in_original_xml(xml):
    broken = (
        xml.replace(b"<RodzajFaktury>VAT", b"<RodzajFaktury>KOR_ROZ")
        .replace(b"<JST>2", b"<JST>1")
        .replace(b"<GV>2", b"<GV>1")
    )
    assert [issue.field for issue in validate_invoice_xml(broken).issues] == [
        "DaneFaKorygowanej",
        "FakturaZaliczkowa",
        "JST",
        "GV",
    ]


def test_settlement_uses_original_p15_and_declared_or_itemized_adjustments(xml):
    root = ET.fromstring(xml)
    fa = root.find(f"{{{FA3_NAMESPACE}}}Fa")
    ns = f"{{{FA3_NAMESPACE}}}"
    assert fa is not None
    gross = fa.findtext(ns + "P_15")
    assert gross is not None
    settlement = ET.SubElement(fa, ns + "Rozliczenie")
    for key in ("Obciazenia", "Odliczenia"):
        adjustment = ET.SubElement(settlement, ns + key)
        ET.SubElement(adjustment, ns + "Kwota").text = "1.50"
        ET.SubElement(adjustment, ns + "Powod").text = "PRIVATE reason"
    total = ET.SubElement(settlement, ns + "SumaOdliczen")
    total.text = "1.50"
    due = ET.SubElement(settlement, ns + "DoZaplaty")
    due.text = gross
    with localcontext() as context:
        context.prec = 1
        assert validate_invoice_xml(ET.tostring(root)) == FA3XmlReport()
    total.text = "2.50"
    result = validate_invoice_xml(ET.tostring(root))
    assert [issue.code for issue in result.issues] == ["ADJUSTMENT_SUM", "AMOUNT_DUE"]
    assert "PRIVATE" not in repr(result)
    settlement.remove(due)
    assert [issue.code for issue in validate_invoice_xml(ET.tostring(root)).issues] == [
        "ADJUSTMENT_SUM"
    ]
