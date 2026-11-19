from __future__ import annotations

from decimal import localcontext
from importlib import resources
from xml.etree import ElementTree as ET
from zipfile import Path as ZipPath
from zipfile import ZipFile

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
    monkeypatch.setattr(validation, "_MAX_XML_NODES", 5)
    assert validate_invoice_xml(xml).issues[0].code == "XML_LIMIT"
    monkeypatch.setattr(validation, "MAX_XML_BYTES", 5)
    assert validate_invoice_xml(b"123456").issues[0].code == "XML_LIMIT"
    assert validate_invoice_xml("ąąą").issues[0].code == "XML_LIMIT"


def test_structure_budget_counts_attributes_and_nesting_before_building_a_tree(monkeypatch):
    monkeypatch.setattr(validation, "_MAX_XML_NODES", 3)
    monkeypatch.setattr(validation, "_MAX_XML_DEPTH", 2)
    # A root and two siblings fit both limits. Validation reaches the schema check.
    assert validate_invoice_xml(b"<a><b/><c/></a>").issues[0].code == "NOT_FA3"
    for source in (b"<a><b><c/></b></a>", b'<a x="1" y="2"><b/></a>'):
        assert validate_invoice_xml(source).issues[0].code == "XML_LIMIT"


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


def test_compressed_schema_resources_support_validation_and_safe_diagnostics(
    xml, tmp_path, monkeypatch
):
    original = resources.files
    package = "ksef_client.documents.fa3.schemas"
    archive = tmp_path / "packaged-resources.zip"
    with ZipFile(archive, "w") as target:
        for schema in original(package).iterdir():
            if schema.name.endswith(".xsd"):
                target.writestr(schema.name, schema.read_bytes())

    validation._field_names.cache_clear()
    try:
        with ZipFile(archive) as source:
            monkeypatch.setattr(
                resources,
                "files",
                lambda name: ZipPath(source) if name == package else original(name),
            )
            assert validate_invoice_xml(xml).valid
            report = validate_invoice_xml(xml.replace(b"<NIP>", b"<NIP>private-"))
            assert report.issues[0].field == "NIP" and "private" not in repr(report)
    finally:
        validation._field_names.cache_clear()


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


@pytest.mark.parametrize(("flag", "role"), [("JST", "8"), ("GV", "10")])
def test_routing_requires_identity_on_each_matching_recipient(xml, flag, role):
    ns = f"{{{FA3_NAMESPACE}}}"
    root = ET.fromstring(xml)
    marker = root.find(ns + "Podmiot2/" + ns + flag)
    assert marker is not None
    marker.text = "1"
    fa = root.find(ns + "Fa")
    assert fa is not None
    index = list(root).index(fa)
    for identity, value in (("NIP", "1234567890"), ("IDWew", "1234567890-12345")):
        party = ET.Element(ns + "Podmiot3")
        identifiers = ET.SubElement(party, ns + "DaneIdentyfikacyjne")
        ET.SubElement(identifiers, ns + identity).text = value
        ET.SubElement(party, ns + "Rola").text = role
        root.insert(index, party)
    assert validate_invoice_xml(ET.tostring(root)).valid
    # An ID reported for another party cannot identify this recipient.
    last_id = identifiers[0]
    last_id.tag = ns + "BrakID"
    last_id.text = "1"
    issues = validate_invoice_xml(ET.tostring(root)).issues
    assert [(i.code, i.field) for i in issues] == [("PARTY_ROLE_REQUIRED", flag)]
    assert "IDWew" in issues[0].hint
    assert value not in repr(issues)


@pytest.mark.parametrize(
    "kind,requires_line",
    [
        ("VAT", True),
        ("UPR", True),
        ("ROZ", True),
        ("ZAL", False),
        ("KOR", False),
        ("KOR_ZAL", False),
        ("KOR_ROZ", False),
    ],
)
def test_missing_line_is_reported_only_for_unambiguous_invoice_kinds(xml, kind, requires_line):
    root = ET.fromstring(xml)
    fa = root.find(f"{{{FA3_NAMESPACE}}}Fa")
    assert fa is not None
    row = fa.find(f"{{{FA3_NAMESPACE}}}FaWiersz")
    kind_node = fa.find(f"{{{FA3_NAMESPACE}}}RodzajFaktury")
    assert row is not None and kind_node is not None
    fa.remove(row)
    kind_node.text = kind
    issues = validate_invoice_xml(ET.tostring(root)).issues
    assert not any(issue.code.startswith("SCHEMAV_") for issue in issues)
    assert (
        any(issue.field == "FaWiersz" and issue.code == "LINE_REQUIRED" for issue in issues)
        == requires_line
    )
