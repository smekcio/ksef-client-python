from __future__ import annotations

from dataclasses import replace
from datetime import date
from decimal import Decimal
from typing import Any
from xml.etree import ElementTree as ET

import pytest

from ksef_client.documents.fa3 import (
    FA3Invoice,
    FA3ParseError,
    InvoiceLine,
    MarginProcedure,
    NewTransportMeans,
    Party,
    PartyIdentifierKind,
    TaxCategory,
    ThirdPartyRole,
    VatClass,
    parse_invoice_xml,
)
from ksef_client.documents.fa3.parse import MAX_PARSE_WARNINGS
from ksef_client.documents.fa3.sections import PaymentDue
from ksef_client.documents.fa3.xml import FA3_NAMESPACE

NS = {"fa": FA3_NAMESPACE}

SELLER = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
BUYER = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")


def _base() -> bytes:
    invoice = (
        FA3Invoice.basic("FV/ERR")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line(
            "Usługa",
            quantity="1",
            unit_net_price="100",
            tax=VatClass.standard_23(),
        )
        .build()
    )
    return invoice.to_xml()


def _root(xml: bytes) -> ET.Element:
    return ET.fromstring(xml)


def _dump(root: ET.Element) -> bytes:
    return ET.tostring(root, encoding="utf-8")


def _normalize(path: str) -> str:
    if path == "fa:Faktura":
        return ""
    prefix = "fa:Faktura/"
    return path[len(prefix) :] if path.startswith(prefix) else path


def _find(root: ET.Element, path: str) -> ET.Element:
    normalized = _normalize(path)
    if not normalized:
        return root
    element = root.find(normalized, NS)
    assert element is not None, f"brak {path}"
    return element


def _mutate(xml: bytes, callback: object) -> bytes:
    root = _root(xml)
    callback(root)  # type: ignore[operator]
    return _dump(root)


def _drop(root: ET.Element, path: str) -> None:
    normalized = _normalize(path)
    parent_path, _, tag = normalized.rpartition("/")
    parent = root.find(parent_path, NS) if parent_path else root
    assert parent is not None
    element = parent.find(tag, NS)
    assert element is not None
    parent.remove(element)


def _set(root: ET.Element, path: str, value: str) -> None:
    _find(root, path).text = value


def _add(root: ET.Element, path: str, tag: str, text: str | None = None) -> ET.Element:
    parent = _find(root, path)
    element = ET.SubElement(parent, f"{{{FA3_NAMESPACE}}}{tag}")
    element.text = text
    return element


def _replace_identity(root: ET.Element, party_path: str, values: dict[str, str]) -> None:
    identity = _find(root, f"{party_path}/fa:DaneIdentyfikacyjne")
    for child in list(identity):
        identity.remove(child)
    for tag, value in values.items():
        element = ET.SubElement(identity, f"{{{FA3_NAMESPACE}}}{tag}")
        element.text = value


def _parse(xml: bytes) -> FA3Invoice:
    return parse_invoice_xml(xml)


# --- wejście i nagłówek ---------------------------------------------------


def test_parse_rejects_non_text_input() -> None:
    with pytest.raises(FA3ParseError, match="XML musi być tekstem"):
        parse_invoice_xml(123)  # type: ignore[arg-type]


def test_parse_rejects_oversized_document(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ksef_client.documents.fa3.parse.MAX_XML_BYTES", 10)

    with pytest.raises(FA3ParseError, match="limit"):
        parse_invoice_xml(b"<Faktura/>" + b" " * 20)


def test_parse_rejects_doctype_with_entity() -> None:
    xml = b'<?xml version="1.0"?><!DOCTYPE Faktura [<!ENTITY x "y">]><Faktura/>'

    with pytest.raises(FA3ParseError, match="DOCTYPE/ENTITY"):
        parse_invoice_xml(xml)


def test_parse_rejects_entity_declaration_outside_doctype() -> None:
    # `<!ENTITY>` w prologu nie jest poprawnym XML-em — dokument musi zostać
    # odrzucony, choć komunikat dotyczy składni, a nie samej deklaracji DTD.
    with pytest.raises(FA3ParseError):
        parse_invoice_xml(b"<!ENTITY x 'y'><Faktura/>")


def test_parse_rejects_malformed_xml() -> None:
    with pytest.raises(FA3ParseError, match="Nieprawidłowy XML"):
        parse_invoice_xml("<Faktura>")


def test_parse_rejects_wrong_root() -> None:
    with pytest.raises(FA3ParseError, match="Oczekiwano elementu głównego"):
        parse_invoice_xml('<Faktura xmlns="urn:other"/>')


def test_parse_warns_about_missing_header() -> None:
    xml = _mutate(_base(), lambda root: _drop(root, "fa:Naglowek"))

    invoice = _parse(xml)

    assert any("Naglowek" in warning.message for warning in invoice.warnings)


def test_parse_rejects_wrong_form_code() -> None:
    xml = _mutate(_base(), lambda root: _set(root, "fa:Naglowek/fa:KodFormularza", "XX"))

    with pytest.raises(FA3ParseError, match="KodFormularza"):
        _parse(xml)


def test_parse_warns_about_unknown_schema_version() -> None:
    def _change(root: ET.Element) -> None:
        _find(root, "fa:Naglowek/fa:KodFormularza").set("wersjaSchemy", "2-0E")

    invoice = _parse(_mutate(_base(), _change))

    assert any("wersja schematu" in warning.message for warning in invoice.warnings)


def test_parse_warns_about_unknown_elements() -> None:
    def _change(root: ET.Element) -> None:
        _add(root, "fa:Faktura", "Nieznany")
        _add(root, "fa:Faktura/fa:Naglowek", "NieznanyNaglowek")
        _add(root, "fa:Faktura/fa:Podmiot1", "NieznanyPodmiot")
        _add(root, "fa:Faktura/fa:Podmiot2", "NieznanyNabywca")
        _add(root, "fa:Faktura/fa:Fa", "NieznanyFa")
        _add(root, "fa:Faktura/fa:Fa/fa:Adnotacje", "NieznaneAdnotacje")
        _add(root, "fa:Faktura/fa:Fa/fa:FaWiersz", "NieznanyWiersz")

    invoice = _parse(_mutate(_base(), _change))
    messages = " ".join(warning.message for warning in invoice.warnings)

    for name in (
        "Nieznany",
        "NieznanyNaglowek",
        "NieznanyPodmiot",
        "NieznanyNabywca",
        "NieznanyFa",
        "NieznaneAdnotacje",
        "NieznanyWiersz",
    ):
        assert name in messages


# --- wymagane elementy ----------------------------------------------------


@pytest.mark.parametrize(
    ("path", "match"),
    [
        ("fa:Faktura/fa:Podmiot1", "Podmiot1"),
        ("fa:Faktura/fa:Podmiot2", "Podmiot2"),
        ("fa:Faktura/fa:Fa", "Fa"),
        ("fa:Faktura/fa:Fa/fa:P_2", "P_2"),
        ("fa:Faktura/fa:Fa/fa:P_1", "P_1"),
        ("fa:Faktura/fa:Fa/fa:KodWaluty", "KodWaluty"),
        ("fa:Faktura/fa:Fa/fa:RodzajFaktury", "RodzajFaktury"),
        ("fa:Faktura/fa:Podmiot1/fa:DaneIdentyfikacyjne", "DaneIdentyfikacyjne"),
        ("fa:Faktura/fa:Podmiot1/fa:Adres/fa:AdresL1", "AdresL1"),
        ("fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_7", "P_7"),
        ("fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_8B", "P_8B"),
    ],
)
def test_parse_rejects_missing_required_elements(path: str, match: str) -> None:
    xml = _mutate(_base(), lambda root: _drop(root, path))

    with pytest.raises(FA3ParseError, match=match):
        _parse(xml)


def test_parse_rejects_unknown_invoice_kind() -> None:
    xml = _mutate(_base(), lambda root: _set(root, "fa:Faktura/fa:Fa/fa:RodzajFaktury", "XYZ"))

    with pytest.raises(FA3ParseError, match="RodzajFaktury"):
        _parse(xml)


# --- wartości -------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "value", "match"),
    [
        ("fa:Faktura/fa:Fa/fa:P_1", "not-a-date", "poprawną datą"),
        ("fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_8B", "abc", "nie jest liczbą"),
        ("fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_8B", "NaN", "skończoną liczbą"),
        ("fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_11", "abc", "nie jest liczbą"),
    ],
)
def test_parse_rejects_invalid_values(path: str, value: str, match: str) -> None:
    xml = _mutate(_base(), lambda root: _set(root, path, value))

    with pytest.raises(FA3ParseError, match=match):
        _parse(xml)


def test_parse_rejects_invalid_discount_value() -> None:
    xml = _mutate(
        _base(),
        lambda root: _add(root, "fa:Faktura/fa:Fa/fa:FaWiersz", "P_10", "abc"),
    )

    with pytest.raises(FA3ParseError, match="nie jest liczbą"):
        _parse(xml)


def test_parse_rejects_invalid_xii_value() -> None:
    def _change(root: ET.Element) -> None:
        _drop(root, "fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_12")
        _add(root, "fa:Faktura/fa:Fa/fa:FaWiersz", "P_12_XII", "abc")

    with pytest.raises(FA3ParseError, match="nie jest liczbą"):
        _parse(_mutate(_base(), _change))


def test_parse_rejects_unknown_vat_code() -> None:
    xml = _mutate(_base(), lambda root: _set(root, "fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_12", "99"))

    with pytest.raises(FA3ParseError, match="P_12"):
        _parse(xml)


def test_parse_rejects_line_without_vat_code() -> None:
    xml = _mutate(_base(), lambda root: _drop(root, "fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_12"))

    with pytest.raises(FA3ParseError, match="brak stawki"):
        _parse(xml)


def test_parse_accepts_line_with_xii_rate() -> None:
    def _change(root: ET.Element) -> None:
        _drop(root, "fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_12")
        _add(root, "fa:Faktura/fa:Fa/fa:FaWiersz", "P_12_XII", "12")

    invoice = _parse(_mutate(_base(), _change))

    assert invoice.lines[0].tax.kind is TaxCategory.xii("12").kind
    assert invoice.lines[0].tax.xii_rate == Decimal("12")


def test_parse_rejects_invalid_transport_datetime() -> None:
    invoice = (
        FA3Invoice.basic("FV/DATE")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .contract(number="UM/1", date=date(2026, 1, 1))
        .build()
    )

    def _change(root: ET.Element) -> None:
        transport = _add(root, "fa:Faktura/fa:Fa/fa:WarunkiTransakcji", "Transport")
        ET.SubElement(transport, f"{{{FA3_NAMESPACE}}}DataGodzRozpTransportu").text = "zła"

    with pytest.raises(FA3ParseError, match="znacznikiem czasu"):
        _parse(_mutate(invoice.to_xml(), _change))


# --- identyfikatory -------------------------------------------------------


def test_parse_eu_vat_identifier() -> None:
    xml = _mutate(
        _base(),
        lambda root: _replace_identity(
            root,
            "fa:Faktura/fa:Podmiot2",
            {"KodUE": "DE", "NrVatUE": "DE123456789", "Nazwa": "Nabywca UE"},
        ),
    )

    invoice = _parse(xml)

    assert invoice.buyer.identifier.kind is PartyIdentifierKind.EU_VAT
    assert invoice.buyer.identifier.country_code == "DE"


def test_parse_rejects_incomplete_eu_identifier() -> None:
    xml = _mutate(
        _base(),
        lambda root: _replace_identity(
            root, "fa:Faktura/fa:Podmiot2", {"KodUE": "DE", "Nazwa": "Nabywca"}
        ),
    )

    with pytest.raises(FA3ParseError, match="KodUE"):
        _parse(xml)


def test_parse_foreign_identifier() -> None:
    xml = _mutate(
        _base(),
        lambda root: _replace_identity(
            root,
            "fa:Faktura/fa:Podmiot2",
            {"KodKraju": "US", "NrID": "12345", "Nazwa": "Buyer"},
        ),
    )

    invoice = _parse(xml)

    assert invoice.buyer.identifier.country_code == "US"
    assert invoice.buyer.identifier.value == "12345"


def test_parse_rejects_foreign_identifier_without_number() -> None:
    xml = _mutate(
        _base(),
        lambda root: _replace_identity(
            root, "fa:Faktura/fa:Podmiot2", {"KodKraju": "US", "Nazwa": "Buyer"}
        ),
    )

    with pytest.raises(FA3ParseError, match="NrID"):
        _parse(xml)


def test_parse_brak_id_identifier() -> None:
    xml = _mutate(
        _base(),
        lambda root: _replace_identity(
            root, "fa:Faktura/fa:Podmiot2", {"BrakID": "1", "Nazwa": "Anonim"}
        ),
    )

    invoice = _parse(xml)

    assert invoice.buyer.identifier.kind is PartyIdentifierKind.NONE


def test_parse_internal_identifier_for_third_party() -> None:
    extra = Party.polish_company(nip="3333333333", name="Trzeci", address="Adres 3")
    invoice = (
        FA3Invoice.basic("FV/IDWEW")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_party(extra, ThirdPartyRole.RECIPIENT)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _replace_identity(
            root,
            "fa:Faktura/fa:Podmiot3",
            {"IDWew": "WEW-1", "Nazwa": "Trzeci"},
        ),
    )

    parsed = _parse(xml)

    assert parsed.additional_parties[0].identifier.kind is PartyIdentifierKind.INTERNAL


def test_parse_rejects_missing_identifier() -> None:
    xml = _mutate(
        _base(),
        lambda root: _replace_identity(
            root, "fa:Faktura/fa:Podmiot2", {"Nazwa": "Bez identyfikatora"}
        ),
    )

    with pytest.raises(FA3ParseError, match="brak identyfikatora"):
        _parse(xml)


# --- role podmiotów -------------------------------------------------------


def test_parse_rejects_unknown_third_party_role() -> None:
    extra = Party.polish_company(nip="3333333333", name="Trzeci", address="Adres 3")
    invoice = (
        FA3Invoice.basic("FV/ROLE")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_party(extra, ThirdPartyRole.RECIPIENT)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _set(root, "fa:Faktura/fa:Podmiot3/fa:Rola", "99"),
    )

    with pytest.raises(FA3ParseError, match="rola podmiotu trzeciego"):
        _parse(xml)


def test_parse_rejects_unknown_authorized_role() -> None:
    authorized = Party.polish_company(nip="2222222222", name="Auth", address="Auth A")
    from ksef_client.documents.fa3 import AuthorizedPartyRole

    invoice = (
        FA3Invoice.basic("FV/AUTH")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .authorized_party(authorized, AuthorizedPartyRole.BAILIFF)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _set(root, "fa:Faktura/fa:PodmiotUpowazniony/fa:RolaPU", "9"),
    )

    with pytest.raises(FA3ParseError, match="rola podmiotu upoważnionego"):
        _parse(xml)


# --- zaliczki: wnioskowanie stawki ---------------------------------------


def _advance_xml(*, tax: TaxCategory, amount: str = "1230.00", kind: str = "advance") -> bytes:
    factory = FA3Invoice.advance if kind == "advance" else FA3Invoice.advance_correction
    builder = (
        factory("ZAL/ERR")
        .issued_on(date(2026, 2, 5))
        .seller(SELLER)
        .buyer(BUYER)
        .advance_payment(amount=amount, tax=tax)
        .add_service_line("Zaliczka", quantity="1", unit_net_price="1000", tax=tax)
    )
    if kind != "advance":
        correction_builder: Any = builder
        correction_builder = correction_builder.corrects(
            "ZAL/OLD", date(2026, 1, 1), reason="Korekta"
        )
        builder = correction_builder.add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Przed", quantity="1", unit_net_price="100", tax=tax
            ),
            after=InvoiceLine.service(
                "Po", quantity="1", unit_net_price="90", tax=tax
            ),
        )
    return builder.build().to_xml()


def test_parse_infers_zero_rate_advance() -> None:
    invoice = _parse(_advance_xml(tax=VatClass.zero_domestic()))

    assert invoice.advance_payments[0].tax.kind is TaxCategory.zero_domestic().kind


def test_parse_infers_exempt_advance() -> None:
    invoice = _parse(_advance_xml(tax=VatClass.exempt("art. 43")))

    assert invoice.advance_payments[0].tax.kind is TaxCategory.exempt("art. 43").kind


def test_parse_infers_outside_country_advance() -> None:
    invoice = _parse(_advance_xml(tax=VatClass.outside_country()))

    assert invoice.advance_payments[0].tax.kind is TaxCategory.outside_country().kind


def test_parse_infers_service_article_100_advance() -> None:
    invoice = _parse(_advance_xml(tax=VatClass.service_article_100()))

    assert invoice.advance_payments[0].tax.kind is TaxCategory.service_article_100().kind


def test_parse_infers_reverse_charge_advance() -> None:
    invoice = _parse(_advance_xml(tax=VatClass.reverse_charge()))

    assert invoice.advance_payments[0].tax.kind is TaxCategory.reverse_charge().kind


def test_parse_infers_margin_advance() -> None:
    invoice = _parse(_advance_xml(tax=VatClass.margin()))

    assert invoice.advance_payments[0].tax.kind is TaxCategory.margin().kind


def test_parse_warns_when_advance_rate_is_ambiguous() -> None:
    xml = _advance_xml(tax=VatClass.standard_23())
    xml = _mutate(xml, lambda root: _set(root, "fa:Faktura/fa:Fa/fa:P_13_1", "2500.00"))

    invoice = _parse(xml)

    assert any("nie wynika jednoznacznie" in warning.message for warning in invoice.warnings)


def test_parse_warns_when_advance_spans_two_buckets() -> None:
    xml = _advance_xml(tax=VatClass.standard_23())
    xml = _mutate(xml, lambda root: _add(root, "fa:Faktura/fa:Fa", "P_13_2", "100.00"))

    invoice = _parse(xml)

    assert any("nie można jednoznacznie" in warning.message for warning in invoice.warnings)


def test_parse_warns_when_advance_amount_is_not_positive() -> None:
    xml = _advance_xml(tax=VatClass.standard_23(), amount="0.00")
    xml = _mutate(xml, lambda root: _set(root, "fa:Faktura/fa:Fa/fa:P_13_1", "2000.00"))

    invoice = _parse(xml)

    assert any("nie dodatniej kwocie" in warning.message for warning in invoice.warnings)


def test_parse_warns_for_advance_on_settlement_invoice() -> None:
    xml = _advance_xml(tax=VatClass.standard_23())

    def _change(root: ET.Element) -> None:
        _set(root, "fa:Faktura/fa:Fa/fa:RodzajFaktury", "ROZ")
        reference = _add(root, "fa:Faktura/fa:Fa", "FakturaZaliczkowa")
        ET.SubElement(reference, f"{{{FA3_NAMESPACE}}}NrKSeFZN").text = "1"
        ET.SubElement(reference, f"{{{FA3_NAMESPACE}}}NrFaZaliczkowej").text = "ZAL/1"

    parsed = _parse(_mutate(xml, _change))

    assert parsed.kind is FA3Invoice.settlement("X").kind
    assert any("fakturze rozliczającej" in warning.message for warning in parsed.warnings)


def test_parse_handles_advance_correction_signed_lines() -> None:
    invoice = _parse(_advance_xml(tax=VatClass.standard_23(), kind="correction"))

    assert invoice.kind is FA3Invoice.advance_correction("X").kind


# --- marża ----------------------------------------------------------------


def test_parse_warns_for_multiple_margin_lines() -> None:
    invoice = (
        FA3Invoice.basic("FV/MARGIN2")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .margin(MarginProcedure.USED_GOODS)
        .add_goods_line("A", quantity="1", unit_net_price="0", tax=VatClass.margin())
        .add_goods_line("B", quantity="1", unit_net_price="0", tax=VatClass.margin())
        .build()
    )

    parsed = _parse(invoice.to_xml())

    assert any("wierszy procedury marży" in warning.message for warning in parsed.warnings)


def test_parse_restores_single_margin_amount() -> None:
    invoice = (
        FA3Invoice.basic("FV/MARGIN1")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .margin(MarginProcedure.USED_GOODS)
        .add_goods_line("A", quantity="1", unit_net_price="0", tax=VatClass.margin())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(), lambda root: _set(root, "fa:Faktura/fa:Fa/fa:P_13_11", "250.00")
    )

    parsed = _parse(xml)

    assert parsed.lines[0].net_amount == Decimal("250.00")


# --- korekta, rozliczenie, płatność, zamówienie ---------------------------


def test_parse_rejects_correction_without_invoice_number() -> None:
    seller = SELLER
    invoice = (
        FA3Invoice.correction("KOR/ERR")
        .issued_on(date(2026, 2, 15))
        .seller(seller)
        .buyer(BUYER)
        .corrects("FV/OLD", date(2026, 1, 10), reason="Korekta")
        .add_corrected_line_before_after(
            before=__import__(
                "ksef_client.documents.fa3.domain", fromlist=["InvoiceLine"]
            ).InvoiceLine.service(
                "Przed", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
            ),
            after=__import__(
                "ksef_client.documents.fa3.domain", fromlist=["InvoiceLine"]
            ).InvoiceLine.service(
                "Po", quantity="1", unit_net_price="90", tax=VatClass.standard_23()
            ),
        )
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _drop(root, "fa:Faktura/fa:Fa/fa:DaneFaKorygowanej/fa:NrFaKorygowanej"),
    )

    with pytest.raises(FA3ParseError, match="NrFaKorygowanej"):
        _parse(xml)


def test_parse_rejects_settlement_item_without_amount() -> None:
    invoice = (
        FA3Invoice.settlement("ROZ/ERR")
        .issued_on(date(2026, 2, 20))
        .seller(SELLER)
        .buyer(BUYER)
        .settles_advance(invoice_number="ZAL/1")
        .settlement_details(
            __import__(
                "ksef_client.documents.fa3.domain", fromlist=["Settlement"]
            ).Settlement(
                charges=(
                    __import__(
                        "ksef_client.documents.fa3.domain", fromlist=["SettlementAdjustment"]
                    ).SettlementAdjustment.create("15.00", "Korekta"),
                )
            )
        )
        .add_service_line(
            "Rozliczenie", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _drop(root, "fa:Faktura/fa:Fa/fa:Rozliczenie/fa:Obciazenia/fa:Kwota"),
    )

    with pytest.raises(FA3ParseError, match="Kwota"):
        _parse(xml)


def test_parse_rejects_partial_payment_without_date() -> None:
    invoice = (
        FA3Invoice.basic("FV/PART/ERR")
        .issued_on(date(2026, 2, 6))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Pay", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .partially_paid("10", date(2026, 2, 7))
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _drop(
            root, "fa:Faktura/fa:Fa/fa:Platnosc/fa:ZaplataCzesciowa/fa:DataZaplatyCzesciowej"
        ),
    )

    with pytest.raises(FA3ParseError, match="DataZaplatyCzesciowej"):
        _parse(xml)


def test_parse_rejects_due_term_with_invalid_amount() -> None:
    invoice = (
        FA3Invoice.basic("FV/DUE/ERR")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .payment(
            __import__(
                "ksef_client.documents.fa3.domain", fromlist=["PaymentTerms"]
            ).PaymentTerms(
                due_terms=(PaymentDue.description(14, "dni", "wystawienie"),)
            )
        )
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _set(
            root,
            "fa:Faktura/fa:Fa/fa:Platnosc/fa:TerminPlatnosci/fa:TerminOpis/fa:Ilosc",
            "abc",
        ),
    )

    with pytest.raises(FA3ParseError, match="Ilosc"):
        _parse(xml)


def test_parse_rejects_order_without_total() -> None:
    invoice = (
        FA3Invoice.advance("FV/ORDER/ERR")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .order(total_gross="100.00")
        .order_line("Pozycja", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _drop(root, "fa:Faktura/fa:Fa/fa:Zamowienie/fa:WartoscZamowienia"),
    )

    with pytest.raises(FA3ParseError, match="WartoscZamowienia"):
        _parse(xml)


def test_parse_rejects_order_line_without_price() -> None:
    invoice = (
        FA3Invoice.advance("FV/ORDER/ERR2")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .order(total_gross="100.00")
        .order_line("Pozycja", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _drop(
            root, "fa:Faktura/fa:Fa/fa:Zamowienie/fa:ZamowienieWiersz/fa:P_9AZ"
        ),
    )

    with pytest.raises(FA3ParseError, match="P_9AZ"):
        _parse(xml)


def test_parse_order_line_without_vat_code_keeps_tax_unknown() -> None:
    invoice = (
        FA3Invoice.advance("FV/ORDER/MARGIN")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .order(total_gross="100.00")
        .order_line("Pozycja", quantity="1", unit_net_price="100", tax=VatClass.margin())
        .build()
    )
    xml = invoice.to_xml()

    parsed = _parse(xml)

    assert parsed.order is not None
    # XML nie niesie P_12Z, więc parser nie może wymyślić stawki — zapisuje None,
    # a ponowna serializacja nie dodaje brakującego elementu.
    assert parsed.order.lines[0].tax is None
    assert "P_12Z" not in parsed.to_xml().decode("utf-8")
    assert parsed.to_xml().count(b"P_12Z") == xml.count(b"P_12Z")


def test_parse_order_line_with_xii_rate() -> None:
    invoice = (
        FA3Invoice.advance("FV/ORDER/XII")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .order(total_gross="100.00")
        .order_line("Pozycja", quantity="1", unit_net_price="100", tax=VatClass.xii("12"))
        .build()
    )

    parsed = _parse(invoice.to_xml())

    assert parsed.order is not None
    assert parsed.order.lines[0].tax is not None
    assert parsed.order.lines[0].tax.xii_rate == Decimal("12")


def test_parse_rejects_invalid_additional_description_row_number() -> None:
    invoice = (
        FA3Invoice.basic("FV/DESC/ERR")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .additional_description("projekt", "Alfa", row_number=1)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _set(root, "fa:Faktura/fa:Fa/fa:DodatkowyOpis/fa:NrWiersza", "abc"),
    )

    with pytest.raises(FA3ParseError, match="NrWiersza"):
        _parse(xml)


def test_parse_rejects_attachment_table_without_header() -> None:
    from ksef_client.documents.fa3 import Attachment, AttachmentBlock, AttachmentTable

    invoice = (
        FA3Invoice.basic("FV/ATT/ERR")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .attachment(
            Attachment(
                (
                    AttachmentBlock(
                        tables=(AttachmentTable(headers=("A",), rows=(("1",),)),),
                    ),
                )
            )
        )
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _drop(
            root, "fa:Faktura/fa:Zalacznik/fa:BlokDanych/fa:Tabela/fa:TNaglowek"
        ),
    )

    with pytest.raises(FA3ParseError, match="TNaglowek"):
        _parse(xml)


def test_parse_rejects_invalid_transport_means_row_number() -> None:
    from ksef_client.documents.fa3 import NewTransportMeans

    invoice = (
        FA3Invoice.basic("FV/NST/ERR")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .new_transport(
            NewTransportMeans(
                allowed_date=date(2026, 2, 20),
                row_number=1,
                kind="land",
                mileage="10",
            )
        )
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _set(
            root,
            "fa:Faktura/fa:Fa/fa:Adnotacje/fa:NoweSrodkiTransportu/"
            "fa:NowySrodekTransportu/fa:P_NrWierszaNST",
            "abc",
        ),
    )

    with pytest.raises(FA3ParseError, match="P_NrWierszaNST"):
        _parse(xml)


def test_parse_rejects_invalid_transport_means_date() -> None:

    invoice = (
        FA3Invoice.basic("FV/NST/ERR2")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .new_transport(
            NewTransportMeans(
                allowed_date=date(2026, 2, 20),
                row_number=1,
                kind="land",
                mileage="10",
            )
        )
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _set(
            root,
            "fa:Faktura/fa:Fa/fa:Adnotacje/fa:NoweSrodkiTransportu/"
            "fa:NowySrodekTransportu/fa:P_22A",
            "zła",
        ),
    )

    with pytest.raises(FA3ParseError, match="P_22A"):
        _parse(xml)


# --- pokrycie gałęzi pomocniczych -----------------------------------------


def test_parse_without_annotations_uses_defaults() -> None:
    xml = _mutate(_base(), lambda root: _drop(root, "fa:Faktura/fa:Fa/fa:Adnotacje"))

    invoice = _parse(xml)

    assert invoice.annotations.cash_method is False
    assert invoice.annotations.exemption_basis is None
    assert invoice.annotations.margin_procedure is None


def test_parse_margin_annotation_without_margin_lines() -> None:
    invoice = (
        FA3Invoice.basic("FV/MARGIN/MIX")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .margin(MarginProcedure.USED_GOODS)
        .add_goods_line("A", quantity="1", unit_net_price="0", tax=VatClass.margin())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _add(root, "fa:Faktura/fa:Fa/fa:FaWiersz", "P_12", "23"),
    )

    parsed = _parse(xml)

    assert parsed.lines[0].tax.vat_rate == Decimal("23")


def test_parse_margin_invoice_without_summary_total() -> None:
    invoice = (
        FA3Invoice.basic("FV/MARGIN/NOSUM")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .margin(MarginProcedure.USED_GOODS)
        .add_goods_line("A", quantity="1", unit_net_price="0", tax=VatClass.margin())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(), lambda root: _drop(root, "fa:Faktura/fa:Fa/fa:P_13_11")
    )

    parsed = _parse(xml)

    assert parsed.lines[0].net_amount is None


def test_parse_rejects_invalid_order_line_vat_code() -> None:
    invoice = (
        FA3Invoice.advance("FV/ORDER/BADVAT")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .order(total_gross="100.00")
        .order_line("Pozycja", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _set(
            root, "fa:Faktura/fa:Fa/fa:Zamowienie/fa:ZamowienieWiersz/fa:P_12Z", "99"
        ),
    )

    with pytest.raises(FA3ParseError, match="P_12Z"):
        _parse(xml)


def test_parse_additional_description_without_row_number() -> None:
    invoice = (
        FA3Invoice.basic("FV/DESC/NOROW")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .additional_description("projekt", "Alfa")
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )

    parsed = _parse(invoice.to_xml())

    assert parsed.additional_descriptions[0].row_number is None


# --- poprawki z review: DTD niezależne od kodowania ------------------------


def test_parse_rejects_dtd_hidden_in_utf16() -> None:
    xml = _base().decode("utf-8").replace("encoding='utf-8'", "encoding='UTF-16'")
    xml = xml.replace("?>", "?>\n<!DOCTYPE Faktura [<!ENTITY x 'INJECTED'>]>", 1)
    xml = xml.replace(">FV/ERR<", ">&x;<")

    with pytest.raises(FA3ParseError, match="DOCTYPE/ENTITY"):
        _parse(xml.encode("utf-16"))


def test_parse_accepts_doctype_text_inside_comment() -> None:
    def _change(root: ET.Element) -> None:
        root.insert(0, ET.Comment(" <!DOCTYPE to tylko tekst komentarza "))

    invoice = _parse(_mutate(_base(), _change))

    assert invoice.invoice_number == "FV/ERR"


def test_parse_wraps_elementtree_parser_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import ksef_client.documents.fa3.parse as parse_module

    def _fail(*_args: object, **_kwargs: object) -> ET.Element:
        raise ET.ParseError("symulowany błąd")

    monkeypatch.setattr(parse_module.ET, "fromstring", _fail)

    with pytest.raises(FA3ParseError, match="Nieprawidłowy XML"):
        parse_module.parse_invoice_xml(_base())


def test_parse_rejects_exponent_notation() -> None:
    xml = _mutate(
        _base(),
        lambda root: _set(root, "fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_8B", "1e5"),
    )

    with pytest.raises(FA3ParseError, match="nie jest liczbą"):
        _parse(xml)


def test_parse_rejects_rola_inna_without_description() -> None:
    other = replace(
        Party.polish_company(nip="3333333333", name="Trzeci", address="Adres 3"),
        other_role_description="Rola opisana",
    )
    invoice = (
        FA3Invoice.basic("FV/ROLA")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_party(other, ThirdPartyRole.OTHER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )
    xml = _mutate(
        invoice.to_xml(),
        lambda root: _drop(root, "fa:Faktura/fa:Podmiot3/fa:OpisRoli"),
    )

    with pytest.raises(FA3ParseError, match="OpisRoli"):
        _parse(xml)


# --- review 2: namespace, sanityzacja komunikatów -------------------------


def test_parse_ignores_elements_in_foreign_namespace() -> None:
    root = ET.fromstring(_base())
    element = root.find("fa:Fa/fa:P_2", NS)
    assert element is not None
    element.tag = "{urn:evil}P_2"

    with pytest.raises(FA3ParseError, match="P_2"):
        _parse(ET.tostring(root, encoding="utf-8"))


def test_parse_error_sanitizes_untrusted_value() -> None:
    bad = "1'\t" + "9" * 80
    xml = _mutate(
        _base(),
        lambda root: _set(root, "fa:Faktura/fa:Fa/fa:FaWiersz/fa:P_8B", bad),
    )

    with pytest.raises(FA3ParseError) as excinfo:
        _parse(xml)
    message = str(excinfo.value)

    assert "\t" not in message
    assert "?" in message
    assert "…" in message
    assert "`" in message


# --- review 3: koszyk XII, kodowanie wejścia, limit ostrzeżeń, strefy -----


def _add_advance_in_xii_basket(root: ET.Element) -> None:
    _add(root, "fa:Faktura/fa:Fa", "ZaliczkaCzesciowa")
    _add(root, "fa:Faktura/fa:Fa/fa:ZaliczkaCzesciowa", "P_15Z", "123.00")
    _add(root, "fa:Faktura/fa:Fa", "P_13_5", "100.00")


def test_parse_advance_in_xii_basket_warns_instead_of_crashing() -> None:
    # Wcześniej brak wpisu `P_13_5` w mapie stawek kończył się `KeyError`,
    # czyli wyjątkiem spoza kontraktu `FA3ParseError`.
    invoice = _parse(_mutate(_base(), _add_advance_in_xii_basket))

    assert [payment.amount for payment in invoice.advance_payments] == [Decimal("123.00")]
    assert invoice.advance_payments[0].tax == TaxCategory.standard_23()
    assert any("P_13_5" in warning.message for warning in invoice.warnings)


def test_parse_str_ignores_stale_encoding_declaration() -> None:
    # `str` jest już zdekodowany, więc deklaracja `iso-8859-2` nie może
    # spowodować odczytania bajtów UTF-8 jako Latin-2 (wcześniej: mojibake).
    xml = _base().decode("utf-8")
    stale = xml.replace("encoding='utf-8'", "encoding='iso-8859-2'", 1)
    assert stale != xml

    invoice = parse_invoice_xml(stale)

    assert invoice.lines[0].description == "Usługa"
    assert invoice.lines[0].description.encode("utf-8") in invoice.to_xml()


def test_parse_str_with_bom_and_stale_encoding_declaration() -> None:
    stale = _base().decode("utf-8").replace("encoding='utf-8'", "encoding='windows-1250'", 1)

    invoice = parse_invoice_xml("\ufeff" + stale)

    assert invoice.invoice_number == "FV/ERR"
    assert invoice.lines[0].description == "Usługa"


@pytest.mark.parametrize("value", ["2026-03-01Z", "2026-03-01+02:00", "2026-03-01-05:00"])
def test_parse_accepts_xs_date_with_timezone(value: str) -> None:
    # `xs:date` dopuszcza strefę czasową; `date.fromisoformat` jej nie przyjmuje.
    invoice = _parse(
        _mutate(_base(), lambda root: _set(root, "fa:Faktura/fa:Fa/fa:P_1", value))
    )

    assert invoice.issue_date == date(2026, 3, 1)


def test_parse_rejects_date_with_invalid_timezone_suffix() -> None:
    with pytest.raises(FA3ParseError, match="nie jest poprawną datą"):
        _parse(
            _mutate(
                _base(),
                lambda root: _set(root, "fa:Faktura/fa:Fa/fa:P_1", "2026-03-01+2:00"),
            )
        )


def test_parse_limits_number_of_warnings() -> None:
    def add_unknown(root: ET.Element) -> None:
        fa = _find(root, "fa:Faktura/fa:Fa")
        for index in range(MAX_PARSE_WARNINGS + 25):
            ET.SubElement(fa, f"{{{FA3_NAMESPACE}}}Nieznany{index}")

    invoice = _parse(_mutate(_base(), add_unknown))

    # Limit + jedno ostrzeżenie o obcięciu — dokument z milionem nieznanych
    # elementów nie może zbudować miliona obiektów.
    assert len(invoice.warnings) == MAX_PARSE_WARNINGS + 1
    assert "limit" in invoice.warnings[-1].message
