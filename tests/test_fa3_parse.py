from __future__ import annotations

from dataclasses import replace
from datetime import date
from decimal import Decimal
from xml.etree import ElementTree as ET

import pytest

from ksef_client.documents.fa3 import (
    Address,
    Attachment,
    AttachmentBlock,
    AttachmentTable,
    AuthorizedPartyRole,
    BankAccount,
    Contact,
    CorrectionType,
    FA3Invoice,
    GTUCode,
    InvoiceLine,
    LineIdentifiers,
    LineProcedure,
    MarginProcedure,
    NewTransportMeans,
    OrderLineProcedure,
    Party,
    PaymentDue,
    PaymentMethod,
    PaymentTerms,
    Registry,
    Settlement,
    SettlementAdjustment,
    TaxCategory,
    ThirdPartyRole,
    TransportKind,
    VatClass,
    parse_invoice_xml,
)
from ksef_client.documents.fa3.models import decimal_from_value
from ksef_client.documents.fa3.xml import FA3_NAMESPACE

NS = {"fa": FA3_NAMESPACE}

SELLER = Party.polish_company(nip="1234567890", name="Sprzedawca", address="Adres S")
BUYER = Party.polish_company(nip="1111111111", name="Nabywca", address="Adres N")


# --- pomocnicze -----------------------------------------------------------


def _strip_timestamp(xml: bytes) -> str:
    root = ET.fromstring(xml)
    for node in root.iter():
        if node.tag.endswith("DataWytworzeniaFa"):
            node.text = "TIMESTAMP"
    return ET.tostring(root, encoding="unicode")


def assert_roundtrip(invoice: FA3Invoice, *, allow_warnings: bool = False) -> FA3Invoice:
    xml = invoice.to_xml()
    parsed = parse_invoice_xml(xml)
    if not allow_warnings:
        assert [warning.message for warning in parsed.warnings] == []
    assert _strip_timestamp(parsed.to_xml()) == _strip_timestamp(xml)
    return parsed


def basic_invoice(number: str = "FV/1") -> FA3Invoice:
    return (
        FA3Invoice.basic(number)
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line(
            "Usługa", quantity="2", unit_net_price="100.50", tax=VatClass.standard_23()
        )
        .build()
    )


def _find(root: ET.Element, path: str) -> ET.Element:
    element = root.find(path, NS)
    assert element is not None, f"brak elementu {path}"
    return element


def _drop(root: ET.Element, path: str) -> None:
    parent_path, _, tag = path.rpartition("/")
    parent = root.find(parent_path, NS) if parent_path else root
    assert parent is not None
    element = parent.find(tag, NS)
    assert element is not None
    parent.remove(element)


def _set_text(root: ET.Element, path: str, value: str) -> None:
    _find(root, path).text = value


def _mutate(xml: bytes, callback: object) -> bytes:
    root = ET.fromstring(xml)
    callback(root)  # type: ignore[operator]
    return ET.tostring(root, encoding="utf-8")


def _with_text(xml: bytes, path: str, value: str) -> bytes:
    return _mutate(xml, lambda root: _set_text(root, path, value))


def _without(xml: bytes, path: str) -> bytes:
    return _mutate(xml, lambda root: _drop(root, path))


# --- ścieżki pozytywne: podstawy -----------------------------------------


def test_parse_basic_invoice_fields() -> None:
    invoice = basic_invoice("FV/BASIC")
    parsed = assert_roundtrip(invoice)

    assert parsed.invoice_number == "FV/BASIC"
    assert parsed.issue_date == date(2026, 3, 1)
    assert parsed.currency == "PLN"
    assert parsed.kind is invoice.kind
    assert parsed.seller.name == "Sprzedawca"
    assert parsed.seller.identifier.value == "1234567890"
    assert parsed.buyer.identifier.value == "1111111111"
    assert parsed.lines[0].description == "Usługa"
    assert parsed.lines[0].quantity == Decimal("2")
    assert parsed.lines[0].unit_net_price == Decimal("100.50")
    assert parsed.lines[0].tax.kind is invoice.lines[0].tax.kind
    assert parsed.total_gross == invoice.total_gross


def test_parse_accepts_bytes_str_and_bytearray() -> None:
    xml = basic_invoice().to_xml()

    assert parse_invoice_xml(xml).invoice_number == "FV/1"
    assert parse_invoice_xml(xml.decode("utf-8")).invoice_number == "FV/1"
    assert parse_invoice_xml(bytearray(xml)).invoice_number == "FV/1"


def test_from_xml_and_to_xml_are_inverse() -> None:
    invoice = basic_invoice()
    parsed = FA3Invoice.from_xml(invoice.to_xml())

    assert parsed.to_xml().startswith(b"<?xml")
    assert parsed.invoice_number == invoice.invoice_number


def test_parse_preserves_optional_header_fields() -> None:
    invoice = (
        FA3Invoice.basic("FV/OPTS")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .issue_place("Warszawa")
        .sale_date(date(2026, 2, 28))
        .add_service_line("Usługa", quantity="1", unit_net_price="10", tax=VatClass.standard_23())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.issue_place == "Warszawa"
    assert parsed.sale_date == date(2026, 2, 28)


def test_parse_period_invoice() -> None:
    invoice = (
        FA3Invoice.basic("FV/PERIOD")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .period(date(2026, 2, 1), date(2026, 2, 28))
        .add_service_line("Usługa", quantity="1", unit_net_price="10", tax=VatClass.standard_23())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.period_from == date(2026, 2, 1)
    assert parsed.period_to == date(2026, 2, 28)


def test_parse_warehouse_documents_and_additional_descriptions() -> None:
    invoice = (
        FA3Invoice.basic("FV/WZ")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .warehouse_document("WZ/1")
        .warehouse_document("WZ/2")
        .additional_description("projekt", "Alfa", row_number=1)
        .add_service_line("Usługa", quantity="1", unit_net_price="10", tax=VatClass.standard_23())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.warehouse_documents == ("WZ/1", "WZ/2")
    assert parsed.additional_descriptions[0].row_number == 1


def test_parse_multiple_vat_rates() -> None:
    invoice = (
        FA3Invoice.basic("FV/VAT")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("23", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .add_service_line("8", quantity="1", unit_net_price="100", tax=VatClass.reduced_8())
        .add_service_line("zw", quantity="1", unit_net_price="100", tax=VatClass.exempt("art. 43"))
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert {line.tax.kind for line in parsed.lines} == {
        invoice.lines[0].tax.kind,
        invoice.lines[1].tax.kind,
        invoice.lines[2].tax.kind,
    }


def test_parse_line_details() -> None:
    invoice = (
        FA3Invoice.basic("FV/LINE")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_goods_line(
            "Towar",
            quantity="3",
            unit_net_price="50",
            tax=VatClass.standard_23(),
            unit="kg",
            unique_id="UU-1",
            service_date=date(2026, 2, 20),
            identifiers=LineIdentifiers(
                internal_index="SKU",
                gtin="5901234123457",
                pkwiu="62.01",
                cn="1234",
                pkob="567",
            ),
            gtu=GTUCode.GTU_12,
            procedure=LineProcedure.IED,
            excise_amount="1.23",
            annex_15=True,
            currency_rate="4.123456",
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)
    line = parsed.lines[0]

    assert line.unit == "kg"
    assert line.unique_id == "UU-1"
    assert line.service_date == date(2026, 2, 20)
    assert line.identifiers is not None
    assert line.identifiers.gtin == "5901234123457"
    assert line.gtu == "GTU_12"
    assert line.procedure == "IED"
    assert line.excise_amount == Decimal("1.23")
    assert line.annex_15 is True
    assert line.currency_rate == Decimal("4.123456")


def test_parse_line_with_discount() -> None:
    invoice = (
        FA3Invoice.basic("FV/DISC")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line(
            "Usługa",
            quantity="2",
            unit_net_price="100",
            tax=VatClass.standard_23(),
            discount=__import__(
                "ksef_client.documents.fa3.domain", fromlist=["Discount"]
            ).Discount(
                __import__(
                    "ksef_client.documents.fa3.domain", fromlist=["DiscountKind"]
                ).DiscountKind.AMOUNT,
                Decimal("10"),
            ),
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.lines[0].discount is not None
    assert parsed.lines[0].discount.value == Decimal("10")


# --- adnotacje i podmioty -------------------------------------------------


def test_parse_annotations() -> None:
    invoice = (
        FA3Invoice.basic("FV/ANN")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .split_payment()
        .cash_method()
        .self_billing()
        .reverse_charge()
        .exemption("art. 43 ust. 1 pkt 2", basis_type="directive")
        .new_transport(
            NewTransportMeans(
                allowed_date=date(2026, 2, 20),
                row_number=1,
                kind="water",
                hours_used="12",
                serial_number="SR-1",
            )
        )
        .margin(MarginProcedure.USED_GOODS)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.margin())
        .build()
    )

    parsed = assert_roundtrip(invoice)
    annotations = parsed.annotations

    assert annotations.split_payment is True
    assert annotations.cash_method is True
    assert annotations.self_billing is True
    assert annotations.reverse_charge is True
    assert annotations.exemption_basis == "art. 43 ust. 1 pkt 2"
    assert annotations.exemption_basis_type == "directive"
    assert annotations.new_transport is True
    assert annotations.new_transport_means[0].kind == "water"
    assert annotations.new_transport_means[0].serial_number == "SR-1"
    assert annotations.margin_procedure == "used_goods"


@pytest.mark.parametrize(
    ("kind", "field", "value"),
    [
        ("land", "mileage", "1000"),
        ("land", "engine_capacity", "1998"),
        ("land", "engine_power", "150"),
        ("land", "approval_number", "APP-1"),
        ("air", "hours_used", "10"),
        ("water", "hours_used", "5"),
    ],
)
def test_parse_new_transport_means_variants(kind: str, field: str, value: str) -> None:
    means = NewTransportMeans(
        allowed_date=date(2026, 2, 20),
        row_number=1,
        kind=kind,
        serial_number="SR-1",
        **{field: value},
    )
    invoice = (
        FA3Invoice.basic(f"FV/NST/{kind}/{field}")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .new_transport(means)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.annotations.new_transport_means[0].kind == kind


def test_parse_additional_and_authorized_parties() -> None:
    extra = replace(
        Party.foreign_company(
            identifier="EXT-2",
            country_code="DE",
            name="Third",
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
        contacts=(Contact(email="auth@example.com", phone="222333444"),),
    )
    invoice = (
        FA3Invoice.basic("FV/PARTY")
        .issued_on(date(2026, 2, 2))
        .seller(SELLER)
        .buyer(BUYER)
        .add_party(extra, ThirdPartyRole.RECIPIENT)
        .authorized_party(authorized, AuthorizedPartyRole.BAILIFF)
        .add_service_line("Party", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.additional_parties[0].role is ThirdPartyRole.RECIPIENT
    assert parsed.additional_parties[0].share is None
    assert parsed.additional_parties[0].eori == "EORI-3"
    assert parsed.authorized_party is not None
    assert parsed.authorized_party.authorized_role is AuthorizedPartyRole.BAILIFF
    assert parsed.authorized_party.contacts[0].email == "auth@example.com"


def test_parse_other_third_party_role() -> None:
    extra = replace(
        Party.polish_company(nip="3333333333", name="Other", address="Other A"),
        other_role_description="Rola opisana",
    )
    invoice = (
        FA3Invoice.basic("FV/OTHER")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_party(extra, ThirdPartyRole.OTHER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.additional_parties[0].role is ThirdPartyRole.OTHER
    assert parsed.additional_parties[0].other_role_description == "Rola opisana"


# --- płatność i warunki ---------------------------------------------------


def test_parse_payment_terms() -> None:
    invoice = (
        FA3Invoice.basic("FV/PAY")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .payment(
            PaymentTerms(
                due_terms=(PaymentDue.description(14, "dni", "data wystawienia"),),
                method=PaymentMethod.TRANSFER.value,
                bank_accounts=(BankAccount(number="12345678901234567890123456"),),
                cash_discount_terms="7 dni",
                cash_discount_amount="1.00",
                payment_link="https://example.com/pay?IPKSeF=123abc456DEF7",
                ipksef="123abc456DEF7",
            )
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)
    payment = parsed.payment_terms

    assert payment is not None
    assert payment.method == PaymentMethod.TRANSFER.value
    assert payment.bank_accounts[0].number == "12345678901234567890123456"
    assert payment.cash_discount_terms == "7 dni"
    assert payment.cash_discount_amount == "1.00"
    assert payment.payment_link == "https://example.com/pay?IPKSeF=123abc456DEF7"
    assert payment.ipksef == "123abc456DEF7"
    assert payment.due_terms[0].term_description is not None
    assert payment.due_terms[0].term_description.amount == 14


def test_parse_partial_payments_and_factor_account() -> None:
    invoice = (
        FA3Invoice.basic("FV/PART")
        .issued_on(date(2026, 2, 6))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Pay", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .partially_paid("10", date(2026, 2, 7), other_method_description="kompensata")
        .bank_account("99999999999999999999999999", factor=True)
        .build()
    )

    parsed = assert_roundtrip(invoice)
    payment = parsed.payment_terms

    assert payment is not None
    assert payment.partial_payments[0].amount == Decimal("10")
    assert payment.partial_payments[0].other_method_description == "kompensata"
    assert payment.factor_accounts[0].number == "99999999999999999999999999"


def test_parse_paid_date() -> None:
    invoice = (
        FA3Invoice.basic("FV/PAID")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .paid(date(2026, 3, 2))
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.payment_terms is not None
    assert parsed.payment_terms.paid_date == date(2026, 3, 2)


def test_parse_transaction_terms_and_transport() -> None:
    invoice = (
        FA3Invoice.basic("FV/TERMS")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .contract(number="UM/1", date=date(2026, 2, 1))
        .order_reference(number="ZAM/1", date=date(2026, 2, 2))
        .transaction_terms(
            delivery_terms="DAP",
            contractual_rate="4.123456",
            contractual_currency="EUR",
        )
        .transport(
            TransportKind.ROAD,
            carrier=BUYER,
            order_number="TR/1",
            cargo_description="1",
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)
    terms = parsed.transaction_terms

    assert terms is not None
    assert terms.contracts[0].number == "UM/1"
    assert terms.orders[0].number == "ZAM/1"
    assert terms.delivery_terms == "DAP"
    assert terms.contractual_rate == Decimal("4.123456")
    assert terms.contractual_currency == "EUR"
    assert terms.transports[0].carrier is not None
    assert terms.transports[0].carrier.name == "Nabywca"


def test_parse_footer_and_attachment() -> None:
    invoice = (
        FA3Invoice.basic("FV/FOOTER")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .footer_info("Stopka")
        .registry(Registry.krs_entry("0000123456", full_name="Sprzedawca sp. z o.o."))
        .attachment(
            Attachment(
                (
                    AttachmentBlock(
                        header="Załącznik",
                        paragraphs=("Akapit 1", "Akapit 2"),
                        metadata=(("Klucz", "Wartość"),),
                        tables=(
                            AttachmentTable(
                                headers=("Nazwa", "Kwota"),
                                rows=(("Pojazd", "123000.00"),),
                                column_types=("txt", "dec"),
                                footer=("Razem", "123000.00"),
                                description="Tabela",
                                metadata=(("TM", "TV"),),
                            ),
                        ),
                    ),
                )
            )
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.footer is not None
    assert parsed.footer.infos == ("Stopka",)
    assert parsed.footer.registries[0].krs == "0000123456"
    assert parsed.attachment is not None
    block = parsed.attachment.blocks[0]
    assert block.paragraphs == ("Akapit 1", "Akapit 2")
    assert block.tables[0].rows == (("Pojazd", "123000.00"),)
    assert block.tables[0].footer == ("Razem", "123000.00")
    assert block.tables[0].column_types == ("txt", "dec")


def test_parse_fiscal_receipt_and_foreign_currency_rate() -> None:
    invoice = (
        FA3Invoice.basic("FV/FP")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .foreign_currency_rate("4.123456")
        .fiscal_receipt_invoice()
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.fp is True
    assert parsed.foreign_currency_rate == Decimal("4.123456")


# --- rodzaje faktur -------------------------------------------------------


def test_parse_simplified_invoice() -> None:
    invoice = (
        FA3Invoice.simplified("FV/SIMPLIFIED")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(Party.polish_company(nip="1111111111", name="", address="Adres N"))
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.kind is invoice.kind


def test_parse_correction_invoice() -> None:
    seller = replace(SELLER, taxpayer_prefix="PL")
    invoice = (
        FA3Invoice.correction("KOR/1")
        .issued_on(date(2026, 2, 15))
        .seller(seller)
        .buyer(BUYER)
        .corrects(
            "FV/OLD/1",
            date(2026, 1, 10),
            reason="Korekta",
            ksef_number="1234567890-20260110-AAAAAA-BBBBBB-CC",
        )
        .correction_type(CorrectionType.TAX_BASE_OR_TAX)
        .corrected_period("2026-01")
        .corrected_invoice_number_override("FV/OLD/CORRECT/1")
        .corrected_seller(seller)
        .add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Przed", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
            ),
            after=InvoiceLine.service(
                "Po", quantity="1", unit_net_price="90", tax=VatClass.standard_23()
            ),
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.kind is invoice.kind
    assert parsed.correction_reason == "Korekta"
    assert parsed.correction_type == CorrectionType.TAX_BASE_OR_TAX.value
    assert parsed.corrected_period == "2026-01"
    assert parsed.corrected_invoice_number_override == "FV/OLD/CORRECT/1"
    assert parsed.corrected_invoices[0].ksef_number == "1234567890-20260110-AAAAAA-BBBBBB-CC"
    assert parsed.corrected_seller is not None
    assert parsed.corrected_seller.taxpayer_prefix == "PL"


def test_parse_advance_invoice_infers_rate() -> None:
    invoice = (
        FA3Invoice.advance("ZAL/8")
        .issued_on(date(2026, 2, 5))
        .seller(SELLER)
        .buyer(BUYER)
        .advance_payment(
            amount="1080.00",
            tax=VatClass.reduced_8(),
            paid_on=date(2026, 2, 4),
            currency_rate="4.12",
        )
        .add_service_line("Zaliczka", quantity="1", unit_net_price="1000", tax=VatClass.reduced_8())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.advance_payments[0].tax.vat_rate == Decimal("8")
    assert parsed.advance_payments[0].paid_on == date(2026, 2, 4)
    assert parsed.advance_payments[0].currency_rate == Decimal("4.12")


def test_parse_advance_invoice_without_lines() -> None:
    invoice = (
        FA3Invoice.advance("ZAL/ONLY")
        .issued_on(date(2026, 2, 5))
        .seller(SELLER)
        .buyer(BUYER)
        .advance_payment(amount="1230.00", tax=VatClass.standard_23())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.lines == ()
    assert parsed.advance_payments[0].amount == Decimal("1230.00")


def test_parse_settlement_invoice() -> None:
    invoice = (
        FA3Invoice.settlement("ROZ/1")
        .issued_on(date(2026, 2, 20))
        .seller(SELLER)
        .buyer(BUYER)
        .settles_advance(invoice_number="ZAL/1")
        .settlement_details(
            Settlement(
                charges=(SettlementAdjustment.create("15.00", "Korekta"),),
                amount_to_settle=decimal_from_value("200.00", field_name="x"),
            )
        )
        .add_service_line(
            "Rozliczenie", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.kind is invoice.kind
    assert parsed.advance_invoices[0].invoice_number == "ZAL/1"
    assert parsed.settlement_data is not None
    assert parsed.settlement_data.charges[0].reason == "Korekta"
    assert parsed.settlement_data.amount_to_settle == Decimal("200.00")


def test_parse_advance_correction_invoice() -> None:
    invoice = (
        FA3Invoice.advance_correction("KOR/ZAL")
        .issued_on(date(2026, 2, 15))
        .seller(SELLER)
        .buyer(BUYER)
        .corrects("ZAL/OLD", date(2026, 1, 10), reason="Korekta zaliczki")
        .add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Przed", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
            ),
            after=InvoiceLine.service(
                "Po", quantity="1", unit_net_price="90", tax=VatClass.standard_23()
            ),
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.kind is invoice.kind


def test_parse_settlement_correction_invoice() -> None:
    seller = replace(SELLER, taxpayer_prefix="PL")
    invoice = (
        FA3Invoice.settlement_correction("KOR/ROZ")
        .issued_on(date(2026, 2, 15))
        .seller(seller)
        .buyer(BUYER)
        .corrects("ROZ/OLD", date(2026, 1, 10), reason="Korekta rozliczenia")
        .corrected_period("2026-01")
        .corrected_seller(seller)
        .settles_advance(invoice_number="ZAL/1")
        .with_section(
            __import__(
                "ksef_client.documents.fa3.sections", fromlist=["CorrectedAdvanceState"]
            ).CorrectedAdvanceState.create("50.00", currency_rate="4.123456")
        )
        .add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Przed", quantity="1", unit_net_price="100", tax=VatClass.standard_23()
            ),
            after=InvoiceLine.service(
                "Po", quantity="1", unit_net_price="90", tax=VatClass.standard_23()
            ),
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.corrected_advance_state is not None
    assert parsed.corrected_advance_state.amount == Decimal("50.00")
    assert parsed.corrected_advance_state.currency_rate == Decimal("4.123456")


def test_parse_order() -> None:
    invoice = (
        FA3Invoice.advance("FV/ORDER")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .order(total_gross="5000.00")
        .order_line(
            "Pozycja",
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
            excise_amount="1.23",
            annex_15=True,
            before_correction=True,
        )
        .order_line(
            "Pozycja standard",
            quantity="1",
            unit_net_price="100.00",
            tax=VatClass.standard_23(),
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)
    order = parsed.order

    assert order is not None
    assert order.total_gross == Decimal("5000.00")
    assert order.lines[0].tax is not None
    assert order.lines[0].tax.kind is TaxCategory.xii("12").kind
    assert order.lines[0].identifiers is not None
    assert order.lines[0].identifiers.pkwiu == "62.01"
    assert order.lines[0].gtu == "GTU_12"
    assert order.lines[0].annex_15 is True
    assert order.lines[0].before_correction is True
    assert order.lines[1].tax is not None
    assert order.lines[1].tax.vat_rate == Decimal("23")


def test_parse_margin_invoice() -> None:
    invoice = (
        FA3Invoice.basic("FV/MARGIN")
        .issued_on(date(2026, 2, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .margin(MarginProcedure.USED_GOODS)
        .add_goods_line("Samochód", quantity="1", unit_net_price="0", tax=VatClass.margin())
        .build()
    )

    parsed = assert_roundtrip(invoice)

    assert parsed.annotations.margin_procedure == "used_goods"
    assert parsed.lines[0].tax.kind is invoice.lines[0].tax.kind


def test_parse_transport_with_addresses_and_times() -> None:
    from datetime import datetime, timezone

    invoice = (
        FA3Invoice.basic("FV/TRANSPORT")
        .issued_on(date(2026, 3, 1))
        .seller(SELLER)
        .buyer(BUYER)
        .add_service_line("Usługa", quantity="1", unit_net_price="100", tax=VatClass.standard_23())
        .transport(
            TransportKind.ROAD,
            ship_from=Address.polish("Magazyn"),
            ship_via=(Address.polish("Punkt 1"), Address.polish("Punkt 2")),
            ship_to=Address.polish("Odbiorca"),
            started_at=datetime(2026, 3, 1, 10, 0, tzinfo=timezone.utc),
            finished_at=datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc),
        )
        .build()
    )

    parsed = assert_roundtrip(invoice)
    terms = parsed.transaction_terms
    assert terms is not None
    transport = terms.transports[0]

    assert transport.ship_from is not None
    assert transport.ship_from.line1 == "Magazyn"
    assert [address.line1 for address in transport.ship_via] == ["Punkt 1", "Punkt 2"]
    assert transport.ship_to is not None
    assert transport.ship_to.line1 == "Odbiorca"
    assert transport.started_at is not None
    assert transport.started_at.hour == 10
