from __future__ import annotations

from datetime import date, datetime, timezone
from decimal import Decimal
from importlib import resources
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from .domain import (
    Address,
    AnnotationSet,
    Attachment,
    AttachmentBlock,
    AttachmentTable,
    AuthorizedPartyRole,
    BankAccount,
    FA3Invoice,
    InvoiceLine,
    InvoiceParty,
    PartialPayment,
    PartyIdentifierKind,
    PaymentTerms,
    Settlement,
)
from .models import FA3Draft, FA3InvoiceKind, FA3Party, money
from .sections import (
    AdditionalDescription,
    AdvancePayment,
    Footer,
    NewTransportMeans,
    Order,
    OrderLine,
    PaymentDue,
    TransactionTerms,
    Transport,
    enum_value,
)

FA3_NAMESPACE = "http://crd.gov.pl/wzor/2025/06/25/13775/"
ETD_NAMESPACE = "http://crd.gov.pl/xml/schematy/dziedzinowe/mf/2022/01/05/eD/DefinicjeTypy/"
XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"


class FA3XmlValidationError(ValueError):
    pass


def draft_to_xml(
    draft: FA3Draft,
    *,
    validate: bool = True,
    xsd_validate: bool = False,
) -> bytes:
    structure_errors = draft._validate_xml_shape()
    if structure_errors:
        raise FA3XmlValidationError("; ".join(issue.message for issue in structure_errors))
    if validate:
        errors, _warnings = draft.validate()
        if errors:
            raise FA3XmlValidationError("; ".join(issue.message for issue in errors))

    ET.register_namespace("", FA3_NAMESPACE)
    ET.register_namespace("etd", ETD_NAMESPACE)
    ET.register_namespace("xsi", XSI_NAMESPACE)
    root = ET.Element(_q("Faktura"))
    root.set(f"{{{XSI_NAMESPACE}}}schemaLocation", f"{FA3_NAMESPACE} schemat_FA(3)_v1-0E.xsd")
    _header(root)
    _party(root, "Podmiot1", draft.seller)
    _party(root, "Podmiot2", draft.buyer)
    _invoice(root, draft)
    _basic_xml_validation(root)
    xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    if xsd_validate:
        validate_fa3_xml_xsd(xml)
    return xml


def invoice_to_xml(
    invoice: FA3Invoice,
    *,
    validate: bool = True,
    xsd_validate: bool = False,
) -> bytes:
    structure_errors = invoice._validate_xml_shape()
    if structure_errors:
        raise FA3XmlValidationError("; ".join(issue.message for issue in structure_errors))
    if validate:
        result = invoice.validate()
        if result.errors:
            raise FA3XmlValidationError("; ".join(issue.message for issue in result.errors))

    ET.register_namespace("", FA3_NAMESPACE)
    ET.register_namespace("etd", ETD_NAMESPACE)
    ET.register_namespace("xsi", XSI_NAMESPACE)
    root = ET.Element(_q("Faktura"))
    root.set(f"{{{XSI_NAMESPACE}}}schemaLocation", f"{FA3_NAMESPACE} schemat_FA(3)_v1-0E.xsd")
    _header(root)
    _domain_party(root, "Podmiot1", invoice.seller, seller=True)
    _domain_party(root, "Podmiot2", invoice.buyer, buyer=True)
    for party in invoice.additional_parties:
        _domain_party(root, "Podmiot3", party, third_party=True)
    if invoice.authorized_party is not None:
        _domain_party(root, "PodmiotUpowazniony", invoice.authorized_party, authorized=True)
    _domain_invoice(root, invoice)
    if invoice.footer is not None:
        _domain_footer(root, invoice.footer)
    if invoice.attachment is not None:
        _attachment(root, invoice.attachment)
    _basic_xml_validation(root)
    xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    if xsd_validate:
        validate_fa3_xml_xsd(xml)
    return xml


def validate_fa3_xml_xsd(xml: bytes | str) -> None:
    try:
        from lxml import etree
    except ImportError as exc:  # pragma: no cover - covered by optional dependency packaging.
        raise RuntimeError(
            'Walidacja XSD FA(3) wymaga lxml. Zainstaluj: pip install "ksef-client[fa3]".'
        ) from exc

    parser = etree.XMLParser()
    parser.resolvers.add(_schema_resolver(etree))
    schema_package = resources.files("ksef_client.documents.fa3.schemas")
    with resources.as_file(schema_package / "schemat_FA(3)_v1-0E.xsd") as schema_path:
        schema = etree.XMLSchema(etree.parse(str(schema_path), parser))
    document = etree.fromstring(xml.encode("utf-8") if isinstance(xml, str) else xml)
    if not schema.validate(document):
        error = schema.error_log.last_error
        detail = str(error) if error is not None else "nieznany błąd walidacji XSD"
        raise FA3XmlValidationError(detail)


def _schema_resolver(etree: Any) -> Any:
    class PackageSchemaResolver(etree.Resolver):
        def resolve(self, url: str, public_id: str | None, context: Any) -> Any:
            file_name = Path(url).name
            known = {
                "schemat_FA(3)_v1-0E.xsd",
                "StrukturyDanych_v10-0E.xsd",
                "ElementarneTypyDanych_v10-0E.xsd",
                "KodyKrajow_v10-0E.xsd",
            }
            if file_name not in known:
                return None
            schema_package = resources.files("ksef_client.documents.fa3.schemas")
            with resources.as_file(schema_package / file_name) as schema_path:
                return self.resolve_filename(str(schema_path), context)

    return PackageSchemaResolver()


def _header(root: ET.Element) -> None:
    header = ET.SubElement(root, _q("Naglowek"))
    form_code = ET.SubElement(header, _q("KodFormularza"))
    form_code.set("kodSystemowy", "FA (3)")
    form_code.set("wersjaSchemy", "1-0E")
    form_code.text = "FA"
    ET.SubElement(header, _q("WariantFormularza")).text = "3"
    ET.SubElement(header, _q("DataWytworzeniaFa")).text = (
        datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    ET.SubElement(header, _q("SystemInfo")).text = "ksef-client-python"


def _party(root: ET.Element, tag: str, party: FA3Party) -> None:
    node = ET.SubElement(root, _q(tag))
    identity = ET.SubElement(node, _q("DaneIdentyfikacyjne"))
    ET.SubElement(identity, _q("NIP")).text = party.tax_id
    ET.SubElement(identity, _q("Nazwa")).text = party.name
    address = ET.SubElement(node, _q("Adres"))
    ET.SubElement(address, _q("KodKraju")).text = party.country_code or "PL"
    ET.SubElement(address, _q("AdresL1")).text = party.address or "brak"
    if tag == "Podmiot2":
        contact = ET.SubElement(node, _q("DaneKontaktowe"))
        ET.SubElement(contact, _q("Email")).text = "brak@example.com"
        ET.SubElement(contact, _q("Telefon")).text = "000000000"
        ET.SubElement(node, _q("JST")).text = "2"
        ET.SubElement(node, _q("GV")).text = "2"


def _domain_party(
    root: ET.Element,
    tag: str,
    party: InvoiceParty,
    *,
    seller: bool = False,
    buyer: bool = False,
    third_party: bool = False,
    authorized: bool = False,
) -> None:
    node = ET.SubElement(root, _q(tag))
    if third_party and party.buyer_id:
        ET.SubElement(node, _q("IDNabywcy")).text = party.buyer_id
    if (seller or authorized) and party.taxpayer_prefix:
        ET.SubElement(node, _q("PrefiksPodatnika")).text = party.taxpayer_prefix
    if party.eori:
        ET.SubElement(node, _q("NrEORI")).text = party.eori
    _party_identity(node, party, seller=seller or authorized)
    if party.address is not None:
        _address(node, "Adres", party.address)
    if party.correspondence_address is not None:
        _address(node, "AdresKoresp", party.correspondence_address)
    for contact in party.contacts[:3]:
        contact_node = ET.SubElement(node, _q("DaneKontaktowe"))
        if contact.email:
            email_tag = "EmailPU" if authorized else "Email"
            ET.SubElement(contact_node, _q(email_tag)).text = contact.email
        if contact.phone:
            phone_tag = "TelefonPU" if authorized else "Telefon"
            ET.SubElement(contact_node, _q(phone_tag)).text = contact.phone
    if buyer:
        if party.customer_number:
            ET.SubElement(node, _q("NrKlienta")).text = party.customer_number
        if party.buyer_id:
            ET.SubElement(node, _q("IDNabywcy")).text = party.buyer_id
        ET.SubElement(node, _q("JST")).text = _yes_no(party.is_jst_subunit)
        ET.SubElement(node, _q("GV")).text = _yes_no(party.is_vat_group_member)
    if seller and party.taxpayer_status:
        ET.SubElement(node, _q("StatusInfoPodatnika")).text = party.taxpayer_status
    if third_party:
        _third_party_role(node, party)
        if party.share is not None:
            ET.SubElement(node, _q("Udzial")).text = _decimal(party.share)
        if party.customer_number:
            ET.SubElement(node, _q("NrKlienta")).text = party.customer_number
    if authorized:
        role = party.authorized_role or AuthorizedPartyRole.REPRESENTATIVE
        role_value = role.value if isinstance(role, AuthorizedPartyRole) else str(role)
        ET.SubElement(node, _q("RolaPU")).text = role_value


def _party_identity(node: ET.Element, party: InvoiceParty, *, seller: bool) -> None:
    identity = ET.SubElement(node, _q("DaneIdentyfikacyjne"))
    identifier = party.identifier
    if seller:
        if identifier.kind is not PartyIdentifierKind.NIP:
            raise FA3XmlValidationError("Podmiot1/PodmiotUpowazniony wymaga identyfikatora NIP.")
        ET.SubElement(identity, _q("NIP")).text = identifier.value
        ET.SubElement(identity, _q("Nazwa")).text = party.name
        return
    if identifier.kind is PartyIdentifierKind.NIP:
        ET.SubElement(identity, _q("NIP")).text = identifier.value
    elif identifier.kind is PartyIdentifierKind.EU_VAT:
        ET.SubElement(identity, _q("KodUE")).text = identifier.country_code
        ET.SubElement(identity, _q("NrVatUE")).text = identifier.value
    elif identifier.kind is PartyIdentifierKind.FOREIGN:
        if identifier.country_code:
            ET.SubElement(identity, _q("KodKraju")).text = identifier.country_code
        ET.SubElement(identity, _q("NrID")).text = identifier.value
    elif identifier.kind is PartyIdentifierKind.NONE:
        ET.SubElement(identity, _q("BrakID")).text = "1"
    elif identifier.kind is PartyIdentifierKind.INTERNAL:
        ET.SubElement(identity, _q("IDWew")).text = identifier.value
    ET.SubElement(identity, _q("Nazwa")).text = party.name


def _address(node: ET.Element, tag: str, address: Address) -> None:
    address_node = ET.SubElement(node, _q(tag))
    ET.SubElement(address_node, _q("KodKraju")).text = address.country_code
    ET.SubElement(address_node, _q("AdresL1")).text = address.line1
    if address.line2:
        ET.SubElement(address_node, _q("AdresL2")).text = address.line2
    if address.gln:
        ET.SubElement(address_node, _q("GLN")).text = address.gln


def _third_party_role(node: ET.Element, party: InvoiceParty) -> None:
    role = party.role
    role_value = getattr(role, "value", role)
    if str(role_value) == "other":
        if not party.other_role_description:
            raise FA3XmlValidationError("Podmiot3/RolaInna wymaga opisu roli.")
        ET.SubElement(node, _q("RolaInna")).text = "1"
        ET.SubElement(node, _q("OpisRoli")).text = party.other_role_description
    else:
        ET.SubElement(node, _q("Rola")).text = str(role_value)


def _domain_invoice(root: ET.Element, invoice: FA3Invoice) -> None:
    fa = ET.SubElement(root, _q("Fa"))
    ET.SubElement(fa, _q("KodWaluty")).text = invoice.currency
    ET.SubElement(fa, _q("P_1")).text = invoice.issue_date.isoformat()
    if invoice.issue_place:
        ET.SubElement(fa, _q("P_1M")).text = invoice.issue_place
    ET.SubElement(fa, _q("P_2")).text = invoice.invoice_number
    for document_number in invoice.warehouse_documents:
        ET.SubElement(fa, _q("WZ")).text = document_number
    if invoice.sale_date:
        ET.SubElement(fa, _q("P_6")).text = invoice.sale_date.isoformat()
    elif invoice.period_from and invoice.period_to:
        period = ET.SubElement(fa, _q("OkresFa"))
        ET.SubElement(period, _q("P_6_Od")).text = invoice.period_from.isoformat()
        ET.SubElement(period, _q("P_6_Do")).text = invoice.period_to.isoformat()
    _tax_summary(fa, invoice)
    if invoice.foreign_currency_rate is not None:
        ET.SubElement(fa, _q("KursWalutyZ")).text = _decimal(invoice.foreign_currency_rate)
    _domain_annotations(fa, invoice.annotations)
    ET.SubElement(fa, _q("RodzajFaktury")).text = invoice.kind.xml_code
    _domain_correction(fa, invoice)
    _domain_advance_payments(fa, invoice.advance_payments, invoice.issue_date)
    if invoice.fp:
        ET.SubElement(fa, _q("FP")).text = "1"
    if invoice.tp:
        ET.SubElement(fa, _q("TP")).text = "1"
    _domain_additional_descriptions(fa, invoice.additional_descriptions)
    _domain_advance_references(fa, invoice)
    if invoice.excise_refund and invoice.excise_refund.enabled:
        ET.SubElement(fa, _q("ZwrotAkcyzy")).text = "1"
    for index, line in enumerate(invoice.lines, start=1):
        _domain_line(fa, index, line)
    _domain_settlement(fa, invoice.settlement_data)
    _domain_payment(fa, invoice.payment_terms)
    _domain_transaction_terms(fa, invoice.transaction_terms)
    _domain_order(fa, invoice.order)


def _tax_summary(fa: ET.Element, invoice: FA3Invoice) -> None:
    summary: dict[str, Decimal] = {}
    vat_summary: dict[str, Decimal] = {}
    foreign_vat_summary: dict[str, Decimal] = {}
    for line in invoice.lines:
        net_tag, vat_tag, vat_w_tag = line.tax.summary_fields
        net_amount = invoice._signed_line_amount(line, line.effective_net_amount)
        vat_amount = invoice._signed_line_amount(line, line.effective_vat_amount)
        summary[net_tag] = money(summary.get(net_tag, Decimal("0.00")) + net_amount)
        if vat_tag:
            vat_summary[vat_tag] = money(
                vat_summary.get(vat_tag, Decimal("0.00")) + vat_amount
            )
            line_currency_rate = line.currency_rate or invoice.foreign_currency_rate
            if (
                vat_w_tag
                and line_currency_rate is not None
                and invoice.currency.upper() != "PLN"
            ):
                foreign_vat_summary[vat_w_tag] = money(
                    foreign_vat_summary.get(vat_w_tag, Decimal("0.00"))
                    + money(vat_amount * line_currency_rate)
                )
    for payment in invoice.advance_payments:
        net_tag, vat_tag, vat_w_tag = payment.tax.summary_fields
        net_amount = invoice._advance_payment_net_amount(payment)
        vat_amount = invoice._advance_payment_vat_amount(payment)
        summary[net_tag] = money(summary.get(net_tag, Decimal("0.00")) + net_amount)
        if vat_tag:
            vat_summary[vat_tag] = money(
                vat_summary.get(vat_tag, Decimal("0.00")) + vat_amount
            )
            payment_currency_rate = payment.currency_rate or invoice.foreign_currency_rate
            if (
                vat_w_tag
                and payment_currency_rate is not None
                and invoice.currency.upper() != "PLN"
            ):
                foreign_vat_summary[vat_w_tag] = money(
                    foreign_vat_summary.get(vat_w_tag, Decimal("0.00"))
                    + money(vat_amount * payment_currency_rate)
                )
    for net_tag, vat_tag, _vat_w_tag in _TAX_SUMMARY_ORDER:
        if net_tag in summary:
            ET.SubElement(fa, _q(net_tag)).text = _amount(summary[net_tag])
            if vat_tag and vat_tag in vat_summary:
                ET.SubElement(fa, _q(vat_tag)).text = _amount(vat_summary[vat_tag])
        if _vat_w_tag and _vat_w_tag in foreign_vat_summary:
            ET.SubElement(fa, _q(_vat_w_tag)).text = _amount(foreign_vat_summary[_vat_w_tag])
    ET.SubElement(fa, _q("P_15")).text = _amount(invoice.total_gross)


_TAX_SUMMARY_ORDER = (
    ("P_13_1", "P_14_1", "P_14_1W"),
    ("P_13_2", "P_14_2", "P_14_2W"),
    ("P_13_3", "P_14_3", "P_14_3W"),
    ("P_13_4", "P_14_4", "P_14_4W"),
    ("P_13_5", "P_14_5", None),
    ("P_13_6_1", None, None),
    ("P_13_6_2", None, None),
    ("P_13_6_3", None, None),
    ("P_13_7", None, None),
    ("P_13_8", None, None),
    ("P_13_9", None, None),
    ("P_13_10", None, None),
    ("P_13_11", None, None),
)


def _domain_annotations(fa: ET.Element, annotations: AnnotationSet) -> None:
    node = ET.SubElement(fa, _q("Adnotacje"))
    ET.SubElement(node, _q("P_16")).text = _yes_no(annotations.cash_method)
    ET.SubElement(node, _q("P_17")).text = _yes_no(annotations.self_billing)
    ET.SubElement(node, _q("P_18")).text = _yes_no(annotations.reverse_charge)
    ET.SubElement(node, _q("P_18A")).text = _yes_no(annotations.split_payment)
    exemption = ET.SubElement(node, _q("Zwolnienie"))
    if annotations.exemption_basis:
        ET.SubElement(exemption, _q("P_19")).text = "1"
        basis_tag = {
            "law": "P_19A",
            "directive": "P_19B",
            "other": "P_19C",
        }.get(annotations.exemption_basis_type, "P_19A")
        ET.SubElement(exemption, _q(basis_tag)).text = annotations.exemption_basis
    else:
        ET.SubElement(exemption, _q("P_19N")).text = "1"
    transport = ET.SubElement(node, _q("NoweSrodkiTransportu"))
    if annotations.new_transport or annotations.new_transport_means:
        ET.SubElement(transport, _q("P_22")).text = "1"
        ET.SubElement(transport, _q("P_42_5")).text = _yes_no(annotations.new_transport_intra_eu)
        for means in annotations.new_transport_means:
            _new_transport_means(transport, means)
    else:
        ET.SubElement(transport, _q("P_22N")).text = "1"
    ET.SubElement(node, _q("P_23")).text = _yes_no(annotations.simplified_triangular)
    margin = ET.SubElement(node, _q("PMarzy"))
    if annotations.margin_procedure:
        ET.SubElement(margin, _q("P_PMarzy")).text = "1"
        tag = {
            "travel": "P_PMarzy_2",
            "used_goods": "P_PMarzy_3_1",
            "art": "P_PMarzy_3_2",
            "collectibles": "P_PMarzy_3_3",
        }.get(annotations.margin_procedure, "P_PMarzy_3_1")
        ET.SubElement(margin, _q(tag)).text = "1"
    else:
        ET.SubElement(margin, _q("P_PMarzyN")).text = "1"


def _domain_correction(fa: ET.Element, invoice: FA3Invoice) -> None:
    if invoice.kind not in {
        FA3InvoiceKind.CORRECTION,
        FA3InvoiceKind.ADVANCE_CORRECTION,
        FA3InvoiceKind.SETTLEMENT_CORRECTION,
    }:
        return
    if invoice.correction_reason:
        ET.SubElement(fa, _q("PrzyczynaKorekty")).text = invoice.correction_reason
    if invoice.correction_type:
        ET.SubElement(fa, _q("TypKorekty")).text = invoice.correction_type
    for corrected in invoice.corrected_invoices:
        node = ET.SubElement(fa, _q("DaneFaKorygowanej"))
        ET.SubElement(node, _q("DataWystFaKorygowanej")).text = corrected.issue_date.isoformat()
        ET.SubElement(node, _q("NrFaKorygowanej")).text = corrected.invoice_number
        if corrected.ksef_number:
            ET.SubElement(node, _q("NrKSeF")).text = "1"
            ET.SubElement(node, _q("NrKSeFFaKorygowanej")).text = corrected.ksef_number
        else:
            ET.SubElement(node, _q("NrKSeFN")).text = "1"
    if invoice.corrected_period:
        ET.SubElement(fa, _q("OkresFaKorygowanej")).text = invoice.corrected_period
    if invoice.corrected_invoice_number_override:
        ET.SubElement(fa, _q("NrFaKorygowany")).text = invoice.corrected_invoice_number_override
    if invoice.corrected_seller is not None:
        node = ET.SubElement(fa, _q("Podmiot1K"))
        if invoice.corrected_seller.taxpayer_prefix:
            ET.SubElement(node, _q("PrefiksPodatnika")).text = (
                invoice.corrected_seller.taxpayer_prefix
            )
        _party_identity(node, invoice.corrected_seller, seller=True)
        if invoice.corrected_seller.address is not None:
            _address(node, "Adres", invoice.corrected_seller.address)
    for corrected_buyer in invoice.corrected_buyers:
        node = ET.SubElement(fa, _q("Podmiot2K"))
        _party_identity(node, corrected_buyer, seller=False)
        if corrected_buyer.address is not None:
            _address(node, "Adres", corrected_buyer.address)
        if corrected_buyer.buyer_id:
            ET.SubElement(node, _q("IDNabywcy")).text = corrected_buyer.buyer_id
    if invoice.corrected_advance_state is not None:
        ET.SubElement(fa, _q("P_15ZK")).text = _amount(invoice.corrected_advance_state.amount)
        if invoice.corrected_advance_state.currency_rate is not None:
            ET.SubElement(fa, _q("KursWalutyZK")).text = _decimal(
                invoice.corrected_advance_state.currency_rate
            )


def _domain_advance_payments(
    fa: ET.Element,
    payments: tuple[AdvancePayment, ...],
    issue_date: date,
) -> None:
    for payment in payments:
        node = ET.SubElement(fa, _q("ZaliczkaCzesciowa"))
        ET.SubElement(node, _q("P_6Z")).text = (payment.paid_on or issue_date).isoformat()
        ET.SubElement(node, _q("P_15Z")).text = _amount(payment.amount)
        if payment.currency_rate is not None:
            ET.SubElement(node, _q("KursWalutyZW")).text = _decimal(payment.currency_rate)


def _domain_additional_descriptions(
    fa: ET.Element,
    descriptions: tuple[AdditionalDescription, ...],
) -> None:
    for description in descriptions:
        node = ET.SubElement(fa, _q("DodatkowyOpis"))
        ET.SubElement(node, _q("Klucz")).text = description.key
        ET.SubElement(node, _q("Wartosc")).text = description.value


def _domain_advance_references(fa: ET.Element, invoice: FA3Invoice) -> None:
    for advance_ref in invoice.advance_invoices:
        node = ET.SubElement(fa, _q("FakturaZaliczkowa"))
        if advance_ref.ksef_number:
            ET.SubElement(node, _q("NrKSeFFaZaliczkowej")).text = advance_ref.ksef_number
        else:
            ET.SubElement(node, _q("NrKSeFZN")).text = "1"
            if advance_ref.invoice_number:
                ET.SubElement(node, _q("NrFaZaliczkowej")).text = advance_ref.invoice_number


def _domain_line(fa: ET.Element, index: int, line: InvoiceLine) -> None:
    row = ET.SubElement(fa, _q("FaWiersz"))
    ET.SubElement(row, _q("NrWierszaFa")).text = str(index)
    if line.unique_id:
        ET.SubElement(row, _q("UU_ID")).text = line.unique_id
    if line.service_date:
        ET.SubElement(row, _q("P_6A")).text = line.service_date.isoformat()
    ET.SubElement(row, _q("P_7")).text = line.description
    if line.identifiers is not None:
        if line.identifiers.internal_index:
            ET.SubElement(row, _q("Indeks")).text = line.identifiers.internal_index
        if line.identifiers.gtin:
            ET.SubElement(row, _q("GTIN")).text = line.identifiers.gtin
        if line.identifiers.pkwiu:
            ET.SubElement(row, _q("PKWiU")).text = line.identifiers.pkwiu
        if line.identifiers.cn:
            ET.SubElement(row, _q("CN")).text = line.identifiers.cn
        if line.identifiers.pkob:
            ET.SubElement(row, _q("PKOB")).text = line.identifiers.pkob
    ET.SubElement(row, _q("P_8A")).text = line.unit
    ET.SubElement(row, _q("P_8B")).text = _decimal(line.quantity)
    ET.SubElement(row, _q("P_9A")).text = _amount2(line.unit_net_price)
    if line.unit_gross_price is not None:
        ET.SubElement(row, _q("P_9B")).text = _amount2(line.unit_gross_price)
    if line.discount_amount:
        ET.SubElement(row, _q("P_10")).text = _amount2(line.discount_amount)
    ET.SubElement(row, _q("P_11")).text = _amount(line.effective_net_amount)
    if line.gross_amount is not None:
        ET.SubElement(row, _q("P_11A")).text = _amount(line.effective_gross_amount)
    if line.vat_amount is not None:
        ET.SubElement(row, _q("P_11Vat")).text = _amount(line.effective_vat_amount)
    if line.tax.xml_rate:
        ET.SubElement(row, _q("P_12")).text = line.tax.xml_rate
    if line.tax.xii_rate is not None:
        ET.SubElement(row, _q("P_12_XII")).text = _decimal(line.tax.xii_rate)
    if line.annex_15:
        ET.SubElement(row, _q("P_12_Zal_15")).text = "1"
    if line.excise_amount is not None:
        ET.SubElement(row, _q("KwotaAkcyzy")).text = _amount(line.excise_amount)
    if line.gtu:
        ET.SubElement(row, _q("GTU")).text = enum_value(line.gtu)
    if line.procedure:
        ET.SubElement(row, _q("Procedura")).text = enum_value(line.procedure)
    if line.currency_rate is not None:
        ET.SubElement(row, _q("KursWaluty")).text = _decimal(line.currency_rate)
    if line.before_correction:
        ET.SubElement(row, _q("StanPrzed")).text = "1"


def _domain_settlement(fa: ET.Element, settlement: Settlement | None) -> None:
    if settlement is None:
        return
    node = ET.SubElement(fa, _q("Rozliczenie"))
    for charge in settlement.charges:
        charge_node = ET.SubElement(node, _q("Obciazenia"))
        ET.SubElement(charge_node, _q("Kwota")).text = _amount(charge.amount)
        ET.SubElement(charge_node, _q("Powod")).text = charge.reason
    if settlement.charges:
        total = sum((charge.amount for charge in settlement.charges), Decimal("0.00"))
        ET.SubElement(node, _q("SumaObciazen")).text = _amount(money(total))
    for deduction in settlement.deductions:
        deduction_node = ET.SubElement(node, _q("Odliczenia"))
        ET.SubElement(deduction_node, _q("Kwota")).text = _amount(deduction.amount)
        ET.SubElement(deduction_node, _q("Powod")).text = deduction.reason
    if settlement.deductions:
        total = sum((deduction.amount for deduction in settlement.deductions), Decimal("0.00"))
        ET.SubElement(node, _q("SumaOdliczen")).text = _amount(money(total))
    if settlement.amount_due is not None:
        ET.SubElement(node, _q("DoZaplaty")).text = _amount(settlement.amount_due)
    elif settlement.amount_to_settle is not None:
        ET.SubElement(node, _q("DoRozliczenia")).text = _amount(settlement.amount_to_settle)


def _domain_payment(fa: ET.Element, payment: PaymentTerms | None) -> None:
    if payment is None:
        return
    node = ET.SubElement(fa, _q("Platnosc"))
    if payment.paid_date:
        ET.SubElement(node, _q("Zaplacono")).text = "1"
        ET.SubElement(node, _q("DataZaplaty")).text = payment.paid_date.isoformat()
    elif payment.partial_payments:
        ET.SubElement(node, _q("ZnacznikZaplatyCzesciowej")).text = "1"
        for partial in payment.partial_payments:
            _partial_payment(node, partial)
    due_terms = payment.due_terms or tuple(PaymentDue.date(value) for value in payment.due_dates)
    for due_term in due_terms:
        due_node = ET.SubElement(node, _q("TerminPlatnosci"))
        if due_term.due_date is not None:
            ET.SubElement(due_node, _q("Termin")).text = due_term.due_date.isoformat()
        if due_term.term_description is not None:
            description = ET.SubElement(due_node, _q("TerminOpis"))
            ET.SubElement(description, _q("Ilosc")).text = str(due_term.term_description.amount)
            ET.SubElement(description, _q("Jednostka")).text = due_term.term_description.unit
            ET.SubElement(description, _q("ZdarzeniePoczatkowe")).text = (
                due_term.term_description.starts_from
            )
    _payment_method(node, payment.method, payment.other_method_description)
    for account in payment.bank_accounts:
        _bank_account(node, "RachunekBankowy", account)
    for account in payment.factor_accounts:
        _bank_account(node, "RachunekBankowyFaktora", account)
    if payment.cash_discount_terms and payment.cash_discount_amount:
        discount = ET.SubElement(node, _q("Skonto"))
        ET.SubElement(discount, _q("WarunkiSkonta")).text = payment.cash_discount_terms
        ET.SubElement(discount, _q("WysokoscSkonta")).text = payment.cash_discount_amount
    if payment.payment_link:
        ET.SubElement(node, _q("LinkDoPlatnosci")).text = payment.payment_link
    if payment.ipksef:
        ET.SubElement(node, _q("IPKSeF")).text = payment.ipksef


def _domain_transaction_terms(fa: ET.Element, terms: TransactionTerms | None) -> None:
    if terms is None:
        return
    node = ET.SubElement(fa, _q("WarunkiTransakcji"))
    for contract in terms.contracts:
        contract_node = ET.SubElement(node, _q("Umowy"))
        if contract.date:
            ET.SubElement(contract_node, _q("DataUmowy")).text = contract.date.isoformat()
        if contract.number:
            ET.SubElement(contract_node, _q("NrUmowy")).text = contract.number
    for order_ref in terms.orders:
        order_node = ET.SubElement(node, _q("Zamowienia"))
        if order_ref.date:
            ET.SubElement(order_node, _q("DataZamowienia")).text = order_ref.date.isoformat()
        if order_ref.number:
            ET.SubElement(order_node, _q("NrZamowienia")).text = order_ref.number
    for batch_number in terms.batch_numbers:
        ET.SubElement(node, _q("NrPartiiTowaru")).text = batch_number
    if terms.delivery_terms:
        ET.SubElement(node, _q("WarunkiDostawy")).text = terms.delivery_terms
    if terms.contractual_rate is not None and terms.contractual_currency:
        ET.SubElement(node, _q("KursUmowny")).text = _decimal(terms.contractual_rate)
        ET.SubElement(node, _q("WalutaUmowna")).text = terms.contractual_currency
    for transport in terms.transports:
        _domain_transport(node, transport)
    if terms.intermediary:
        ET.SubElement(node, _q("PodmiotPosredniczacy")).text = "1"


def _domain_transport(parent: ET.Element, transport: Transport) -> None:
    node = ET.SubElement(parent, _q("Transport"))
    if transport.other_kind_description:
        ET.SubElement(node, _q("TransportInny")).text = "1"
        ET.SubElement(node, _q("OpisInnegoTransportu")).text = transport.other_kind_description
    elif transport.kind:
        ET.SubElement(node, _q("RodzajTransportu")).text = transport.kind
    else:
        ET.SubElement(node, _q("RodzajTransportu")).text = "3"
    if transport.carrier is not None:
        carrier = ET.SubElement(node, _q("Przewoznik"))
        _party_identity(carrier, transport.carrier, seller=False)
        if transport.carrier.address is not None:
            _address(carrier, "AdresPrzewoznika", transport.carrier.address)
    if transport.order_number:
        ET.SubElement(node, _q("NrZleceniaTransportu")).text = transport.order_number
    if transport.other_cargo_description:
        ET.SubElement(node, _q("LadunekInny")).text = "1"
        ET.SubElement(node, _q("OpisInnegoLadunku")).text = transport.other_cargo_description
    else:
        ET.SubElement(node, _q("OpisLadunku")).text = transport.cargo_description
    if transport.package_unit:
        ET.SubElement(node, _q("JednostkaOpakowania")).text = transport.package_unit
    if transport.started_at:
        ET.SubElement(node, _q("DataGodzRozpTransportu")).text = transport.started_at.isoformat()
    if transport.finished_at:
        ET.SubElement(node, _q("DataGodzZakTransportu")).text = transport.finished_at.isoformat()
    if transport.ship_from is not None:
        _address(node, "WysylkaZ", transport.ship_from)
    for address in transport.ship_via:
        _address(node, "WysylkaPrzez", address)
    if transport.ship_to is not None:
        _address(node, "WysylkaDo", transport.ship_to)


def _domain_order(fa: ET.Element, order: Order | None) -> None:
    if order is None:
        return
    node = ET.SubElement(fa, _q("Zamowienie"))
    ET.SubElement(node, _q("WartoscZamowienia")).text = _amount(order.total_gross)
    for index, line in enumerate(order.lines, start=1):
        _domain_order_line(node, index, line)


def _domain_order_line(parent: ET.Element, index: int, line: OrderLine) -> None:
    row = ET.SubElement(parent, _q("ZamowienieWiersz"))
    ET.SubElement(row, _q("NrWierszaZam")).text = str(index)
    if line.identifiers is not None and line.identifiers.unique_id:
        ET.SubElement(row, _q("UU_IDZ")).text = line.identifiers.unique_id
    ET.SubElement(row, _q("P_7Z")).text = line.description
    if line.identifiers is not None:
        if line.identifiers.internal_index:
            ET.SubElement(row, _q("IndeksZ")).text = line.identifiers.internal_index
        if line.identifiers.gtin:
            ET.SubElement(row, _q("GTINZ")).text = line.identifiers.gtin
        if line.identifiers.pkwiu:
            ET.SubElement(row, _q("PKWiUZ")).text = line.identifiers.pkwiu
        if line.identifiers.cn:
            ET.SubElement(row, _q("CNZ")).text = line.identifiers.cn
        if line.identifiers.pkob:
            ET.SubElement(row, _q("PKOBZ")).text = line.identifiers.pkob
    ET.SubElement(row, _q("P_8AZ")).text = line.unit
    ET.SubElement(row, _q("P_8BZ")).text = _decimal(line.quantity)
    ET.SubElement(row, _q("P_9AZ")).text = _amount2(line.unit_net_price)
    ET.SubElement(row, _q("P_11NettoZ")).text = _amount(line.effective_net_amount)
    ET.SubElement(row, _q("P_11VatZ")).text = _amount(line.effective_vat_amount)
    if line.tax.xml_rate:
        ET.SubElement(row, _q("P_12Z")).text = line.tax.xml_rate
    if line.tax.xii_rate is not None:
        ET.SubElement(row, _q("P_12Z_XII")).text = _decimal(line.tax.xii_rate)
    if line.annex_15:
        ET.SubElement(row, _q("P_12Z_Zal_15")).text = "1"
    if line.gtu:
        ET.SubElement(row, _q("GTUZ")).text = line.gtu
    if line.procedure:
        ET.SubElement(row, _q("ProceduraZ")).text = line.procedure
    if line.excise_amount is not None:
        ET.SubElement(row, _q("KwotaAkcyzyZ")).text = _amount(line.excise_amount)
    if line.before_correction:
        ET.SubElement(row, _q("StanPrzedZ")).text = "1"


def _new_transport_means(parent: ET.Element, means: NewTransportMeans) -> None:
    node = ET.SubElement(parent, _q("NowySrodekTransportu"))
    ET.SubElement(node, _q("P_22A")).text = means.allowed_date.isoformat()
    ET.SubElement(node, _q("P_NrWierszaNST")).text = str(means.row_number)
    if means.make:
        ET.SubElement(node, _q("P_22BMK")).text = means.make
    if means.model:
        ET.SubElement(node, _q("P_22BMD")).text = means.model
    if means.color:
        ET.SubElement(node, _q("P_22BK")).text = means.color
    if means.registry_number:
        ET.SubElement(node, _q("P_22BNR")).text = means.registry_number
    if means.manufacture_year:
        ET.SubElement(node, _q("P_22BRP")).text = means.manufacture_year
    if means.kind == "water":
        ET.SubElement(node, _q("P_22C")).text = means.hours_used or "0"
        if means.serial_number:
            ET.SubElement(node, _q("P_22C1")).text = means.serial_number
    elif means.kind == "air":
        ET.SubElement(node, _q("P_22D")).text = means.hours_used or "0"
        if means.serial_number:
            ET.SubElement(node, _q("P_22D1")).text = means.serial_number
    else:
        ET.SubElement(node, _q("P_22B")).text = means.mileage or "0"
        # XSD allows exactly one optional identifier from the P_22B1..P_22B4 choice.
        if means.serial_number:
            ET.SubElement(node, _q("P_22B1")).text = means.serial_number
        elif means.engine_capacity:
            ET.SubElement(node, _q("P_22B2")).text = means.engine_capacity
        elif means.engine_power:
            ET.SubElement(node, _q("P_22B3")).text = means.engine_power
        elif means.approval_number:
            ET.SubElement(node, _q("P_22B4")).text = means.approval_number
        if means.tax_rate:
            ET.SubElement(node, _q("P_22BT")).text = means.tax_rate


def _partial_payment(node: ET.Element, partial: PartialPayment) -> None:
    partial_node = ET.SubElement(node, _q("ZaplataCzesciowa"))
    ET.SubElement(partial_node, _q("KwotaZaplatyCzesciowej")).text = _amount(partial.amount)
    ET.SubElement(partial_node, _q("DataZaplatyCzesciowej")).text = partial.payment_date.isoformat()
    _payment_method(partial_node, partial.method, partial.other_method_description)


def _payment_method(
    node: ET.Element,
    method: str | None,
    other_method_description: str | None,
) -> None:
    if other_method_description:
        ET.SubElement(node, _q("PlatnoscInna")).text = "1"
        ET.SubElement(node, _q("OpisPlatnosci")).text = other_method_description
    elif method:
        ET.SubElement(node, _q("FormaPlatnosci")).text = _payment_code(method)


def _bank_account(node: ET.Element, tag: str, account: BankAccount) -> None:
    account_node = ET.SubElement(node, _q(tag))
    if account.number:
        ET.SubElement(account_node, _q("NrRB")).text = account.number
    if account.swift:
        ET.SubElement(account_node, _q("SWIFT")).text = account.swift
    if account.own_bank_account:
        ET.SubElement(account_node, _q("RachunekWlasnyBanku")).text = account.own_bank_account
    if account.bank_name:
        ET.SubElement(account_node, _q("NazwaBanku")).text = account.bank_name
    if account.description:
        ET.SubElement(account_node, _q("OpisRachunku")).text = account.description


def _attachment(root: ET.Element, attachment: Attachment) -> None:
    node = ET.SubElement(root, _q("Zalacznik"))
    for block in attachment.blocks:
        _attachment_block(node, block)


def _attachment_block(parent: ET.Element, block: AttachmentBlock) -> None:
    node = ET.SubElement(parent, _q("BlokDanych"))
    if block.header:
        ET.SubElement(node, _q("ZNaglowek")).text = block.header
    for key, value in block.metadata:
        meta = ET.SubElement(node, _q("MetaDane"))
        ET.SubElement(meta, _q("ZKlucz")).text = key
        ET.SubElement(meta, _q("ZWartosc")).text = value
    if block.paragraphs:
        text = ET.SubElement(node, _q("Tekst"))
        for paragraph in block.paragraphs:
            ET.SubElement(text, _q("Akapit")).text = paragraph
    for table in block.tables:
        _attachment_table(node, table)


def _attachment_table(parent: ET.Element, table: AttachmentTable) -> None:
    node = ET.SubElement(parent, _q("Tabela"))
    for key, value in table.metadata:
        meta = ET.SubElement(node, _q("TMetaDane"))
        ET.SubElement(meta, _q("TKlucz")).text = key
        ET.SubElement(meta, _q("TWartosc")).text = value
    if table.description:
        ET.SubElement(node, _q("Opis")).text = table.description
    header = ET.SubElement(node, _q("TNaglowek"))
    column_types = table.column_types or tuple("txt" for _ in table.headers)
    for value, column_type in zip(table.headers, column_types, strict=False):
        column = ET.SubElement(header, _q("Kol"))
        column.set("Typ", column_type)
        ET.SubElement(column, _q("NKom")).text = value
    for row_values in table.rows:
        row = ET.SubElement(node, _q("Wiersz"))
        for value in row_values:
            ET.SubElement(row, _q("WKom")).text = value
    if table.footer:
        footer = ET.SubElement(node, _q("Suma"))
        for value in table.footer:
            ET.SubElement(footer, _q("SKom")).text = value


def _domain_footer(root: ET.Element, footer: Footer) -> None:
    node = ET.SubElement(root, _q("Stopka"))
    for info in footer.infos:
        info_node = ET.SubElement(node, _q("Informacje"))
        ET.SubElement(info_node, _q("StopkaFaktury")).text = info
    for registry in footer.registries:
        registry_node = ET.SubElement(node, _q("Rejestry"))
        if registry.full_name:
            ET.SubElement(registry_node, _q("PelnaNazwa")).text = registry.full_name
        if registry.krs:
            ET.SubElement(registry_node, _q("KRS")).text = registry.krs
        if registry.regon:
            ET.SubElement(registry_node, _q("REGON")).text = registry.regon
        if registry.bdo:
            ET.SubElement(registry_node, _q("BDO")).text = registry.bdo


def _invoice(root: ET.Element, draft: FA3Draft) -> None:
    fa = ET.SubElement(root, _q("Fa"))
    ET.SubElement(fa, _q("KodWaluty")).text = draft.currency
    ET.SubElement(fa, _q("P_1")).text = draft.issue_date.isoformat()
    if draft.issue_place:
        ET.SubElement(fa, _q("P_1M")).text = draft.issue_place
    ET.SubElement(fa, _q("P_2")).text = draft.invoice_number
    ET.SubElement(fa, _q("P_13_1")).text = _amount(draft.total_net)
    ET.SubElement(fa, _q("P_14_1")).text = _amount(draft.total_vat)
    ET.SubElement(fa, _q("P_15")).text = _amount(draft.total_gross)
    _annotations(fa)
    ET.SubElement(fa, _q("RodzajFaktury")).text = draft.kind.xml_code
    _correction(fa, draft)
    _advance_invoice_reference(fa, draft)
    for index, line in enumerate(draft.lines, start=1):
        row = ET.SubElement(fa, _q("FaWiersz"))
        ET.SubElement(row, _q("NrWierszaFa")).text = str(index)
        ET.SubElement(row, _q("P_7")).text = line.description
        ET.SubElement(row, _q("P_8A")).text = line.unit
        ET.SubElement(row, _q("P_8B")).text = _amount(line.quantity)
        ET.SubElement(row, _q("P_9A")).text = _amount(line.unit_net_price)
        ET.SubElement(row, _q("P_11")).text = _amount(line.effective_net_amount)
        ET.SubElement(row, _q("P_12")).text = _vat_rate(line.vat_rate)
    _settlement(fa, draft)
    _payment(fa, draft)


def _annotations(fa: ET.Element) -> None:
    annotations = ET.SubElement(fa, _q("Adnotacje"))
    for tag in ("P_16", "P_17", "P_18", "P_18A"):
        ET.SubElement(annotations, _q(tag)).text = "2"
    exemption = ET.SubElement(annotations, _q("Zwolnienie"))
    ET.SubElement(exemption, _q("P_19N")).text = "1"
    transport = ET.SubElement(annotations, _q("NoweSrodkiTransportu"))
    ET.SubElement(transport, _q("P_22N")).text = "1"
    ET.SubElement(annotations, _q("P_23")).text = "2"
    margin = ET.SubElement(annotations, _q("PMarzy"))
    ET.SubElement(margin, _q("P_PMarzyN")).text = "1"


def _correction(fa: ET.Element, draft: FA3Draft) -> None:
    if draft.kind not in {
        FA3InvoiceKind.CORRECTION,
        FA3InvoiceKind.ADVANCE_CORRECTION,
        FA3InvoiceKind.SETTLEMENT_CORRECTION,
    }:
        return
    correction = ET.SubElement(fa, _q("PrzyczynaKorekty"))
    correction.text = draft.correction_reason
    corrected = ET.SubElement(fa, _q("DaneFaKorygowanej"))
    if draft.corrected_invoice_date:
        ET.SubElement(
            corrected, _q("DataWystFaKorygowanej")
        ).text = draft.corrected_invoice_date.isoformat()
    if draft.corrected_invoice_number:
        ET.SubElement(corrected, _q("NrFaKorygowanej")).text = draft.corrected_invoice_number
    if draft.corrected_ksef_number:
        ET.SubElement(corrected, _q("NrKSeF")).text = "1"
        ET.SubElement(corrected, _q("NrKSeFFaKorygowanej")).text = draft.corrected_ksef_number
    else:
        ET.SubElement(corrected, _q("NrKSeFN")).text = "1"


def _advance_invoice_reference(fa: ET.Element, draft: FA3Draft) -> None:
    if not (draft.advance_invoice_number or draft.advance_ksef_number):
        return
    advance = ET.SubElement(fa, _q("FakturaZaliczkowa"))
    if draft.advance_ksef_number:
        ET.SubElement(advance, _q("NrKSeFFaZaliczkowej")).text = draft.advance_ksef_number
    else:
        ET.SubElement(advance, _q("NrKSeFZN")).text = "1"
        ET.SubElement(advance, _q("NrFaZaliczkowej")).text = draft.advance_invoice_number


def _settlement(fa: ET.Element, draft: FA3Draft) -> None:
    if draft.settlement_amount is not None:
        settlement = ET.SubElement(fa, _q("Rozliczenie"))
        ET.SubElement(settlement, _q("DoZaplaty")).text = _amount(draft.settlement_amount)


def _payment(fa: ET.Element, draft: FA3Draft) -> None:
    if not (draft.payment_due_date or draft.payment_method):
        return
    payment = ET.SubElement(fa, _q("Platnosc"))
    if draft.payment_due_date:
        due = ET.SubElement(payment, _q("TerminPlatnosci"))
        ET.SubElement(due, _q("Termin")).text = draft.payment_due_date.isoformat()
    if draft.payment_method:
        ET.SubElement(payment, _q("FormaPlatnosci")).text = _payment_code(draft.payment_method)


def _payment_code(value: str) -> str:
    aliases = {
        "gotówka": "1",
        "gotowka": "1",
        "karta": "2",
        "bon": "3",
        "czek": "4",
        "kredyt": "5",
        "przelew": "6",
        "mobilna": "7",
        "platnosc mobilna": "7",
        "płatność mobilna": "7",
        "mobile": "7",
    }
    return aliases.get(value.strip().lower(), value)


def _basic_xml_validation(root: ET.Element) -> None:
    required = ["Naglowek", "Podmiot1", "Podmiot2", "Fa"]
    missing = [tag for tag in required if root.find(_q(tag)) is None]
    if missing:
        raise FA3XmlValidationError(
            "XML FA(3) nie zawiera wymaganych elementów: " + ", ".join(missing)
        )


def _q(tag: str) -> str:
    return f"{{{FA3_NAMESPACE}}}{tag}"


def _amount(value: Decimal) -> str:
    return f"{value:.2f}"


def _amount2(value: Decimal) -> str:
    return f"{value:.2f}"


def _decimal(value: Decimal) -> str:
    if value == value.to_integral_value():
        return str(int(value))
    return format(value.normalize(), "f")


def _yes_no(value: bool) -> str:
    return "1" if value else "2"


def _vat_rate(value: Decimal | None) -> str:
    if value is None:
        return "zw"
    if value == value.to_integral_value():
        return str(int(value))
    return format(value.normalize(), "f")
