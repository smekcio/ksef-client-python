from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from importlib import resources
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET

from .models import FA3Draft, FA3InvoiceKind, FA3Party

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
        "przelew": "6",
        "kompensata": "7",
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


def _vat_rate(value: Decimal | None) -> str:
    if value is None:
        return "zw"
    if value == value.to_integral_value():
        return str(int(value))
    return format(value.normalize(), "f")
