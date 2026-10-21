"""Odczyt XML FA(3) do modelu domenowego.

Moduł jest odwrotnością :func:`ksef_client.documents.fa3.xml.invoice_to_xml`:
zamienia dokument FA(3) (np. pobrany z KSeF) na :class:`FA3Invoice`, którego
można użyć do analizy, rekoncyliacji albo ponownej serializacji.

```python
from ksef_client.documents.fa3 import parse_invoice_xml

invoice = parse_invoice_xml(Path("fa.xml").read_bytes())
print(invoice.invoice_number, invoice.total_gross)
```

Czego ten parser **nie** robi:

* nie waliduje biznesowo dokumentu (``FA3Invoice.validate()`` bywa surowsze niż
  XSD — np. dla faktury uproszczonej bez nazwy nabywcy),
* nie jest odwzorowaniem bezstratnym: elementy spoza modelu trafiają do
  ``warnings``, a nie do ``raw_extensions`` (serializator ich nie odtwarza),
* nie odtwarza stawek zaliczek, których XML nie zawiera — dla
  ``ZaliczkaCzesciowa`` stawka jest wnioskowana z pól podsumowania, a gdy to
  się nie uda, parser używa stawki 23% (tak jak builder) i dodaje ostrzeżenie.

Bezpieczeństwo: parser odrzuca deklaracje ``DOCTYPE``/``ENTITY`` (ochrona przed
ekspansją encji) i ma limit rozmiaru dokumentu. Nie pobiera niczego z sieci.
"""

from __future__ import annotations

import xml.parsers.expat as _expat
from dataclasses import replace
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from xml.etree import ElementTree as ET

from ...utils.datetime_parsing import parse_api_datetime
from .domain import (
    SETTLEMENT_SCALE_KINDS,
    Address,
    AdvanceInvoiceReference,
    AnnotationSet,
    Attachment,
    AttachmentBlock,
    AttachmentTable,
    AuthorizedPartyRole,
    BankAccount,
    Contact,
    CorrectionReference,
    Discount,
    DiscountKind,
    FA3Invoice,
    InvoiceLine,
    InvoiceParty,
    PartialPayment,
    PartyIdentifier,
    PartyIdentifierKind,
    PaymentTerms,
    Settlement,
    SettlementAdjustment,
    TaxCategory,
    TaxCategoryKind,
    ThirdPartyRole,
)
from .models import FA3InvoiceKind, FA3ValidationIssue
from .sections import (
    AdditionalDescription,
    AdvancePayment,
    Contract,
    CorrectedAdvanceState,
    ExciseRefund,
    Footer,
    LineIdentifiers,
    NewTransportMeans,
    Order,
    OrderLine,
    PaymentDue,
    PaymentDueDescription,
    Registry,
    TransactionTerms,
    Transport,
)
from .xml import FA3_NAMESPACE

#: Górny limit rozmiaru dokumentu — faktura FA(3) to kilobajty, nie megabajty.
#: Limit chroni przed przypadkowym podaniem ogromnego pliku (np. archiwum ZIP).
MAX_XML_BYTES = 20 * 1024 * 1024

_DTD_ERROR = (
    "XML zawiera deklarację DTD (DOCTYPE/ENTITY) — parsowanie takich dokumentów "
    "jest zablokowane (ochrona przed ekspansją encji)."
)

#: Rodzaje faktur, w których wiersz przed korektą ma ujemną wartość w podsumowaniu.
_CORRECTION_KINDS = frozenset(
    {
        FA3InvoiceKind.CORRECTION,
        FA3InvoiceKind.ADVANCE_CORRECTION,
        FA3InvoiceKind.SETTLEMENT_CORRECTION,
    }
)

_TAX_SUMMARY_TAGS = frozenset(
    {
        "P_13_1",
        "P_13_2",
        "P_13_3",
        "P_13_4",
        "P_13_5",
        "P_13_6_1",
        "P_13_6_2",
        "P_13_6_3",
        "P_13_7",
        "P_13_8",
        "P_13_9",
        "P_13_10",
        "P_13_11",
        "P_14_1",
        "P_14_2",
        "P_14_3",
        "P_14_4",
        "P_14_5",
        "P_14_1W",
        "P_14_2W",
        "P_14_3W",
        "P_14_4W",
        "P_15",
    }
)

#: Kandydaci stawek dla koszyka podsumowania (kolejność ma znaczenie tylko
#: dla komunikatu — dopasowanie wymaga dokładnie jednego trafienia).
_ADVANCE_RATE_CANDIDATES: dict[str, tuple[Decimal, ...]] = {
    "P_13_1": (Decimal("23"), Decimal("22")),
    "P_13_2": (Decimal("8"), Decimal("7")),
    "P_13_3": (Decimal("5"),),
    "P_13_4": (Decimal("4"), Decimal("3")),
}

#: Wszystkie koszyki netto, w których może wylądować zaliczka.
_ADVANCE_NET_TAGS: tuple[str, ...] = (
    "P_13_1",
    "P_13_2",
    "P_13_3",
    "P_13_4",
    "P_13_5",
    "P_13_6_1",
    "P_13_6_2",
    "P_13_6_3",
    "P_13_7",
    "P_13_8",
    "P_13_9",
    "P_13_10",
    "P_13_11",
)


class FA3ParseError(ValueError):
    """Dokument nie jest poprawnym XML-em FA(3) albo brakuje wymaganego pola."""


# --- pomocnicze -----------------------------------------------------------


def _tag(local_name: str) -> str:
    return f"{{{FA3_NAMESPACE}}}{local_name}"


def _local(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _child(node: ET.Element, name: str) -> ET.Element | None:
    for candidate in node:
        if _local(candidate) == name:
            return candidate
    return None


def _children(node: ET.Element, name: str) -> list[ET.Element]:
    return [candidate for candidate in node if _local(candidate) == name]


def _attr(element: ET.Element, name: str) -> str | None:
    value = element.get(name)
    return value.strip() if value and value.strip() else None


def _text(node: ET.Element, name: str) -> str | None:
    element = _child(node, name)
    if element is None or element.text is None:
        return None
    value = element.text.strip()
    return value or None


def _required_child(node: ET.Element, name: str, path: str) -> ET.Element:
    element = _child(node, name)
    if element is None:
        raise FA3ParseError(f"{path}: brak wymaganego elementu '{name}'.")
    return element


def _required_text(node: ET.Element, name: str, path: str) -> str:
    value = _text(node, name)
    if value is None:
        raise FA3ParseError(f"{path}: brak wymaganego elementu '{name}'.")
    return value


def _decimal(value: str, path: str) -> Decimal:
    normalized = value.strip().replace(",", ".")
    # XSD `decimal` nie dopuszcza notacji wykładniczej, a `Decimal` przyjmuje ją
    # bez oporu. Wartość typu "1e999999999" przeszłaby więc walidację formatu,
    # a późniejsze działania na zaliczkach mogłyby zakończyć się wyjątkiem
    # `decimal.Overflow` — zamiast czytelnego błędu parsowania.
    if "e" in normalized.lower():
        raise FA3ParseError(f"{path}: '{value}' nie jest liczbą.")
    try:
        parsed = Decimal(normalized)
    except (InvalidOperation, AttributeError) as exc:
        raise FA3ParseError(f"{path}: '{value}' nie jest liczbą.") from exc
    if not parsed.is_finite():
        raise FA3ParseError(f"{path}: '{value}' nie jest skończoną liczbą.")
    return parsed


def _decimal_opt(node: ET.Element, name: str, path: str) -> Decimal | None:
    value = _text(node, name)
    if value is None:
        return None
    return _decimal(value, f"{path}/{name}")


def _date(value: str, path: str) -> date:
    try:
        return date.fromisoformat(value.strip())
    except ValueError as exc:
        raise FA3ParseError(f"{path}: '{value}' nie jest poprawną datą (YYYY-MM-DD).") from exc


def _date_opt(node: ET.Element, name: str, path: str) -> date | None:
    value = _text(node, name)
    if value is None:
        return None
    return _date(value, f"{path}/{name}")


def _datetime_opt(node: ET.Element, name: str, path: str) -> datetime | None:
    value = _text(node, name)
    if value is None:
        return None
    try:
        return parse_api_datetime(value)
    except ValueError as exc:
        raise FA3ParseError(
            f"{path}/{name}: '{value}' nie jest poprawnym znacznikiem czasu."
        ) from exc


def _yes(value: str | None) -> bool:
    return value is not None and value.strip() == "1"


def _flag(node: ET.Element, name: str) -> bool:
    return _yes(_text(node, name))


def _warning(message: str) -> FA3ValidationIssue:
    return FA3ValidationIssue(message, severity="warning")


def _warn_unknown(
    node: ET.Element,
    known: frozenset[str],
    path: str,
    warnings: list[FA3ValidationIssue],
) -> None:
    for candidate in node:
        name = _local(candidate)
        if name not in known:
            warnings.append(
                _warning(f"{path}: element '{name}' nie jest obsługiwany przez SDK — pominięty.")
            )


def _as_bytes(xml: bytes | bytearray | str) -> bytes:
    if isinstance(xml, str):
        return xml.encode("utf-8")
    if isinstance(xml, (bytes, bytearray)):
        return bytes(xml)
    raise FA3ParseError(
        f"XML musi być tekstem albo bajtami, otrzymano {type(xml).__name__}."
    )


# --- strony i adresy ------------------------------------------------------


def _parse_address(node: ET.Element | None, path: str) -> Address | None:
    if node is None:
        return None
    line1 = _required_text(node, "AdresL1", path)
    return Address(
        line1=line1,
        country_code=_text(node, "KodKraju") or "PL",
        line2=_text(node, "AdresL2"),
        gln=_text(node, "GLN"),
    )


def _parse_address_list(nodes: list[ET.Element], path: str) -> tuple[Address, ...]:
    """Parsuje listę adresów (``WysylkaPrzez``); wejście zawsze zawiera elementy."""
    addresses: list[Address] = []
    for index, node in enumerate(nodes, start=1):
        address = _parse_address(node, f"{path}[{index}]")
        assert address is not None
        addresses.append(address)
    return tuple(addresses)


def _parse_identifier(identity: ET.Element, path: str) -> PartyIdentifier:
    nip = _text(identity, "NIP")
    if nip is not None:
        return PartyIdentifier(PartyIdentifierKind.NIP, nip)
    eu_country = _text(identity, "KodUE")
    eu_number = _text(identity, "NrVatUE")
    if eu_country is not None or eu_number is not None:
        if eu_country is None or eu_number is None:
            raise FA3ParseError(
                f"{path}: identyfikator unijny wymaga jednocześnie KodUE i NrVatUE."
            )
        return PartyIdentifier(PartyIdentifierKind.EU_VAT, eu_number, country_code=eu_country)
    foreign_country = _text(identity, "KodKraju")
    foreign_number = _text(identity, "NrID")
    if foreign_country is not None or foreign_number is not None:
        if foreign_number is None:
            raise FA3ParseError(f"{path}: identyfikator zagraniczny wymaga NrID.")
        return PartyIdentifier(
            PartyIdentifierKind.FOREIGN,
            foreign_number,
            country_code=foreign_country,
        )
    if _flag(identity, "BrakID"):
        return PartyIdentifier(PartyIdentifierKind.NONE)
    internal = _text(identity, "IDWew")
    if internal is not None:
        return PartyIdentifier(PartyIdentifierKind.INTERNAL, internal)
    raise FA3ParseError(f"{path}: brak identyfikatora podmiotu (NIP/KodUE/NrID/BrakID/IDWew).")


def _parse_contact(node: ET.Element, *, authorized: bool) -> Contact:
    email_tag = "EmailPU" if authorized else "Email"
    phone_tag = "TelefonPU" if authorized else "Telefon"
    return Contact(email=_text(node, email_tag), phone=_text(node, phone_tag))


def _parse_party(node: ET.Element, *, role: str, path: str) -> InvoiceParty:
    identity = _required_child(node, "DaneIdentyfikacyjne", f"{path}/DaneIdentyfikacyjne")
    contacts = tuple(
        _parse_contact(contact, authorized=role == "authorized")
        for contact in _children(node, "DaneKontaktowe")
    )
    party = InvoiceParty(
        name=_text(identity, "Nazwa") or "",
        identifier=_parse_identifier(identity, f"{path}/DaneIdentyfikacyjne"),
        address=_parse_address(_child(node, "Adres"), f"{path}/Adres"),
        taxpayer_prefix=_text(node, "PrefiksPodatnika"),
        taxpayer_status=_text(node, "StatusInfoPodatnika") if role == "seller" else None,
        correspondence_address=_parse_address(
            _child(node, "AdresKoresp"), f"{path}/AdresKoresp"
        ),
        contacts=contacts,
        eori=_text(node, "NrEORI"),
        customer_number=_text(node, "NrKlienta") if role in {"buyer", "third"} else None,
        buyer_id=_text(node, "IDNabywcy") if role in {"buyer", "third"} else None,
        is_jst_subunit=_flag(node, "JST") if role == "buyer" else False,
        is_vat_group_member=_flag(node, "GV") if role == "buyer" else False,
    )
    if role == "third":
        role_value = _text(node, "Rola")
        other_description = _text(node, "OpisRoli")
        if other_description is not None or _flag(node, "RolaInna"):
            if other_description is None:
                # Schemat wymaga `OpisRoli` razem z `RolaInna`; bez tego
                # odczytana faktura nie dałaby się ponownie zserializować.
                raise FA3ParseError(f"{path}: RolaInna wymaga elementu OpisRoli.")
            party = _replace_party(
                party,
                role=ThirdPartyRole.OTHER,
                other_role_description=other_description,
            )
        elif role_value is not None:
            party = _replace_party(party, role=_third_party_role(role_value, path))
        party = _replace_party(
            party,
            share=_decimal_opt(node, "Udzial", path),
        )
    if role == "authorized":
        role_value = _text(node, "RolaPU")
        party = _replace_party(
            party,
            authorized_role=(
                _authorized_role(role_value, path)
                if role_value is not None
                else AuthorizedPartyRole.REPRESENTATIVE
            ),
        )
    return party


def _replace_party(party: InvoiceParty, **changes: Any) -> InvoiceParty:
    return replace(party, **changes)


def _third_party_role(value: str, path: str) -> ThirdPartyRole:
    try:
        return ThirdPartyRole(value)
    except ValueError as exc:
        raise FA3ParseError(f"{path}: nieznana rola podmiotu trzeciego: {value!r}.") from exc


def _authorized_role(value: str, path: str) -> AuthorizedPartyRole:
    try:
        return AuthorizedPartyRole(value)
    except ValueError as exc:
        raise FA3ParseError(f"{path}: nieznana rola podmiotu upoważnionego: {value!r}.") from exc


# --- adnotacje ------------------------------------------------------------


_EXEMPTION_TAGS = {"P_19A": "law", "P_19B": "directive", "P_19C": "other"}

_MARGIN_TAGS = {
    "P_PMarzy_2": "travel",
    "P_PMarzy_3_1": "used_goods",
    "P_PMarzy_3_2": "art",
    "P_PMarzy_3_3": "collectibles",
}

_TRANSPORT_MEANS_KNOWN = frozenset(
    {
        "P_22A",
        "P_NrWierszaNST",
        "P_22BMK",
        "P_22BMD",
        "P_22BK",
        "P_22BNR",
        "P_22BRP",
        "P_22B",
        "P_22B1",
        "P_22B2",
        "P_22B3",
        "P_22B4",
        "P_22BT",
        "P_22C",
        "P_22C1",
        "P_22D",
        "P_22D1",
    }
)


def _parse_new_transport_means(node: ET.Element, path: str) -> NewTransportMeans:
    allowed_date = _date(
        _required_text(node, "P_22A", path),
        f"{path}/P_22A",
    )
    row_number_text = _required_text(node, "P_NrWierszaNST", path)
    try:
        row_number = int(row_number_text)
    except ValueError as exc:
        raise FA3ParseError(f"{path}/P_NrWierszaNST: '{row_number_text}' nie jest liczbą.") from exc
    if _text(node, "P_22C") is not None or _text(node, "P_22C1") is not None:
        kind = "water"
        hours_used = _text(node, "P_22C")
        serial_number = _text(node, "P_22C1")
    elif _text(node, "P_22D") is not None or _text(node, "P_22D1") is not None:
        kind = "air"
        hours_used = _text(node, "P_22D")
        serial_number = _text(node, "P_22D1")
    else:
        kind = "land"
        hours_used = None
        serial_number = _text(node, "P_22B1")
    return NewTransportMeans(
        allowed_date=allowed_date,
        row_number=row_number,
        kind=kind,
        mileage=_text(node, "P_22B"),
        hours_used=hours_used,
        serial_number=serial_number,
        registry_number=_text(node, "P_22BNR"),
        approval_number=_text(node, "P_22B4"),
        make=_text(node, "P_22BMK"),
        model=_text(node, "P_22BMD"),
        color=_text(node, "P_22BK"),
        manufacture_year=_text(node, "P_22BRP"),
        engine_capacity=_text(node, "P_22B2"),
        engine_power=_text(node, "P_22B3"),
        tax_rate=_text(node, "P_22BT"),
    )


def _parse_annotations(node: ET.Element | None, path: str) -> AnnotationSet:
    if node is None:
        return AnnotationSet.default()
    exemption_node = _child(node, "Zwolnienie")
    exemption_basis: str | None = None
    exemption_basis_type = "law"
    if exemption_node is not None and _flag(exemption_node, "P_19"):
        for tag, basis_type in _EXEMPTION_TAGS.items():
            value = _text(exemption_node, tag)
            if value is not None:
                exemption_basis = value
                exemption_basis_type = basis_type
                break
    transport_node = _child(node, "NoweSrodkiTransportu")
    new_transport = False
    new_transport_intra_eu = False
    new_transport_means: tuple[NewTransportMeans, ...] = ()
    if transport_node is not None:
        new_transport = _flag(transport_node, "P_22")
        new_transport_intra_eu = _flag(transport_node, "P_42_5")
        new_transport_means = tuple(
            _parse_new_transport_means(
                means,
                f"{path}/NoweSrodkiTransportu/NowySrodekTransportu[{index}]",
            )
            for index, means in enumerate(
                _children(transport_node, "NowySrodekTransportu"), start=1
            )
        )
    margin_node = _child(node, "PMarzy")
    margin_procedure: str | None = None
    if margin_node is not None and _flag(margin_node, "P_PMarzy"):
        for tag, name in _MARGIN_TAGS.items():
            if _flag(margin_node, tag):
                margin_procedure = name
                break
    return AnnotationSet(
        cash_method=_flag(node, "P_16"),
        self_billing=_flag(node, "P_17"),
        reverse_charge=_flag(node, "P_18"),
        split_payment=_flag(node, "P_18A"),
        simplified_triangular=_flag(node, "P_23"),
        exemption_basis=exemption_basis,
        exemption_basis_type=exemption_basis_type,
        new_transport=new_transport,
        new_transport_intra_eu=new_transport_intra_eu,
        new_transport_means=new_transport_means,
        margin_procedure=margin_procedure,
    )


# --- pozycje --------------------------------------------------------------


def _line_tax(node: ET.Element, annotations: AnnotationSet, path: str) -> TaxCategory:
    xii = _text(node, "P_12_XII")
    if xii is not None:
        return TaxCategory.xii(_decimal(xii, f"{path}/P_12_XII"))
    code = _text(node, "P_12")
    if code is not None:
        try:
            tax = TaxCategory.from_rate_code(code)
        except ValueError as exc:
            raise FA3ParseError(f"{path}/P_12: {exc}") from exc
        if tax.kind is TaxCategoryKind.EXEMPT and annotations.exemption_basis:
            return TaxCategory.exempt(
                annotations.exemption_basis,
                basis_type=annotations.exemption_basis_type,
            )
        return tax
    if annotations.margin_procedure:
        return TaxCategory.margin()
    raise FA3ParseError(f"{path}: brak stawki P_12/P_12_XII.")


def _parse_line(node: ET.Element, index: int, annotations: AnnotationSet, path: str) -> InvoiceLine:
    row_path = f"{path}/FaWiersz[{index}]"
    identifiers = LineIdentifiers(
        unique_id=_text(node, "UU_ID"),
        internal_index=_text(node, "Indeks"),
        gtin=_text(node, "GTIN"),
        pkwiu=_text(node, "PKWiU"),
        cn=_text(node, "CN"),
        pkob=_text(node, "PKOB"),
    )
    has_identifiers = any(
        value is not None
        for value in (
            identifiers.internal_index,
            identifiers.gtin,
            identifiers.pkwiu,
            identifiers.cn,
            identifiers.pkob,
        )
    )
    discount_text = _text(node, "P_10")
    unit_net_price = _decimal_opt(node, "P_9A", row_path)
    return InvoiceLine(
        description=_required_text(node, "P_7", row_path),
        quantity=_decimal(_required_text(node, "P_8B", row_path), f"{row_path}/P_8B"),
        unit_net_price=Decimal("0") if unit_net_price is None else unit_net_price,
        tax=_line_tax(node, annotations, row_path),
        unit=_text(node, "P_8A") or "szt",
        discount=(
            Discount(DiscountKind.AMOUNT, _decimal(discount_text, f"{row_path}/P_10"))
            if discount_text is not None
            else None
        ),
        unique_id=_text(node, "UU_ID"),
        service_date=_date_opt(node, "P_6A", row_path),
        additional_description={},
        identifiers=identifiers if has_identifiers else None,
        unit_gross_price=_decimal_opt(node, "P_9B", row_path),
        net_amount=_decimal_opt(node, "P_11", row_path),
        gross_amount=_decimal_opt(node, "P_11A", row_path),
        vat_amount=_decimal_opt(node, "P_11Vat", row_path),
        excise_amount=_decimal_opt(node, "KwotaAkcyzy", row_path),
        gtu=_text(node, "GTU"),
        procedure=_text(node, "Procedura"),
        currency_rate=_decimal_opt(node, "KursWaluty", row_path),
        annex_15=_flag(node, "P_12_Zal_15"),
        before_correction=_flag(node, "StanPrzed"),
    )


# --- zaliczki -------------------------------------------------------------


def _line_summary_net(lines: tuple[InvoiceLine, ...], kind: FA3InvoiceKind) -> dict[str, Decimal]:
    summary: dict[str, Decimal] = {}
    for line in lines:
        net_tag = line.tax.summary_fields[0]
        amount = line.effective_net_amount
        if kind in _CORRECTION_KINDS and line.before_correction and amount > 0:
            amount = -amount
        summary[net_tag] = summary.get(net_tag, Decimal("0.00")) + amount
    return summary


def _infer_advance_tax(
    fa: ET.Element,
    lines: tuple[InvoiceLine, ...],
    payments: tuple[AdvancePayment, ...],
    annotations: AnnotationSet,
    kind: FA3InvoiceKind,
    path: str,
    warnings: list[FA3ValidationIssue],
) -> TaxCategory:
    """Wnioskuje stawkę zaliczki z różnicy między podsumowaniem a wierszami.

    XML ``ZaliczkaCzesciowa`` nie niesie stawki — trafia ona wyłącznie do
    ``P_13_x``/``P_14_x``. Dla typowego dokumentu (jedna stawka, jeden koszyk)
    różnica jest jednoznaczna; przy kilku koszykach albo fakturze rozliczającej
    (podsumowanie jest skalowane) parser nie zgaduje i używa stawki 23%,
    dodając ostrzeżenie — tak samo robi builder, gdy nie podano stawki.
    """
    default = TaxCategory.standard_23()
    if kind in SETTLEMENT_SCALE_KINDS:
        warnings.append(
            _warning(
                f"{path}: zaliczki na fakturze rozliczającej — stawka VAT zaliczki "
                "nie jest odwracalna z XML; przyjęto 23%."
            )
        )
        return default
    line_net = _line_summary_net(lines, kind)
    deltas: dict[str, Decimal] = {}
    for tag in _ADVANCE_NET_TAGS:
        document_net = _decimal_opt(fa, tag, path)
        if document_net is None:
            continue
        delta = document_net - line_net.get(tag, Decimal("0.00"))
        if abs(delta) > Decimal("0.02"):
            deltas[tag] = delta
    if len(deltas) != 1:
        warnings.append(
            _warning(
                f"{path}: nie można jednoznacznie odtworzyć stawki VAT zaliczki "
                f"(koszyki: {', '.join(sorted(deltas)) or 'brak'}); przyjęto 23%."
            )
        )
        return default
    tag, delta = next(iter(deltas.items()))
    if tag in {"P_13_6_1", "P_13_6_2", "P_13_6_3"}:
        return {
            "P_13_6_1": TaxCategory.zero_domestic,
            "P_13_6_2": TaxCategory.zero_wdt,
            "P_13_6_3": TaxCategory.zero_export,
        }[tag]()
    if tag == "P_13_7":
        return TaxCategory.exempt(annotations.exemption_basis or "zwolnienie")
    if tag == "P_13_8":
        return TaxCategory.outside_country()
    if tag == "P_13_9":
        return TaxCategory.service_article_100()
    if tag == "P_13_10":
        return TaxCategory.reverse_charge()
    if tag == "P_13_11":
        return TaxCategory.margin()
    total_gross = sum((payment.amount for payment in payments), Decimal("0.00"))
    if total_gross <= 0:
        warnings.append(
            _warning(f"{path}: zaliczka o nie dodatniej kwocie — nie da się wnioskować stawki.")
        )
        return default
    candidates = _ADVANCE_RATE_CANDIDATES[tag]
    matches = [
        rate
        for rate in candidates
        if abs(total_gross / (Decimal("1") + rate / Decimal("100")) - delta) <= Decimal("0.05")
    ]
    if len(matches) == 1:
        return TaxCategory.from_vat_rate(matches[0])
    warnings.append(
        _warning(
            f"{path}: stawka VAT zaliczki nie wynika jednoznacznie z podsumowania "
            f"(koszyk {tag}); przyjęto 23%."
        )
    )
    return default


def _restore_margin_amounts(
    fa: ET.Element,
    lines: tuple[InvoiceLine, ...],
    annotations: AnnotationSet,
    path: str,
    warnings: list[FA3ValidationIssue],
    *,
    advance_payments: tuple[AdvancePayment, ...] = (),
) -> tuple[InvoiceLine, ...]:
    """Przywraca kwotę wiersza marży z podsumowania ``P_13_11``.

    Wiersz procedury marży nie niesie ``P_11`` (podstawą jest marża, nie obrót),
    więc bez tego kroku odczytana faktura miałaby zerowe wartości pozycji i zerowe
    ``P_15``. Kwotę da się przypisać tylko wtedy, gdy wiersz marży jest jeden —
    przy kilku wierszach XML nie mówi, jak podzielić ``P_13_11``, więc parser
    zostawia zera i dodaje ostrzeżenie zamiast zgadywać.

    Gdy na fakturze są zaliczki z koszyka marży, ich kwota jest już częścią
    ``P_13_11`` — przypisanie całości do wiersza podwajałoby podstawę, więc
    w takim przypadku wiersze zostają bez zmian.
    """
    if not annotations.margin_procedure:
        return lines
    if any(payment.tax.kind is TaxCategoryKind.MARGIN for payment in advance_payments):
        return lines
    margin_indexes = [
        index for index, line in enumerate(lines) if line.tax.kind is TaxCategoryKind.MARGIN
    ]
    if not margin_indexes:
        return lines
    total = _decimal_opt(fa, "P_13_11", path)
    if total is None:
        return lines
    if len(margin_indexes) > 1:
        warnings.append(
            _warning(
                f"{path}: {len(margin_indexes)} wierszy procedury marży — kwoty P_13_11 "
                "nie da się przypisać do poszczególnych pozycji."
            )
        )
        return lines
    index = margin_indexes[0]
    updated = list(lines)
    updated[index] = replace(updated[index], net_amount=total)
    return tuple(updated)


def _parse_advance_payments(
    fa: ET.Element,
    lines: tuple[InvoiceLine, ...],
    annotations: AnnotationSet,
    kind: FA3InvoiceKind,
    path: str,
    warnings: list[FA3ValidationIssue],
) -> tuple[AdvancePayment, ...]:
    nodes = _children(fa, "ZaliczkaCzesciowa")
    if not nodes:
        return ()
    payments: list[AdvancePayment] = []
    for index, node in enumerate(nodes, start=1):
        payment_path = f"{path}/ZaliczkaCzesciowa[{index}]"
        amount = _decimal(
            _required_text(node, "P_15Z", payment_path),
            f"{payment_path}/P_15Z",
        )
        payments.append(
            AdvancePayment(
                amount=amount,
                tax=TaxCategory.standard_23(),
                paid_on=_date_opt(node, "P_6Z", payment_path),
                currency_rate=_decimal_opt(node, "KursWalutyZW", payment_path),
            )
        )
    tax = _infer_advance_tax(
        fa,
        lines,
        tuple(payments),
        annotations,
        kind,
        path,
        warnings,
    )
    return tuple(replace(payment, tax=tax) for payment in payments)


# --- korekta --------------------------------------------------------------


def _parse_correction(
    fa: ET.Element,
    path: str,
) -> dict[str, Any]:
    corrected_invoices: list[CorrectionReference] = []
    for index, node in enumerate(_children(fa, "DaneFaKorygowanej"), start=1):
        node_path = f"{path}/DaneFaKorygowanej[{index}]"
        corrected_invoices.append(
            CorrectionReference(
                invoice_number=_required_text(node, "NrFaKorygowanej", node_path),
                issue_date=_date(
                    _required_text(node, "DataWystFaKorygowanej", node_path),
                    f"{node_path}/DataWystFaKorygowanej",
                ),
                ksef_number=(
                    _text(node, "NrKSeFFaKorygowanej") if _flag(node, "NrKSeF") else None
                ),
            )
        )
    corrected_seller_node = _child(fa, "Podmiot1K")
    corrected_buyers = tuple(
        _parse_party(node, role="buyer", path=f"{path}/Podmiot2K[{index}]")
        for index, node in enumerate(_children(fa, "Podmiot2K"), start=1)
    )
    advance_state_node = _child(fa, "P_15ZK")
    corrected_advance_state = None
    if advance_state_node is not None:
        corrected_advance_state = CorrectedAdvanceState(
            amount=_decimal(advance_state_node.text or "", f"{path}/P_15ZK"),
            currency_rate=_decimal_opt(fa, "KursWalutyZK", path),
        )
    return {
        "correction_reason": _text(fa, "PrzyczynaKorekty"),
        "correction_type": _text(fa, "TypKorekty"),
        "corrected_period": _text(fa, "OkresFaKorygowanej"),
        "corrected_invoice_number_override": _text(fa, "NrFaKorygowany"),
        "corrected_invoices": tuple(corrected_invoices),
        "corrected_seller": (
            _parse_party(corrected_seller_node, role="seller", path=f"{path}/Podmiot1K")
            if corrected_seller_node is not None
            else None
        ),
        "corrected_buyers": corrected_buyers,
        "corrected_advance_state": corrected_advance_state,
    }


# --- rozliczenie, płatność, warunki, zamówienie ---------------------------


def _parse_settlement(node: ET.Element | None, path: str) -> Settlement | None:
    if node is None:
        return None
    charges = tuple(
        SettlementAdjustment(
            amount=_decimal(
                _required_text(charge, "Kwota", f"{path}/Obciazenia[{index}]"),
                f"{path}/Obciazenia[{index}]/Kwota",
            ),
            reason=_required_text(charge, "Powod", f"{path}/Obciazenia[{index}]"),
        )
        for index, charge in enumerate(_children(node, "Obciazenia"), start=1)
    )
    deductions = tuple(
        SettlementAdjustment(
            amount=_decimal(
                _required_text(deduction, "Kwota", f"{path}/Odliczenia[{index}]"),
                f"{path}/Odliczenia[{index}]/Kwota",
            ),
            reason=_required_text(deduction, "Powod", f"{path}/Odliczenia[{index}]"),
        )
        for index, deduction in enumerate(_children(node, "Odliczenia"), start=1)
    )
    return Settlement(
        charges=charges,
        deductions=deductions,
        amount_due=_decimal_opt(node, "DoZaplaty", path),
        amount_to_settle=_decimal_opt(node, "DoRozliczenia", path),
    )


def _parse_bank_account(node: ET.Element) -> BankAccount:
    return BankAccount(
        number=_text(node, "NrRB") or "",
        swift=_text(node, "SWIFT"),
        own_bank_account=_text(node, "RachunekWlasnyBanku"),
        bank_name=_text(node, "NazwaBanku"),
        description=_text(node, "OpisRachunku"),
    )


def _parse_partial_payment(node: ET.Element, path: str) -> PartialPayment:
    return PartialPayment(
        amount=_decimal(
            _required_text(node, "KwotaZaplatyCzesciowej", path),
            f"{path}/KwotaZaplatyCzesciowej",
        ),
        payment_date=_date(
            _required_text(node, "DataZaplatyCzesciowej", path),
            f"{path}/DataZaplatyCzesciowej",
        ),
        method=_text(node, "FormaPlatnosci"),
        other_method_description=_text(node, "OpisPlatnosci"),
    )


def _parse_due_term(node: ET.Element, path: str) -> PaymentDue:
    description_node = _child(node, "TerminOpis")
    description = None
    if description_node is not None:
        amount_text = _required_text(description_node, "Ilosc", f"{path}/TerminOpis")
        try:
            amount = int(amount_text)
        except ValueError as exc:
            raise FA3ParseError(
                f"{path}/TerminOpis/Ilosc: '{amount_text}' nie jest liczbą."
            ) from exc
        description = PaymentDueDescription(
            amount=amount,
            unit=_required_text(description_node, "Jednostka", f"{path}/TerminOpis"),
            starts_from=_required_text(
                description_node, "ZdarzeniePoczatkowe", f"{path}/TerminOpis"
            ),
        )
    return PaymentDue(
        due_date=_date_opt(node, "Termin", path),
        term_description=description,
    )


def _parse_payment(node: ET.Element | None, path: str) -> PaymentTerms | None:
    if node is None:
        return None
    partial_payments = tuple(
        _parse_partial_payment(partial, f"{path}/ZaplataCzesciowa[{index}]")
        for index, partial in enumerate(_children(node, "ZaplataCzesciowa"), start=1)
    )
    discount_node = _child(node, "Skonto")
    return PaymentTerms(
        due_terms=tuple(
            _parse_due_term(term, f"{path}/TerminPlatnosci[{index}]")
            for index, term in enumerate(_children(node, "TerminPlatnosci"), start=1)
        ),
        method=_text(node, "FormaPlatnosci"),
        other_method_description=_text(node, "OpisPlatnosci"),
        paid_date=_date_opt(node, "DataZaplaty", path) if _flag(node, "Zaplacono") else None,
        partial_payments=partial_payments,
        bank_accounts=tuple(
            _parse_bank_account(account) for account in _children(node, "RachunekBankowy")
        ),
        factor_accounts=tuple(
            _parse_bank_account(account)
            for account in _children(node, "RachunekBankowyFaktora")
        ),
        cash_discount_terms=_text(discount_node, "WarunkiSkonta")
        if discount_node is not None
        else None,
        cash_discount_amount=_text(discount_node, "WysokoscSkonta")
        if discount_node is not None
        else None,
        payment_link=_text(node, "LinkDoPlatnosci"),
        ipksef=_text(node, "IPKSeF"),
    )


def _parse_transport(node: ET.Element, path: str) -> Transport:
    carrier_node = _child(node, "Przewoznik")
    carrier = None
    if carrier_node is not None:
        carrier = _parse_party(carrier_node, role="carrier", path=f"{path}/Przewoznik")
        carrier = _replace_party(
            carrier,
            address=_parse_address(
                _child(carrier_node, "AdresPrzewoznika"),
                f"{path}/Przewoznik/AdresPrzewoznika",
            ),
        )
    return Transport(
        kind=_text(node, "RodzajTransportu"),
        other_kind_description=_text(node, "OpisInnegoTransportu"),
        carrier=carrier,
        order_number=_text(node, "NrZleceniaTransportu"),
        cargo_description=_text(node, "OpisLadunku") or "1",
        other_cargo_description=_text(node, "OpisInnegoLadunku"),
        package_unit=_text(node, "JednostkaOpakowania"),
        started_at=_datetime_opt(node, "DataGodzRozpTransportu", path),
        finished_at=_datetime_opt(node, "DataGodzZakTransportu", path),
        ship_from=_parse_address(_child(node, "WysylkaZ"), f"{path}/WysylkaZ"),
        ship_via=_parse_address_list(_children(node, "WysylkaPrzez"), f"{path}/WysylkaPrzez"),
        ship_to=_parse_address(_child(node, "WysylkaDo"), f"{path}/WysylkaDo"),
    )


def _parse_contract(node: ET.Element, *, date_tag: str, number_tag: str) -> Contract:
    return Contract(
        number=_text(node, number_tag),
        date=_date_opt(node, date_tag, _local(node)),
    )


def _parse_transaction_terms(node: ET.Element | None, path: str) -> TransactionTerms | None:
    if node is None:
        return None
    return TransactionTerms(
        contracts=tuple(
            _parse_contract(contract, date_tag="DataUmowy", number_tag="NrUmowy")
            for contract in _children(node, "Umowy")
        ),
        orders=tuple(
            _parse_contract(order, date_tag="DataZamowienia", number_tag="NrZamowienia")
            for order in _children(node, "Zamowienia")
        ),
        batch_numbers=tuple(
            value
            for element in _children(node, "NrPartiiTowaru")
            if (value := (element.text or "").strip())
        ),
        delivery_terms=_text(node, "WarunkiDostawy"),
        contractual_rate=_decimal_opt(node, "KursUmowny", path),
        contractual_currency=_text(node, "WalutaUmowna"),
        transports=tuple(
            _parse_transport(transport, f"{path}/Transport[{index}]")
            for index, transport in enumerate(_children(node, "Transport"), start=1)
        ),
        intermediary=_flag(node, "PodmiotPosredniczacy"),
    )


def _order_line_tax(node: ET.Element, path: str) -> TaxCategory:
    xii = _text(node, "P_12Z_XII")
    if xii is not None:
        return TaxCategory.xii(_decimal(xii, f"{path}/P_12Z_XII"))
    code = _text(node, "P_12Z")
    if code is None:
        return TaxCategory.standard_23()
    try:
        return TaxCategory.from_rate_code(code)
    except ValueError as exc:
        raise FA3ParseError(f"{path}/P_12Z: {exc}") from exc


def _parse_order_line(node: ET.Element, index: int, path: str) -> OrderLine:
    row_path = f"{path}/ZamowienieWiersz[{index}]"
    identifiers = LineIdentifiers(
        unique_id=_text(node, "UU_IDZ"),
        internal_index=_text(node, "IndeksZ"),
        gtin=_text(node, "GTINZ"),
        pkwiu=_text(node, "PKWiUZ"),
        cn=_text(node, "CNZ"),
        pkob=_text(node, "PKOBZ"),
    )
    has_identifiers = any(
        value is not None
        for value in (
            identifiers.unique_id,
            identifiers.internal_index,
            identifiers.gtin,
            identifiers.pkwiu,
            identifiers.cn,
            identifiers.pkob,
        )
    )
    return OrderLine(
        description=_required_text(node, "P_7Z", row_path),
        quantity=_decimal(_required_text(node, "P_8BZ", row_path), f"{row_path}/P_8BZ"),
        unit_net_price=_decimal(
            _required_text(node, "P_9AZ", row_path), f"{row_path}/P_9AZ"
        ),
        tax=_order_line_tax(node, row_path),
        unit=_text(node, "P_8AZ") or "szt",
        gtu=_text(node, "GTUZ"),
        procedure=_text(node, "ProceduraZ"),
        identifiers=identifiers if has_identifiers else None,
        excise_amount=_decimal_opt(node, "KwotaAkcyzyZ", row_path),
        annex_15=_flag(node, "P_12Z_Zal_15"),
        before_correction=_flag(node, "StanPrzedZ"),
    )


def _parse_order(node: ET.Element | None, path: str) -> Order | None:
    if node is None:
        return None
    return Order(
        total_gross=_decimal(
            _required_text(node, "WartoscZamowienia", path),
            f"{path}/WartoscZamowienia",
        ),
        lines=tuple(
            _parse_order_line(line, index, path)
            for index, line in enumerate(_children(node, "ZamowienieWiersz"), start=1)
        ),
    )


# --- załącznik i stopka ---------------------------------------------------


def _parse_attachment_table(node: ET.Element, path: str) -> AttachmentTable:
    header = _required_child(node, "TNaglowek", path)
    headers: list[str] = []
    column_types: list[str] = []
    for column in _children(header, "Kol"):
        headers.append(_text(column, "NKom") or "")
        column_types.append(_attr(column, "Typ") or "txt")
    footer_node = _child(node, "Suma")
    footer = (
        tuple((cell.text or "").strip() for cell in _children(footer_node, "SKom"))
        if footer_node is not None
        else ()
    )
    return AttachmentTable(
        headers=tuple(headers),
        rows=tuple(
            tuple((cell.text or "").strip() for cell in _children(row, "WKom"))
            for row in _children(node, "Wiersz")
        ),
        column_types=tuple(column_types),
        metadata=tuple(
            (
                _text(meta, "TKlucz") or "",
                _text(meta, "TWartosc") or "",
            )
            for meta in _children(node, "TMetaDane")
        ),
        description=_text(node, "Opis"),
        footer=footer,
    )


def _parse_attachment_block(node: ET.Element, path: str) -> AttachmentBlock:
    text_node = _child(node, "Tekst")
    return AttachmentBlock(
        header=_text(node, "ZNaglowek"),
        metadata=tuple(
            (
                _text(meta, "ZKlucz") or "",
                _text(meta, "ZWartosc") or "",
            )
            for meta in _children(node, "MetaDane")
        ),
        paragraphs=tuple(
            paragraph.text.strip()
            for paragraph in _children(text_node, "Akapit")
            if paragraph.text and paragraph.text.strip()
        )
        if text_node is not None
        else (),
        tables=tuple(
            _parse_attachment_table(table, f"{path}/Tabela[{index}]")
            for index, table in enumerate(_children(node, "Tabela"), start=1)
        ),
    )


def _parse_attachment(node: ET.Element | None, path: str) -> Attachment | None:
    if node is None:
        return None
    return Attachment(
        blocks=tuple(
            _parse_attachment_block(block, f"{path}/BlokDanych[{index}]")
            for index, block in enumerate(_children(node, "BlokDanych"), start=1)
        )
    )


def _parse_footer(node: ET.Element | None, path: str) -> Footer | None:
    if node is None:
        return None
    return Footer(
        infos=tuple(
            _text(info, "StopkaFaktury") or ""
            for info in _children(node, "Informacje")
        ),
        registries=tuple(
            Registry(
                full_name=_text(registry, "PelnaNazwa"),
                krs=_text(registry, "KRS"),
                regon=_text(registry, "REGON"),
                bdo=_text(registry, "BDO"),
            )
            for registry in _children(node, "Rejestry")
        ),
    )


# --- główny przepływ ------------------------------------------------------


_HEADER_KNOWN = frozenset({"KodFormularza", "WariantFormularza", "DataWytworzeniaFa", "SystemInfo"})

_PARTY_KNOWN = {
    "seller": frozenset(
        {
            "PrefiksPodatnika",
            "NrEORI",
            "DaneIdentyfikacyjne",
            "Adres",
            "AdresKoresp",
            "DaneKontaktowe",
            "StatusInfoPodatnika",
        }
    ),
    "buyer": frozenset(
        {
            "NrEORI",
            "DaneIdentyfikacyjne",
            "Adres",
            "AdresKoresp",
            "DaneKontaktowe",
            "NrKlienta",
            "IDNabywcy",
            "JST",
            "GV",
        }
    ),
    "third": frozenset(
        {
            "IDNabywcy",
            "NrEORI",
            "DaneIdentyfikacyjne",
            "Adres",
            "AdresKoresp",
            "DaneKontaktowe",
            "Rola",
            "RolaInna",
            "OpisRoli",
            "Udzial",
            "NrKlienta",
        }
    ),
    "authorized": frozenset(
        {
            "NrEORI",
            "DaneIdentyfikacyjne",
            "Adres",
            "AdresKoresp",
            "DaneKontaktowe",
            "RolaPU",
        }
    ),
    "carrier": frozenset({"DaneIdentyfikacyjne"}),
}

_ANNOTATIONS_KNOWN = frozenset(
    {"P_16", "P_17", "P_18", "P_18A", "Zwolnienie", "NoweSrodkiTransportu", "P_23", "PMarzy"}
)

_LINE_KNOWN = frozenset(
    {
        "NrWierszaFa",
        "UU_ID",
        "P_6A",
        "P_7",
        "Indeks",
        "GTIN",
        "PKWiU",
        "CN",
        "PKOB",
        "P_8A",
        "P_8B",
        "P_9A",
        "P_9B",
        "P_10",
        "P_11",
        "P_11A",
        "P_11Vat",
        "P_12",
        "P_12_XII",
        "P_12_Zal_15",
        "KwotaAkcyzy",
        "GTU",
        "Procedura",
        "KursWaluty",
        "StanPrzed",
    }
)

_FA_KNOWN = (
    frozenset(
        {
            "KodWaluty",
            "P_1",
            "P_1M",
            "P_2",
            "WZ",
            "P_6",
            "OkresFa",
            "KursWalutyZ",
            "Adnotacje",
            "RodzajFaktury",
            "PrzyczynaKorekty",
            "TypKorekty",
            "DaneFaKorygowanej",
            "OkresFaKorygowanej",
            "NrFaKorygowany",
            "Podmiot1K",
            "Podmiot2K",
            "P_15ZK",
            "KursWalutyZK",
            "ZaliczkaCzesciowa",
            "FP",
            "TP",
            "DodatkowyOpis",
            "FakturaZaliczkowa",
            "ZwrotAkcyzy",
            "FaWiersz",
            "Rozliczenie",
            "Platnosc",
            "WarunkiTransakcji",
            "Zamowienie",
        }
    )
    | _TAX_SUMMARY_TAGS
)

_ROOT_KNOWN = frozenset(
    {
        "Naglowek",
        "Podmiot1",
        "Podmiot2",
        "Podmiot3",
        "PodmiotUpowazniony",
        "Fa",
        "Stopka",
        "Zalacznik",
    }
)


def _parse_root(root: ET.Element) -> FA3Invoice:
    if root.tag != _tag("Faktura"):
        raise FA3ParseError(
            f"Oczekiwano elementu głównego 'Faktura' w przestrzeni {FA3_NAMESPACE}, "
            f"otrzymano {root.tag!r}."
        )
    warnings: list[FA3ValidationIssue] = []
    _warn_unknown(root, _ROOT_KNOWN, "Faktura", warnings)

    header = _child(root, "Naglowek")
    if header is not None:
        _warn_unknown(header, _HEADER_KNOWN, "Faktura/Naglowek", warnings)
        form_code = _child(header, "KodFormularza")
        if form_code is not None:
            if (form_code.text or "").strip() != "FA":
                raise FA3ParseError(
                    "Faktura/Naglowek/KodFormularza: oczekiwano 'FA', "
                    f"otrzymano {(form_code.text or '').strip()!r}."
                )
            schema_version = _attr(form_code, "wersjaSchemy")
            if schema_version is not None and schema_version != "1-0E":
                warnings.append(
                    _warning(
                        "Faktura/Naglowek/KodFormularza: wersja schematu "
                        f"{schema_version!r} — parser obsługuje '1-0E'."
                    )
                )
    else:
        warnings.append(_warning("Faktura: brak elementu 'Naglowek'."))

    seller_node = _required_child(root, "Podmiot1", "Faktura")
    buyer_node = _required_child(root, "Podmiot2", "Faktura")
    _warn_unknown(seller_node, _PARTY_KNOWN["seller"], "Faktura/Podmiot1", warnings)
    _warn_unknown(buyer_node, _PARTY_KNOWN["buyer"], "Faktura/Podmiot2", warnings)
    seller = _parse_party(seller_node, role="seller", path="Faktura/Podmiot1")
    buyer = _parse_party(buyer_node, role="buyer", path="Faktura/Podmiot2")
    additional_parties: list[InvoiceParty] = []
    for index, node in enumerate(_children(root, "Podmiot3"), start=1):
        path = f"Faktura/Podmiot3[{index}]"
        _warn_unknown(node, _PARTY_KNOWN["third"], path, warnings)
        additional_parties.append(_parse_party(node, role="third", path=path))
    authorized_node = _child(root, "PodmiotUpowazniony")
    authorized_party = None
    if authorized_node is not None:
        _warn_unknown(
            authorized_node,
            _PARTY_KNOWN["authorized"],
            "Faktura/PodmiotUpowazniony",
            warnings,
        )
        authorized_party = _parse_party(
            authorized_node, role="authorized", path="Faktura/PodmiotUpowazniony"
        )

    fa = _required_child(root, "Fa", "Faktura")
    _warn_unknown(fa, _FA_KNOWN, "Faktura/Fa", warnings)
    invoice_number = _required_text(fa, "P_2", "Faktura/Fa")
    issue_date = _date(_required_text(fa, "P_1", "Faktura/Fa"), "Faktura/Fa/P_1")
    currency = _required_text(fa, "KodWaluty", "Faktura/Fa")
    try:
        kind = FA3InvoiceKind.parse(_required_text(fa, "RodzajFaktury", "Faktura/Fa"))
    except ValueError as exc:
        raise FA3ParseError(f"Faktura/Fa/RodzajFaktury: {exc}") from exc

    annotations_node = _child(fa, "Adnotacje")
    if annotations_node is not None:
        _warn_unknown(annotations_node, _ANNOTATIONS_KNOWN, "Faktura/Fa/Adnotacje", warnings)
    annotations = _parse_annotations(annotations_node, "Faktura/Fa/Adnotacje")

    lines: list[InvoiceLine] = []
    for index, node in enumerate(_children(fa, "FaWiersz"), start=1):
        path = f"Faktura/Fa/FaWiersz[{index}]"
        _warn_unknown(node, _LINE_KNOWN, path, warnings)
        lines.append(_parse_line(node, index, annotations, "Faktura/Fa"))
    invoice_lines = tuple(lines)

    period_node = _child(fa, "OkresFa")
    advance_payments = _parse_advance_payments(
        fa, invoice_lines, annotations, kind, "Faktura/Fa", warnings
    )
    invoice_lines = _restore_margin_amounts(
        fa,
        invoice_lines,
        annotations,
        "Faktura/Fa",
        warnings,
        advance_payments=advance_payments,
    )
    additional_descriptions = tuple(
        AdditionalDescription(
            key=_required_text(node, "Klucz", "Faktura/Fa/DodatkowyOpis"),
            value=_required_text(node, "Wartosc", "Faktura/Fa/DodatkowyOpis"),
            row_number=_int_opt(node, "NrWiersza", "Faktura/Fa/DodatkowyOpis"),
        )
        for node in _children(fa, "DodatkowyOpis")
    )
    advance_invoices = tuple(
        AdvanceInvoiceReference(
            invoice_number=_text(node, "NrFaZaliczkowej"),
            ksef_number=_text(node, "NrKSeFFaZaliczkowej"),
        )
        for node in _children(fa, "FakturaZaliczkowa")
    )
    footer = _parse_footer(_child(root, "Stopka"), "Faktura/Stopka")
    attachment = _parse_attachment(_child(root, "Zalacznik"), "Faktura/Zalacznik")

    invoice = FA3Invoice(
        invoice_number=invoice_number,
        issue_date=issue_date,
        seller=seller,
        buyer=buyer,
        lines=invoice_lines,
        kind=kind,
        currency=currency,
        issue_place=_text(fa, "P_1M"),
        sale_date=_date_opt(fa, "P_6", "Faktura/Fa"),
        period_from=_date_opt(period_node, "P_6_Od", "Faktura/Fa/OkresFa")
        if period_node is not None
        else None,
        period_to=_date_opt(period_node, "P_6_Do", "Faktura/Fa/OkresFa")
        if period_node is not None
        else None,
        additional_parties=tuple(additional_parties),
        authorized_party=authorized_party,
        annotations=annotations,
        payment_terms=_parse_payment(_child(fa, "Platnosc"), "Faktura/Fa/Platnosc"),
        settlement_data=_parse_settlement(
            _child(fa, "Rozliczenie"), "Faktura/Fa/Rozliczenie"
        ),
        advance_payments=advance_payments,
        advance_invoices=advance_invoices,
        order=_parse_order(_child(fa, "Zamowienie"), "Faktura/Fa/Zamowienie"),
        transaction_terms=_parse_transaction_terms(
            _child(fa, "WarunkiTransakcji"), "Faktura/Fa/WarunkiTransakcji"
        ),
        warehouse_documents=tuple(
            value
            for element in _children(fa, "WZ")
            if (value := (element.text or "").strip())
        ),
        additional_descriptions=additional_descriptions,
        foreign_currency_rate=_decimal_opt(fa, "KursWalutyZ", "Faktura/Fa"),
        fp=_flag(fa, "FP"),
        tp=_flag(fa, "TP"),
        excise_refund=ExciseRefund(enabled=True) if _flag(fa, "ZwrotAkcyzy") else None,
        footer=footer,
        attachment=attachment,
        warnings=tuple(warnings),
        **_parse_correction(fa, "Faktura/Fa"),
    )
    return invoice


def _int_opt(node: ET.Element, name: str, path: str) -> int | None:
    value = _text(node, name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise FA3ParseError(f"{path}/{name}: '{value}' nie jest liczbą.") from exc


def _reject_dtd(data: bytes) -> None:
    """Blokuje DTD niezależnie od kodowania dokumentu.

    Wcześniejsza wersja szukała ``<!DOCTYPE``/``<!ENTITY`` w bajtach, więc
    dokument zakodowany w UTF-16 (albo innym kodowaniu ze znakami NUL) omijał
    kontrolę, a ``ElementTree`` rozwijał encje — czyli działał atak typu
    „billion laughs" i podmiana treści przez encję. Tutaj dokument parsuje
    ``expat``, który sam rozpoznaje kodowanie, a każda deklaracja DTD kończy
    pracę wyjątkiem **przed** rozwinięciem encji.

    Args:
        data: Bajty dokumentu.

    Raises:
        FA3ParseError: Gdy dokument deklaruje DTD albo nie jest poprawnym XML-em.
    """

    parser = _expat.ParserCreate()

    def _forbid(*_args: object) -> None:
        raise FA3ParseError(_DTD_ERROR)

    parser.StartDoctypeDeclHandler = _forbid
    parser.EntityDeclHandler = _forbid
    try:
        parser.Parse(data, True)
    except _expat.ExpatError as exc:
        raise FA3ParseError(f"Nieprawidłowy XML: {exc}") from exc


def parse_invoice_xml(xml: bytes | bytearray | str) -> FA3Invoice:
    """Parsuje dokument FA(3) i zwraca model domenowy.

    Args:
        xml: Treść dokumentu FA(3) (bajty albo tekst).

    Returns:
        Faktura z wypełnionymi polami modelu. Elementy, których SDK nie
        obsługuje, są wymienione w ``warnings`` (``severity='warning'``), a nie
        pomijane po cichu.

    Raises:
        FA3ParseError: Gdy XML jest niepoprawny, ma zły element główny,
            zawiera deklarację ``DOCTYPE``/``ENTITY`` (w dowolnym kodowaniu),
            przekracza limit rozmiaru albo brakuje w nim wymaganego pola.
    """
    data = _as_bytes(xml)
    if len(data) > MAX_XML_BYTES:
        raise FA3ParseError(
            f"XML ma {len(data)} bajtów, limit to {MAX_XML_BYTES}."
        )
    _reject_dtd(data)
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise FA3ParseError(f"Nieprawidłowy XML: {exc}") from exc
    return _parse_root(root)


__all__ = ["FA3ParseError", "MAX_XML_BYTES", "parse_invoice_xml"]
