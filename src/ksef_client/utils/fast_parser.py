"""High-performance streaming metadata parser for KSeF XML invoices using ElementTree.iterparse.

Features:
- Stream-based XML parsing via ElementTree.iterparse (event-driven pull-parser)
- Ignores CDATA sections, comments, PIs, and element attributes
- Handles `FaWiersz` rows (`P_11` net, `P_11A` gross — art. 106e ust. 7 and 8)
  **and** `ZamowienieWiersz` rows (`P_11NettoZ` net plus `P_11VatZ` tax as gross),
  so an order/settlement document is not reported as an empty one
- Skips rows marked `StanPrzed`/`StanPrzedZ` (state before a correction), so a
  KOR/KOR_ROZ document is not counted twice
- Precision Decimal monetary calculations with comma-to-dot normalization
- Input support for str, bytes, and BufferedIOBase streams
- Parent element tracking (Podmiot1 vs Podmiot2) for seller and buyer NIP identification

`ET.ParseError` is deliberately **propagated** to the caller (the parser does not
swallow malformed XML).
"""

import io
import logging
import xml.etree.ElementTree as ET
from decimal import Decimal, InvalidOperation
from typing import Any

logger = logging.getLogger(__name__)

#: Znaczniki, które kończą bieżący wiersz faktury.
_ROW_TAGS = frozenset({"FaWiersz", "ZamowienieWiersz"})


def _parse_amount(text: str) -> Decimal | None:
    sanitized_text = text.replace(",", ".")
    if len(sanitized_text) > 30:
        raise ValueError(
            f"Wartość kwotowa jest zbyt długa (potencjalny atak DoS): "
            f"{len(sanitized_text)} znaków"
        )
    try:
        return Decimal(sanitized_text)
    except (ValueError, InvalidOperation):
        return None


def _sum_optional(left: Decimal | None, right: Decimal | None) -> Decimal | None:
    """Suma dwóch opcjonalnych kwot (None, gdy obie są nieobecne)."""
    if left is None and right is None:
        return None
    return (left or Decimal("0.00")) + (right or Decimal("0.00"))


def fast_extract_ksef_metadata(xml_content: str | bytes | io.BufferedIOBase) -> dict[str, Any]:
    """Stream-extract NIP list, seller/buyer NIP, totals, and line item count from KSeF XML.

    :param xml_content: KSeF XML invoice content (str, bytes, or BufferedIOBase stream)
    :return: Dictionary containing 'seller_nip', 'buyer_nip', 'nips', 'total_netto',
        'total_brutto', 'item_count' and 'stan_przed_item_count'.

    ``total_netto`` sumuje wartości ``P_11``/``P_11NettoZ`` (netto), a ``total_brutto``
    wartości ``P_11A`` (brutto) albo — dla wiersza zamówienia — ``P_11NettoZ + P_11VatZ``.
    Dokumenty z art. 106e ust. 7 i 8 nie mają ``P_11``, więc wcześniejsza wersja
    zwracała dla nich ``total_netto = 0.00`` i ``item_count = 0`` bez żadnego sygnału;
    tak samo działo się z każdym dokumentem, którego pozycje to ``ZamowienieWiersz``.
    Wiersze oznaczone ``StanPrzed``/``StanPrzedZ`` (stan przed korektą) są liczone
    osobno w ``stan_przed_item_count`` i nie wchodzą do sum — inaczej korekta
    (KOR/KOR_ROZ) podwajała wartości.
    """
    source: Any
    if isinstance(xml_content, str):
        source = io.StringIO(xml_content)
    elif isinstance(xml_content, bytes):
        source = io.BytesIO(xml_content)
    else:
        source = xml_content

    seller_nip: str | None = None
    buyer_nip: str | None = None
    nips: list[str] = []
    total_netto = Decimal("0.00")
    total_brutto = Decimal("0.00")
    item_count = 0
    stan_przed_item_count = 0

    stack: list[str] = []
    row_tag: str | None = None
    row_net: Decimal | None = None
    row_vat: Decimal | None = None
    row_gross: Decimal | None = None
    row_before_correction = False

    context = ET.iterparse(source, events=("start", "end"))
    context_iter = iter(context)

    try:
        _, root = next(context_iter)
    except StopIteration:
        root = None  # pragma: no cover

    for event, elem in context_iter:
        tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

        if event == "start":
            stack.append(tag_name)
            if tag_name in _ROW_TAGS:
                row_tag = tag_name
                row_net = None
                row_vat = None
                row_gross = None
                row_before_correction = False
            continue

        text = (elem.text or "").strip()

        if tag_name == "NIP" and text:
            nips.append(text)
            if "Podmiot1" in stack and seller_nip is None:
                seller_nip = text
            elif "Podmiot2" in stack and buyer_nip is None:
                buyer_nip = text
        elif tag_name == "P_11" and text:
            row_net = _parse_amount(text)
        elif tag_name == "P_11A" and text:
            row_gross = _parse_amount(text)
        elif tag_name == "P_11NettoZ" and text:
            # `ZamowienieWiersz` (zamówienie/rozliczenie) nie ma `P_11`/`P_11A` —
            # wartości siedzą w `P_11NettoZ` (netto) i `P_11VatZ` (podatek).
            row_net = _parse_amount(text)
        elif tag_name == "P_11VatZ" and text:
            row_vat = _parse_amount(text)
        elif tag_name in ("StanPrzed", "StanPrzedZ") and text == "1":
            # Znaczniki występują w wierszu PO kwotach, dlatego decyzję
            # podejmujemy dopiero na końcu wiersza.
            row_before_correction = True
        elif tag_name in _ROW_TAGS:
            # `ZamowienieWiersz` nie ma jawnej kwoty brutto (`P_11A`), więc brutto
            # to netto + podatek. Dla `FaWiersz` brutto bierzemy wyłącznie z
            # `P_11A` — bez tego „brutto" byłoby równe netto i myliłoby odbiorcę.
            if row_gross is None and row_tag == "ZamowienieWiersz":
                row_gross = _sum_optional(row_net, row_vat)
            has_values = row_net is not None or row_gross is not None
            if has_values:
                item_count += 1
                if row_before_correction:
                    stan_przed_item_count += 1
                else:
                    total_netto += row_net or Decimal("0.00")
                    total_brutto += row_gross or Decimal("0.00")

        if stack and stack[-1] == tag_name:
            stack.pop()

        elem.clear()
        if root is not None and elem is not root:
            root.clear()

    return {
        "seller_nip": seller_nip,
        "buyer_nip": buyer_nip,
        "nips": nips,
        "total_netto": total_netto,
        "total_brutto": total_brutto,
        "item_count": item_count,
        "stan_przed_item_count": stan_przed_item_count,
    }
