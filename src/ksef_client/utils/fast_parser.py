"""High-performance streaming metadata parser for KSeF XML invoices using ElementTree.iterparse.

Features:
- Stream-based XML parsing via ElementTree.iterparse (event-driven pull-parser)
- Ignores CDATA sections, comments, PIs, and element attributes
- Handles both `P_11` (net) and `P_11A` (gross, art. 106e ust. 7 and 8) line values
- Skips rows marked `StanPrzed` (state before a correction), so a KOR/KOR_ROZ
  document is not counted twice
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


def fast_extract_ksef_metadata(xml_content: str | bytes | io.BufferedIOBase) -> dict[str, Any]:
    """Stream-extract NIP list, seller/buyer NIP, totals, and line item count from KSeF XML.

    :param xml_content: KSeF XML invoice content (str, bytes, or BufferedIOBase stream)
    :return: Dictionary containing 'seller_nip', 'buyer_nip', 'nips', 'total_netto',
        'total_brutto', 'item_count' and 'stan_przed_item_count'.

    ``total_netto`` sumuje wartości ``P_11`` (netto), a ``total_brutto`` wartości
    ``P_11A`` (brutto) — dokumenty z art. 106e ust. 7 i 8 nie mają ``P_11``, więc
    wcześniejsza wersja zwracała dla nich ``total_netto = 0.00`` i ``item_count = 0``
    bez żadnego sygnału. Wiersze oznaczone ``StanPrzed`` (stan przed korektą) są
    liczone osobno w ``stan_przed_item_count`` i nie wchodzą do sum — inaczej
    korekta (KOR/KOR_ROZ) podwajała wartości.
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
    row_net: Decimal | None = None
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
                row_net = None
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
        elif tag_name == "StanPrzed" and text == "1":
            # `StanPrzed` występuje w wierszu PO `P_11`/`P_11A`, dlatego decyzję
            # podejmujemy dopiero na końcu wiersza.
            row_before_correction = True
        elif tag_name in _ROW_TAGS:
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
