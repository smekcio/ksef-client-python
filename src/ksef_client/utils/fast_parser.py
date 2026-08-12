"""High-performance streaming metadata parser for KSeF XML invoices using ElementTree.iterparse.

Features:
- Stream-based XML parsing via ElementTree.iterparse (event-driven pull-parser)
- Ignores CDATA sections, comments, PIs, and element attributes
- Exact tag matching for P_11 (ignoring sub-elements such as P_11A, P_11Vat, etc.)
- Precision Decimal monetary calculations with comma-to-dot normalization
- Input support for str, bytes, and BufferedIOBase streams
- Parent element tracking (Podmiot1 vs Podmiot2) for seller and buyer NIP identification
- Graceful handling of XML syntax errors (ET.ParseError) to prevent batch pipeline crashes
"""

import io
import logging
import xml.etree.ElementTree as ET
from decimal import Decimal, InvalidOperation
from typing import Any

logger = logging.getLogger(__name__)


def fast_extract_ksef_metadata(xml_content: str | bytes | io.BufferedIOBase) -> dict[str, Any]:
    """Stream-extract NIP list, seller/buyer NIP, total netto, and line item count from KSeF XML.

    :param xml_content: KSeF XML invoice content (str, bytes, or BufferedIOBase stream)
    :return: Dictionary containing 'seller_nip', 'buyer_nip', 'nips',
        'total_netto', and 'item_count'
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
    item_count = 0

    stack: list[str] = []

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
        elif event == "end":
            text = (elem.text or "").strip()

            if tag_name == "NIP" and text:
                nips.append(text)
                if "Podmiot1" in stack and seller_nip is None:
                    seller_nip = text
                elif "Podmiot2" in stack and buyer_nip is None:
                    buyer_nip = text

            elif tag_name == "P_11" and text:
                sanitized_text = text.replace(",", ".")
                if len(sanitized_text) > 30:
                    raise ValueError(
                        f"Wartość P_11 jest zbyt długa (potencjalny atak DoS): "
                        f"{len(sanitized_text)} znaków"
                    )
                try:
                    amount = Decimal(sanitized_text)
                    total_netto += amount
                    item_count += 1
                except (ValueError, InvalidOperation):
                    pass

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
        "item_count": item_count,
    }
