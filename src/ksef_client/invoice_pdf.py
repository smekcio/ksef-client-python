"""Local, human-readable FA(3) invoice visualization."""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from importlib.metadata import distribution
from io import BytesIO
from itertools import zip_longest
from threading import Lock
from typing import TYPE_CHECKING
from xml.etree import ElementTree as ET

from .documents.fa3.parse import MAX_XML_BYTES
from .documents.fa3.xml import FA3_NAMESPACE

if TYPE_CHECKING:
    from reportlab.pdfgen.canvas import Canvas

_NS = "{" + FA3_NAMESPACE + "}"
_MAX_NODES = 100_000
_MAX_PAGES = 500
_MAX_FIELD = 65_536
_MARGIN = 44
_LEFT = 44
_RIGHT = 551
_BODY = "KSeF-Roboto"
_BOLD = "KSeF-Roboto-Bold"
_FONT_LOCK = Lock()
_LABELS = {
    "Naglowek": "Nagłówek",
    "KodFormularza": "Formularz",
    "WariantFormularza": "Wariant",
    "Podmiot1": "Sprzedawca",
    "Podmiot2": "Nabywca",
    "Podmiot3": "Podmiot trzeci",
    "PodmiotUpowazniony": "Podmiot upoważniony",
    "DaneIdentyfikacyjne": "Dane identyfikacyjne",
    "AdresL1": "Adres",
    "AdresL2": "Dalsza część adresu",
    "KodKraju": "Kraj",
    "Fa": "Dane faktury",
    "RodzajFaktury": "Rodzaj faktury",
    "KodWaluty": "Waluta",
    "P_1": "Data wystawienia",
    "P_2": "Numer faktury",
    "P_6": "Data sprzedaży",
    "P_15": "Kwota należności ogółem",
    "FaWiersz": "Pozycja faktury",
    "NrWierszaFa": "Numer wiersza",
    "P_7": "Towar lub usługa",
    "P_8A": "Jednostka miary",
    "P_8B": "Ilość",
    "P_9A": "Cena jednostkowa netto",
    "P_9B": "Cena jednostkowa brutto",
    "P_10": "Opust lub obniżka",
    "P_11": "Wartość netto",
    "P_11A": "Wartość brutto",
    "P_12": "Stawka VAT",
    "Adnotacje": "Adnotacje",
    "Platnosc": "Płatność",
    "P_13_1": "Suma netto (stawka podstawowa)",
    "P_14_1": "VAT (stawka podstawowa)",
    "P_13_2": "Suma netto (stawka obniżona 1)",
    "P_14_2": "VAT (stawka obniżona 1)",
    "P_13_3": "Suma netto (stawka obniżona 2)",
    "P_14_3": "VAT (stawka obniżona 2)",
    "TerminPlatnosci": "Termin płatności",
    "RachunekBankowy": "Rachunek bankowy",
    "NrRB": "Numer rachunku",
    "Zalacznik": "Załącznik",
    "Zamowienie": "Zamówienie",
}


class _InvoiceTree(ET.TreeBuilder):
    """Apply the document budget before adding each element to the PDF's XML tree."""

    def __init__(self) -> None:
        super().__init__()
        self.count = 0
        self.depth = 0

    def start(self, tag: str, attrs: dict[str, str]) -> ET.Element:
        self.count += 1 + len(attrs)
        self.depth += 1
        if self.depth > 64 or self.count > _MAX_NODES:
            raise ValueError("Invoice XML exceeds the PDF structure limit.")
        return super().start(tag, attrs)

    def end(self, tag: str) -> ET.Element:
        self.depth -= 1
        return super().end(tag)

    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise ValueError("Invoice PDF does not accept a document type declaration.")


def _read_invoice(xml: bytes) -> ET.Element:
    if not isinstance(xml, bytes) or len(xml) > MAX_XML_BYTES:
        raise ValueError("Invoice PDF requires FA(3) XML bytes within the SDK size limit.")
    try:
        root = ET.fromstring(xml, parser=ET.XMLParser(target=_InvoiceTree()))
    except (ET.ParseError, LookupError):
        raise ValueError("Invalid invoice XML for PDF.") from None
    if root.tag != _NS + "Faktura" or len(root.findall(_NS + "Fa")) != 1:
        raise ValueError("Invoice PDF requires an FA(3) Faktura document.")
    if any(
        (len(node) and (node.text or "").strip()) or (node.tail or "").strip()
        for node in root.iter()
    ):
        raise ValueError("Invoice PDF cannot represent mixed XML content.")
    return root


@lru_cache(maxsize=1)
def _register_fonts() -> frozenset[int]:
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    fonts = distribution("font-roboto")
    supported: set[int] = set()
    for name, style in ((_BODY, "Regular"), (_BOLD, "Bold")):
        asset = fonts.locate_file(f"font_roboto/files/Roboto-{style}.ttf")
        font = TTFont(name, str(asset))
        pdfmetrics.registerFont(font)
        if not supported:
            supported.update(font.face.charWidths)
        else:
            supported.intersection_update(font.face.charWidths)
    return frozenset(supported)


def _label(tag: str) -> str:
    if tag.startswith(_NS):
        name = tag.removeprefix(_NS)
        return _LABELS.get(name, name)
    return tag


def _summary_value(root: ET.Element, path: str) -> str | None:
    matches = root.findall("/".join(_NS + name for name in path.split("/")))
    if len(matches) > 1:
        raise ValueError("Invoice contains duplicate PDF summary fields.")
    return matches[0].text if matches else None


class _InvoicePage:
    def __init__(self, canvas: Canvas, supported: frozenset[int]) -> None:
        self.canvas = canvas
        self.supported = supported
        self.y = 0
        self.new_page()

    def new_page(self) -> None:
        page = self.canvas.getPageNumber()
        if page > _MAX_PAGES:
            raise ValueError("Invoice exceeds the PDF page limit.")
        self.canvas.setFillColor("#17566B")
        self.canvas.setFont(_BOLD, 12)
        self.canvas.drawString(_LEFT, 798, "Faktura   /   FA(3)")
        self.canvas.setStrokeColor("#B8CACF")
        self.canvas.line(_LEFT, 787, _RIGHT, 787)
        self.canvas.setFillColor("#435A61")
        self.canvas.setFont(_BODY, 9)
        self.canvas.drawRightString(_RIGHT, 27, f"Strona {page}")
        self.y = 760

    def room(self, height: int) -> None:
        if self.y - height < _MARGIN:
            self.canvas.showPage()
            self.new_page()

    def lines(self, text: str, width: float, font: str, size: int) -> Iterator[str]:
        from reportlab.lib.textsplit import wordSplit

        if len(text) > _MAX_FIELD:
            raise ValueError("Invoice field exceeds the PDF rendering limit.")
        for line in text.splitlines() or [""]:
            # A missing glyph is printed as its Unicode code point, never as a blank box.
            visible = "".join(
                ch if ch.isprintable() and ord(ch) in self.supported else f"[U+{ord(ch):04X}]"
                for ch in line
            )
            for _, part in wordSplit(visible or " ", width, font, size):
                yield part

    def heading(self, label: str, indent: int = 0, size: int = 12) -> None:
        self.room(40)
        self.y -= 5
        for line in self.lines(label, _RIGHT - _LEFT - indent, _BOLD, size):
            self.room(size + 6)
            self.canvas.setFillColor("#17566B")
            self.canvas.setFont(_BOLD, size)
            self.canvas.drawString(_LEFT + indent, self.y, line)
            self.y -= size + 5

    def field(self, label: str, value: str, indent: int = 0) -> None:
        split = 235
        labels = self.lines(label, split - _LEFT - indent - 12, _BODY, 9)
        values = self.lines(value, _RIGHT - split, _BODY, 10)
        for left, right in zip_longest(labels, values, fillvalue=""):
            self.room(15)
            self.canvas.setFillColor("#435A61")
            self.canvas.setFont(_BODY, 9)
            self.canvas.drawString(_LEFT + indent, self.y, left)
            self.canvas.setFillColor("#172C32")
            self.canvas.setFont(_BODY, 10)
            self.canvas.drawString(split, self.y, right)
            self.y -= 15

    def element(self, node: ET.Element, depth: int) -> None:
        indent = min(depth, 4) * 8
        label = _label(node.tag)
        if len(node):
            self.heading(label, indent)
        else:
            self.field(label, node.text or "", indent)
        for key, value in node.attrib.items():
            self.field(_label(key), value, indent + 8)
        for child in node:
            self.element(child, depth + 1)


def render_invoice_pdf(xml: bytes, *, ksef_number: str | None = None) -> bytes:
    """Render the original FA(3) document locally, with an optional assigned KSeF number."""
    with _FONT_LOCK:  # ReportLab shares its TrueType font registry across canvases.
        root = _read_invoice(xml)
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.pdfgen.canvas import Canvas

            supported = _register_fonts()
        except ImportError as exc:
            raise ImportError("Install ksef-client[pdf] to render invoice PDFs.") from exc
        buffer = BytesIO()
        canvas = Canvas(buffer, pagesize=A4, invariant=True, pageCompression=1)
        canvas.setTitle("Wizualizacja faktury FA(3)")
        page = _InvoicePage(canvas, supported)
        number = _summary_value(root, "Fa/P_2")
        page.heading(number or "Faktura", size=20)
        for label, path in (
            ("Data wystawienia", "Fa/P_1"),
            ("Sprzedawca", "Podmiot1/DaneIdentyfikacyjne/Nazwa"),
            ("Nabywca", "Podmiot2/DaneIdentyfikacyjne/Nazwa"),
            ("Kwota należności ogółem", "Fa/P_15"),
            ("Waluta", "Fa/KodWaluty"),
        ):
            value = _summary_value(root, path)
            if value:
                page.field(label, value)
        if ksef_number:
            page.field("Numer KSeF", ksef_number)
        for node in root:
            page.element(node, 0)
        canvas.save()
        return buffer.getvalue()
