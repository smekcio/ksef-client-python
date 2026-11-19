from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO

import pytest
from pypdf import PdfReader

from ksef_client import invoice_pdf
from ksef_client.documents.fa3.xml import FA3_NAMESPACE


def invoice(*, description: str = "Montaż żaluzji", repetitions: int = 1) -> bytes:
    line = (
        "<FaWiersz><NrWierszaFa>1</NrWierszaFa><P_7>"
        + description
        + "</P_7><P_8B>2</P_8B><P_11>278.00</P_11><P_12>23</P_12></FaWiersz>"
    )
    return (
        f'<Faktura xmlns="{FA3_NAMESPACE}">'
        '<Naglowek><KodFormularza kodSystemowy="FA (3)">FA</KodFormularza></Naglowek>'
        "<Podmiot1><DaneIdentyfikacyjne><Nazwa>Żółć i Łęgi Sp. z o.o.</Nazwa>"
        "</DaneIdentyfikacyjne></Podmiot1><Fa><KodWaluty>PLN</KodWaluty>"
        "<P_1>2026-11-19</P_1><P_2>FV/2026/11</P_2><P_15>341.94</P_15>"
        + line
        * repetitions
        + "<Platnosc><RachunekBankowy><NrRB>PL1234</NrRB></RachunekBankowy></Platnosc>"
        "</Fa></Faktura>"
    ).encode()


def pdf_text(data: bytes) -> str:
    return "\n".join(page.extract_text() for page in PdfReader(BytesIO(data)).pages)


def test_readable_invoice_keeps_original_values_and_literal_text():
    data = invoice(description="Montaż &amp; transport &lt;usługa&gt; \U0001f680")
    rendered = invoice_pdf.render_invoice_pdf(data, ksef_number="numer-ksef-z-metadanych")
    text = pdf_text(rendered)
    for item in (
        "Żółć i Łęgi",
        "FV/2026/11",
        "341.94",
        "numer-ksef-z-metadanych",
        "Montaż & transport <usługa>",
        "[U+1F680]",
        "PL1234",
        "kodSystemowy",
        "FA (3)",
    ):
        assert item in text
    assert "/Annots" not in PdfReader(BytesIO(rendered)).pages[0]


def test_long_text_and_multiple_pages():
    value = "początek " + "długi opis " * 150 + "koniec"
    out = invoice_pdf.render_invoice_pdf(invoice(description=value, repetitions=9))
    pages = PdfReader(BytesIO(out)).pages
    assert len(pages) > 1
    all_text = "\n".join(page.extract_text() for page in pages)
    assert "Numer KSeF" not in all_text
    assert all_text.count("koniec") == 9
    assert f"Strona {len(pages)}" in pages[-1].extract_text()


def test_concurrent_invoices_remain_independent():
    with ThreadPoolExecutor(2) as pool:
        results = list(
            pool.map(
                invoice_pdf.render_invoice_pdf,
                (
                    invoice(description="Pierwsza partia"),
                    invoice(description="Druga partia"),
                ),
            )
        )
    assert "Druga partia" not in pdf_text(results[0])
    assert "Pierwsza partia" not in pdf_text(results[1])


@pytest.mark.parametrize(
    "xml", [b"<", b"<Faktura/>", f'<Faktura xmlns="{FA3_NAMESPACE}"/>'.encode()]
)
def test_unusable_input_has_a_safe_error(xml):
    with pytest.raises(ValueError, match="Invoice PDF|Invalid invoice XML"):
        invoice_pdf.render_invoice_pdf(xml)


@pytest.mark.parametrize("limit", ["MAX_XML_BYTES", "_MAX_NODES", "_MAX_PAGES", "_MAX_FIELD"])
def test_limits_stop_rendering(monkeypatch, limit):
    monkeypatch.setattr(invoice_pdf, limit, 1)
    with pytest.raises(ValueError, match="limit"):
        invoice_pdf.render_invoice_pdf(invoice(repetitions=25))


def test_optional_dependency_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "reportlab.pdfgen.canvas", None)
    with pytest.raises(ImportError, match=r"ksef-client\[pdf\]"):
        invoice_pdf.render_invoice_pdf(invoice())
