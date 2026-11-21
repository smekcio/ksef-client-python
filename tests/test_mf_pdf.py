import hashlib
import shutil
import subprocess
from io import BytesIO
from pathlib import Path

import pytest
from pypdf import PdfReader

from ksef_client import mf_pdf
from ksef_client.config import KsefClientOptions, KsefEnvironment
from ksef_client.exceptions import KsefDocumentValidationError, KsefRenderingError
from ksef_client.invoice_pdf import InvoicePdfContext, render_invoice_pdf, render_upo_pdf

FIXTURES = Path(__file__).parent / "fixtures/pdf"


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for MF integration")
@pytest.mark.parametrize(
    "name",
    [
        "invoice.xml",
        "upo-faktura-42.xml",
        "upo-sesja-42.xml",
        "upo-faktura-43.xml",
        "upo-sesja-43.xml",
    ],
)
def test_real_upstream_rendering(name):
    xml = (FIXTURES / name).read_bytes()
    render = (
        (lambda data: render_invoice_pdf(data, renderer="mf"))
        if name == "invoice.xml"
        else render_upo_pdf
    )
    pdf = render(xml)
    text = "\n".join(page.extract_text() for page in PdfReader(BytesIO(pdf)).pages)
    assert "Krajowy System" in text
    assert ("YUCFO" if name == "invoice.xml" else "36950822") in text
    if name.endswith("43.xml"):
        assert "Online" in text
    metadata = PdfReader(BytesIO(pdf)).metadata
    assert metadata is not None
    assert str(metadata["/Producer"].get_object()).strip() == "ksef-pdf-generator/1.1.48"
    assert render(xml.decode("utf-8-sig").replace("utf-8", "utf-16").encode("utf-16")).startswith(
        b"%PDF-"
    )


@pytest.mark.parametrize("xml", [b"<!DOCTYPE x><x/>", b"<x/>", b"bad"])
def test_invalid_xml_never_starts_node(xml, monkeypatch):
    monkeypatch.setattr(mf_pdf.subprocess, "Popen", lambda *a, **k: pytest.fail("started Node"))
    with pytest.raises(KsefDocumentValidationError):
        render_upo_pdf(xml)


def test_missing_node(monkeypatch):
    monkeypatch.setattr(mf_pdf.shutil, "which", lambda _: None)
    with pytest.raises(KsefRenderingError, match="Node.js"):
        render_upo_pdf((FIXTURES / "upo-faktura-43.xml").read_bytes())


def test_qr_uses_original_bytes_and_environment(monkeypatch):
    from tests.test_offline_invoice_state import NUMBER

    xml = (FIXTURES / "invoice.xml").read_bytes()
    options = KsefClientOptions(base_url=KsefEnvironment.TEST.value)
    captured = {}

    def capture(data, kind, additional):
        assert data == xml
        captured.update(additional)
        return b"%PDF-test"

    monkeypatch.setattr(mf_pdf, "_render", capture)
    render_invoice_pdf(xml, renderer="mf", context=InvoicePdfContext.accepted(options, NUMBER))
    import base64

    digest = base64.urlsafe_b64encode(hashlib.sha256(xml).digest()).decode().rstrip("=")
    assert captured["qrCode"].startswith("https://qr-test.ksef.mf.gov.pl/invoice/")
    assert captured["qrCode"].endswith("/" + digest)
    assert captured["nrKSeF"] == NUMBER


def test_process_output_limit(monkeypatch):
    if not shutil.which("node"):
        pytest.skip("Node.js required")
    monkeypatch.setattr(mf_pdf, "MAX_PDF_BYTES", 1)
    with pytest.raises(KsefRenderingError, match="output size"):
        render_upo_pdf((FIXTURES / "upo-faktura-43.xml").read_bytes())


def test_release_watcher_simulation():
    if not shutil.which("node"):
        pytest.skip("Node.js required")
    subprocess.run(["node", str(Path(__file__).parent / "pdf_release_watch.cjs")], check=True)


def test_offline_pdf_qr_scan_and_signature(tmp_path):
    fitz = pytest.importorskip("pymupdf")
    zxing = pytest.importorskip("zxingcpp")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from PIL import Image

    from ksef_client.utils.base64url import b64url_decode
    from tests.test_offline_verification import signer

    pair = signer()
    xml = (FIXTURES / "invoice.xml").read_bytes()
    context = InvoicePdfContext.offline(
        KsefClientOptions(base_url=KsefEnvironment.TEST.value), "Nip", "5265877635", pair
    )
    pdf = render_invoice_pdf(xml, renderer="mf", context=context)
    doc = fitz.open(stream=pdf, filetype="pdf")
    decoded: set[str] = set()
    for page in doc:
        pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
        image = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        decoded.update(code.text for code in zxing.read_barcodes(image))
    assert len(decoded) == 2
    certificate_url = next(url for url in decoded if "/certificate/" in url)
    path, signature = certificate_url.rsplit("/", 1)
    raw = b64url_decode(signature)
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    public = x509.load_pem_x509_certificate(pair.certificate_pem.encode()).public_key()
    assert isinstance(public, ec.EllipticCurvePublicKey)
    public.verify(der, path.removeprefix("https://").encode(), ec.ECDSA(hashes.SHA256()))
    assert "OFFLINE" in "".join(page.get_text() for page in doc)
    assert "CERTYFIKAT" in "".join(page.get_text() for page in doc)


@pytest.mark.parametrize(
    "kind,xml",
    [
        ("upo", b""),
        ("upo", b"<!DOCTYPE x><x/>"),
        ("upo", b'<Potwierdzenie xmlns="http://upo.schematy.mf.gov.pl/KSeF/v4-3"/>'),
        ("invoice", b"<x/>"),
        ("invoice", (FIXTURES / "invoice.xml").read_bytes().replace(b"FA (3)", b"FA (2)")),
        (
            "invoice",
            (FIXTURES / "invoice.xml").read_bytes().replace(b"<P_2>", b"<P_2>" + b"a" * 65537),
        ),
        ("invoice", (FIXTURES / "invoice.xml").read_bytes().replace(b"<Fa>", b"<Fa>mixed")),
        ("upo", b"<x>" * 65 + b"</x>" * 65),
    ],
    ids=["empty", "dtd", "empty-upo", "root", "version", "field", "mixed", "depth"],
)
def test_rendering_input_budgets(kind, xml):
    with pytest.raises(KsefDocumentValidationError):
        mf_pdf._read(xml, kind)


def test_checksum_start_timeout_and_bad_output(monkeypatch):
    xml = (FIXTURES / "upo-faktura-43.xml").read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(mf_pdf, "generator_info", lambda: {"sha256": "bad"})
        with pytest.raises(KsefRenderingError, match="checksum"):
            render_upo_pdf(xml)
    with monkeypatch.context() as patch:

        def denied(*a, **kw):
            raise OSError("denied")

        patch.setattr(mf_pdf.subprocess, "Popen", denied)
        with pytest.raises(KsefRenderingError, match="start"):
            render_upo_pdf(xml)
    with monkeypatch.context() as patch:
        patch.setattr(mf_pdf, "RENDER_TIMEOUT", 0)
        with pytest.raises(KsefRenderingError, match="timed out"):
            render_upo_pdf(xml)
    with monkeypatch.context() as patch:
        original = subprocess.Popen
        patch.setattr(
            mf_pdf.subprocess,
            "Popen",
            lambda *a, **kw: original(
                [shutil.which("node") or "node", "-e", "process.stdout.write('invalid')"], **kw
            ),
        )
        with pytest.raises(KsefRenderingError, match="generation failed"):
            render_upo_pdf(xml)


def test_conflicting_verification_contexts(monkeypatch):
    from dataclasses import replace

    from tests.test_offline_invoice_state import NUMBER

    options = KsefClientOptions(base_url=KsefEnvironment.TEST.value)
    xml = (FIXTURES / "invoice.xml").read_bytes()
    context = InvoicePdfContext.accepted(options, NUMBER)
    with pytest.raises(KsefDocumentValidationError):
        render_invoice_pdf(
            xml.replace(b"<NIP>", b"<Other>").replace(b"</NIP>", b"</Other>"),
            renderer="mf",
            context=context,
        )
    with pytest.raises(KsefDocumentValidationError):
        render_invoice_pdf(
            xml, renderer="mf", ksef_number=NUMBER, context=replace(context, mode="offline")
        )
    with pytest.raises(KsefDocumentValidationError):
        render_invoice_pdf(xml, renderer="mf", context=replace(context, mode="unknown"))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        render_invoice_pdf(xml, context=context)
    # A second valid invoice identity must not override the accepted context.
    from ksef_client.utils.ksef_number import _crc8

    prefix = NUMBER[:20] + ("A" if NUMBER[20] != "A" else "B") + NUMBER[21:32]
    other = prefix + "-" + f"{_crc8(prefix.encode()):02X}"
    with pytest.raises(KsefDocumentValidationError, match="Conflicting"):
        render_invoice_pdf(xml, renderer="mf", context=context, ksef_number=other)


def test_broken_input_pipe_is_reported_as_rendering_failure(monkeypatch):
    class BrokenInput(BytesIO):
        def write(self, data):
            raise BrokenPipeError()

    class StoppedProcess:
        stdin = BrokenInput()
        stdout = BytesIO()

        def wait(self, **kw):
            return 1

    monkeypatch.setattr(mf_pdf.subprocess, "Popen", lambda *a, **kw: StoppedProcess())
    with pytest.raises(KsefRenderingError, match="generation failed"):
        render_upo_pdf((FIXTURES / "upo-faktura-43.xml").read_bytes())


@pytest.mark.parametrize("variant", ["correction", "attachment"])
def test_extended_invoice_sections(variant):
    xml = (FIXTURES / "invoice.xml").read_bytes()
    if variant == "correction":
        xml = xml.replace(
            b"<RodzajFaktury>VAT</RodzajFaktury>", b"<RodzajFaktury>KOR</RodzajFaktury>"
        )
        xml = xml.replace(b"</Fa>", b"<PrzyczynaKorekty>PRICE CHANGE</PrzyczynaKorekty></Fa>")
        expected = "PRICE CHANGE"
    else:
        xml = xml.replace(
            b"</Faktura>",
            b"<Zalacznik><BlokDanych><ZNaglowek>ATTACHMENT TEST</ZNaglowek>"
            b"<Tekst><Akapit>Additional data</Akapit></Tekst></BlokDanych></Zalacznik></Faktura>",
        )
        expected = "ATTACHMENT TEST"
    pdf = render_invoice_pdf(xml, renderer="mf")
    text = "".join(page.extract_text() for page in PdfReader(BytesIO(pdf)).pages)
    assert expected in text


def test_collective_upo_keeps_ten_thousand_documents():
    from xml.etree import ElementTree as ET

    fitz = pytest.importorskip("pymupdf")
    root = ET.fromstring((FIXTURES / "upo-sesja-43.xml").read_bytes())
    ns = "{http://upo.schematy.mf.gov.pl/KSeF/v4-3}"
    document = root.find(ns + "Dokument")
    assert document is not None
    for item in root.findall(ns + "Dokument"):
        root.remove(item)
    for _ in range(10000):
        root.append(document)
    pdf = render_upo_pdf(ET.tostring(root, encoding="utf-8", xml_declaration=True))
    result = fitz.open(stream=pdf, filetype="pdf")
    assert sum(page.get_text().count("Online") for page in result) == 10000


def test_accepted_pdf_has_one_scannable_qr():
    fitz = pytest.importorskip("pymupdf")
    zxing = pytest.importorskip("zxingcpp")
    from PIL import Image

    from tests.test_offline_invoice_state import NUMBER

    xml = (FIXTURES / "invoice.xml").read_bytes()
    pdf = render_invoice_pdf(
        xml,
        renderer="mf",
        context=InvoicePdfContext.accepted(
            KsefClientOptions(base_url=KsefEnvironment.TEST.value), NUMBER
        ),
    )
    decoded: set[str] = set()
    document = fitz.open(stream=pdf, filetype="pdf")
    for page in document:
        pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))
        bitmap = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
        decoded.update(code.text for code in zxing.read_barcodes(bitmap))
    assert len(decoded) == 1
    assert next(iter(decoded)).startswith("https://qr-test.ksef.mf.gov.pl/invoice/")
    assert NUMBER in "".join(page.get_text() for page in document)
