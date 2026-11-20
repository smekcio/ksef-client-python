"""Local rendering with the pinned CIRFMF invoice and UPO generator."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import threading
from contextlib import suppress
from dataclasses import dataclass, field
from importlib.resources import as_file, files
from typing import Literal
from xml.etree import ElementTree as ET

from ._offline_invoice_state import OfflineInvoiceProgress, offline_invoice_hash
from ._offline_verification import build_offline_verification_links
from .config import KsefClientOptions
from .documents.fa3.xml import FA3_NAMESPACE
from .exceptions import KsefDocumentValidationError, KsefRenderingError
from .services.verification_link import VerificationLinkService
from .services.xades import XadesKeyPair
from .utils.ksef_number import canonical_ksef_number

MAX_UPO_BYTES = 32 * 1024 * 1024
MAX_PDF_BYTES = 64 * 1024 * 1024
RENDER_TIMEOUT = 120
_ASSETS = "ksef_client._mf_pdf"


@dataclass(frozen=True)
class InvoicePdfContext:
    """Verification settings. Private key material is only consumed in Python."""

    options: KsefClientOptions = field(repr=False)
    mode: Literal["accepted", "offline"]
    ksef_number: str | None = field(default=None, repr=False)
    context_type: str | None = field(default=None, repr=False)
    context_value: str | None = field(default=None, repr=False)
    signer: XadesKeyPair | None = field(default=None, repr=False)

    @classmethod
    def accepted(cls, options: KsefClientOptions, ksef_number: str) -> InvoicePdfContext:
        return cls(options, "accepted", canonical_ksef_number(ksef_number))

    @classmethod
    def offline(
        cls,
        options: KsefClientOptions,
        context_type: str,
        context_value: str,
        signer: XadesKeyPair,
    ) -> InvoicePdfContext:
        return cls(
            options,
            "offline",
            context_type=context_type,
            context_value=context_value,
            signer=signer,
        )


class _Tree(ET.TreeBuilder):
    def __init__(self, max_nodes: int) -> None:
        super().__init__()
        self.nodes = 0
        self.depth = 0
        self.max_nodes = max_nodes

    def start(self, tag: str, attrs: dict[str, str]) -> ET.Element:
        self.nodes += 1 + len(attrs)
        self.depth += 1
        if self.nodes > self.max_nodes or self.depth > 64:
            raise ValueError("XML exceeds the rendering structure limit")
        return super().start(tag, attrs)

    def end(self, tag: str) -> ET.Element:
        self.depth -= 1
        return super().end(tag)

    def doctype(self, name: str, pubid: str | None, system: str | None) -> None:
        raise ValueError("DTD is unsupported")


def _read(xml: bytes, kind: str) -> ET.Element:
    limit = 20 * 1024 * 1024 if kind == "invoice" else MAX_UPO_BYTES
    if type(xml) is not bytes or not 0 < len(xml) <= limit:
        raise KsefDocumentValidationError("XML exceeds the rendering size limit")
    try:
        root = ET.fromstring(
            xml, ET.XMLParser(target=_Tree(100_000 if kind == "invoice" else 300_000))
        )
        if any(
            len(node.text or "") > 65_536
            or len(node.tail or "") > 65_536
            or any(len(value) > 65_536 for value in node.attrib.values())
            for node in root.iter()
        ):
            raise ValueError("XML field exceeds the rendering limit")
        if kind == "invoice":
            ns = "{" + FA3_NAMESPACE + "}"
            if root.tag != ns + "Faktura" or len(root.findall(ns + "Fa")) != 1:
                raise ValueError("Expected FA(3) invoice")
            code = root.find(ns + "Naglowek/" + ns + "KodFormularza")
            if code is None or code.get("kodSystemowy") != "FA (3)":
                raise ValueError("Expected FA(3) form code")
        else:
            if root.tag not in {
                f"{{http://upo.schematy.mf.gov.pl/KSeF/v4-{v}}}Potwierdzenie" for v in (2, 3)
            }:
                raise ValueError("Expected UPO 4.2 or 4.3")
            ns = root.tag.split("}")[0] + "}"
            if not 1 <= len(root.findall(ns + "Dokument")) <= 10_000:
                raise ValueError("Expected 1 to 10000 UPO documents")
        if any(
            (len(node) and (node.text or "").strip()) or (node.tail or "").strip()
            for node in root.iter()
        ):
            raise ValueError("Mixed XML content is unsupported")
        return root
    except (ET.ParseError, ValueError, LookupError) as exc:
        raise KsefDocumentValidationError("Invalid XML for MF rendering") from exc


def generator_info() -> dict:
    """Return the provenance of the generator shipped in this distribution."""
    return json.loads(files(_ASSETS).joinpath("upstream.json").read_text(encoding="utf-8"))


def _render(xml: bytes, kind: str, additional: dict) -> bytes:
    node = shutil.which("node")
    if node is None:
        raise KsefRenderingError("Install Node.js 22 or newer to render MF PDFs")
    assets = files(_ASSETS)
    if (
        hashlib.sha256(assets.joinpath("generator.mjs").read_bytes()).hexdigest()
        != generator_info()["sha256"]
    ):
        raise KsefRenderingError("MF generator checksum mismatch")
    payload = json.dumps({"kind": kind, "additionalData": additional}).encode() + b"\n" + xml
    # Concurrent pipe draining bounds output and avoids deadlocks on full pipes.
    output = bytearray()
    exceeded = threading.Event()
    with as_file(assets.joinpath("bridge.mjs")) as bridge:
        try:
            process = subprocess.Popen(
                [node, "--max-old-space-size=512", str(bridge)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={
                    key: value
                    for key, value in os.environ.items()
                    if key.upper()
                    in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL", "TZ"}
                },
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError:
            raise KsefRenderingError("Could not start Node.js for MF rendering") from None

        def write() -> None:
            assert process.stdin is not None
            try:
                process.stdin.write(payload)
            except (BrokenPipeError, OSError):
                pass
            finally:
                with suppress(OSError):
                    process.stdin.close()

        def read() -> None:
            assert process.stdout is not None
            with process.stdout:
                while chunk := process.stdout.read(65536):
                    if len(output) + len(chunk) > MAX_PDF_BYTES:
                        exceeded.set()
                        process.kill()
                        return
                    output.extend(chunk)

        writer = threading.Thread(target=write, daemon=True)
        reader = threading.Thread(target=read, daemon=True)
        writer.start()
        reader.start()
        try:
            code = process.wait(timeout=RENDER_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise KsefRenderingError("MF PDF rendering timed out") from None
        finally:
            writer.join()
            reader.join()
    if exceeded.is_set():
        raise KsefRenderingError("MF PDF exceeds the output size limit")
    if code or not output.startswith(b"%PDF-"):
        raise KsefRenderingError("MF PDF generation failed")
    return bytes(output)


def render_mf_invoice(xml: bytes, number: str | None, context: InvoicePdfContext | None) -> bytes:
    root = _read(xml, "invoice")
    additional = {"nrKSeF": number or ""}
    if context is not None:
        digest = offline_invoice_hash(xml)
        if context.mode == "accepted":
            assigned = canonical_ksef_number(context.ksef_number or "")
            if number is not None and canonical_ksef_number(number) != assigned:
                raise KsefDocumentValidationError("Conflicting PDF KSeF numbers")
            ns = "{" + FA3_NAMESPACE + "}"
            nip = root.findtext(ns + "Podmiot1/" + ns + "DaneIdentyfikacyjne/" + ns + "NIP")
            date = root.findtext(ns + "Fa/" + ns + "P_1")
            if not nip or not date:
                raise KsefDocumentValidationError("Invoice QR requires seller NIP and issue date")
            additional = {
                "nrKSeF": assigned,
                "qrCode": VerificationLinkService(context.options).build_invoice_verification_url(
                    nip, date, digest
                ),
            }
        elif context.mode == "offline":
            if number or context.ksef_number or context.signer is None:
                raise KsefDocumentValidationError(
                    "Offline PDF requires a signer and no KSeF number"
                )
            links = build_offline_verification_links(
                context.options,
                f"{context.context_type}:{context.context_value}",
                OfflineInvoiceProgress(invoice_hash=digest),
                xml,
                context.signer,
            )
            additional = {
                "nrKSeF": "",
                "qrCode": links.invoice_url,
                "qr2Code": links.certificate_url,
            }
        else:
            raise KsefDocumentValidationError("Unknown PDF verification mode")
    return _render(xml, "invoice", additional)


def render_upo_pdf(xml: bytes) -> bytes:
    """Render one original individual or collective UPO XML (v4.2 or v4.3)."""
    _read(xml, "upo")
    return _render(xml, "upo", {})
