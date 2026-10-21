"""Odczyt FA(3): XML → model → XML (roundtrip).

Skrypt nie wymaga sieci ani danych uwierzytelniających: buduje fakturę przez SDK,
serializuje ją do XML, odczytuje z powrotem i porównuje dokumenty (poza
``Naglowek/DataWytworzeniaFa``, która z natury różni się między uruchomieniami).

Uruchomienie:

    python docs/examples/fa3_parse_roundtrip.py
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from xml.etree import ElementTree as ET

from ksef_client.documents.fa3 import FA3Invoice, Party, VatClass, parse_invoice_xml


def _without_timestamp(xml: bytes) -> str:
    root = ET.fromstring(xml)
    for node in root.iter():
        if node.tag.endswith("DataWytworzeniaFa"):
            node.text = "TIMESTAMP"
    return ET.tostring(root, encoding="unicode")


def main() -> int:
    seller = Party.polish_company(nip="1234567890", name="Sprzedawca", address="ul. Testowa 1")
    buyer = Party.polish_company(nip="1111111111", name="Nabywca", address="ul. Kupiecka 2")

    invoice = (
        FA3Invoice.basic("FV/2026/10/0001")
        .issued_on(date(2026, 10, 21))
        .seller(seller)
        .buyer(buyer)
        .add_service_line(
            "Usługa programistyczna",
            quantity="10",
            unit_net_price="150.00",
            tax=VatClass.standard_23(),
        )
        .build()
    )

    xml = invoice.to_xml()
    parsed = parse_invoice_xml(xml)

    print(f"Faktura: {parsed.invoice_number}")
    print(f"Sprzedawca: {parsed.seller.name} ({parsed.seller.identifier.value})")
    print(f"Netto: {parsed.total_net}  VAT: {parsed.total_vat}  Brutto: {parsed.total_gross}")
    for line in parsed.lines:
        print(f"  - {line.description}: {line.effective_net_amount} netto")
    for warning in parsed.warnings:
        print(f"OSTRZEŻENIE: {warning.message}")

    # Odczytany model można zserializować ponownie — dokument jest równoważny.
    reserialized = parsed.to_xml()
    if _without_timestamp(reserialized) != _without_timestamp(xml):
        print("Roundtrip NIE zachował dokumentu.")
        return 1
    print("Roundtrip OK (poza znacznikiem DataWytworzeniaFa).")

    # Model da się też modyfikować (obiekty są niemutowalne — replace tworzy kopię).
    corrected = replace(parsed, invoice_number="FV/2026/10/0001-K")
    print(f"Kopia z nowym numerem: {corrected.invoice_number}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
