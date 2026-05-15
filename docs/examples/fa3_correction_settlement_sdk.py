from __future__ import annotations

from datetime import date
from decimal import Decimal
from pathlib import Path

from ksef_client.documents.fa3 import FA3InvoiceBuilder, FA3InvoiceKind, FA3Party


def main() -> None:
    seller = FA3Party(name="Sprzedawca Sp. z o.o.", tax_id="1234567890", address="ul. Prosta 1")
    buyer = FA3Party(name="Nabywca S.A.", tax_id="1111111111", address="ul. Jasna 2")

    correction = (
        FA3InvoiceBuilder(
            invoice_number="FV/KOR/001/2026",
            issue_date=date(2026, 5, 16),
            seller=seller,
            buyer=buyer,
            kind=FA3InvoiceKind.CORRECTION,
            correction_reason="Rabat posprzedazowy",
            corrected_invoice_number="FV/BASE/001/2026",
            corrected_invoice_date=date(2026, 5, 1),
        )
        .add_line("Korekta pozycji", quantity="1", unit_net_price="-200", vat_rate="23")
        .build()
    )

    settlement = (
        FA3InvoiceBuilder(
            invoice_number="FV/ROZ/001/2026",
            issue_date=date(2026, 5, 16),
            seller=seller,
            buyer=buyer,
            kind=FA3InvoiceKind.SETTLEMENT,
            advance_invoice_number="FV/ZAL/001/2026",
            settlement_amount=Decimal("1230.00"),
        )
        .add_line("Rozliczenie zaliczki", quantity="1", unit_net_price="1000", vat_rate="23")
        .build()
    )

    out_dir = Path("artifacts/fa3-special-cases")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "correction.xml").write_bytes(correction.to_xml(xsd_validate=True))
    (out_dir / "settlement.xml").write_bytes(settlement.to_xml(xsd_validate=True))
    print(out_dir.resolve())


if __name__ == "__main__":
    main()
