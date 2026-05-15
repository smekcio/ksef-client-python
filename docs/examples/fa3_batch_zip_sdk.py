from __future__ import annotations

from datetime import date
from pathlib import Path

from ksef_client.documents.fa3 import FA3BatchDraft, FA3InvoiceBuilder, FA3Party


def _build(invoice_number: str, amount: str) -> bytes:
    seller = FA3Party(name="Sprzedawca Sp. z o.o.", tax_id="1234567890", address="ul. Prosta 1")
    buyer = FA3Party(name="Nabywca S.A.", tax_id="1111111111", address="ul. Jasna 2")

    draft = (
        FA3InvoiceBuilder(
            invoice_number=invoice_number,
            issue_date=date(2026, 5, 16),
            seller=seller,
            buyer=buyer,
        )
        .add_line("Usluga", quantity="1", unit_net_price=amount, vat_rate="23")
        .build()
    )
    return draft.to_xml(xsd_validate=True)


def main() -> None:
    seller = FA3Party(name="Sprzedawca Sp. z o.o.", tax_id="1234567890", address="ul. Prosta 1")
    buyer = FA3Party(name="Nabywca S.A.", tax_id="1111111111", address="ul. Jasna 2")
    draft_1 = (
        FA3InvoiceBuilder(
            invoice_number="FV/BATCH/001/2026",
            issue_date=date(2026, 5, 16),
            seller=seller,
            buyer=buyer,
        )
        .add_line("Usluga A", quantity="1", unit_net_price="1000", vat_rate="23")
        .build()
    )
    draft_2 = (
        FA3InvoiceBuilder(
            invoice_number="FV/BATCH/002/2026",
            issue_date=date(2026, 5, 16),
            seller=seller,
            buyer=buyer,
        )
        .add_line("Usluga B", quantity="1", unit_net_price="1500", vat_rate="23")
        .build()
    )
    batch = FA3BatchDraft((draft_1, draft_2))
    out = Path("artifacts/fa3-batch.zip")
    batch.to_xml_zip(out)
    print(out.resolve())


if __name__ == "__main__":
    main()
