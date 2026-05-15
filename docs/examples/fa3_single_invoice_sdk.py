from __future__ import annotations

from datetime import date
from pathlib import Path

from ksef_client.documents.fa3 import FA3InvoiceBuilder, FA3Party


def main() -> None:
    seller = FA3Party(name="Sprzedawca Sp. z o.o.", tax_id="1234567890", address="ul. Prosta 1")
    buyer = FA3Party(name="Nabywca S.A.", tax_id="1111111111", address="ul. Jasna 2")

    draft = (
        FA3InvoiceBuilder(
            invoice_number="FV/SDK/001/2026",
            issue_date=date(2026, 5, 16),
            seller=seller,
            buyer=buyer,
            currency="PLN",
            issue_place="Warszawa",
        )
        .add_line("Usluga konsultingowa", quantity="2", unit_net_price="500", vat_rate="23")
        .build()
    )

    xml = draft.to_xml(xsd_validate=True)
    out = Path("artifacts/fa3-single.xml")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(xml)
    print(out.resolve())


if __name__ == "__main__":
    main()
