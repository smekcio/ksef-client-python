from __future__ import annotations

from datetime import date
from pathlib import Path

from ksef_client.documents.fa3 import FA3Invoice, InvoiceLine, Party, VatClass


def main() -> None:
    seller = Party.polish_company(
        nip="1234567890",
        name="Sprzedawca Sp. z o.o.",
        address="ul. Prosta 1",
    )
    buyer = Party.polish_company(
        nip="1111111111",
        name="Nabywca S.A.",
        address="ul. Jasna 2",
    )

    correction = (
        FA3Invoice.correction("FV/KOR/001/2026")
        .issued_on(date(2026, 5, 16))
        .seller(seller)
        .buyer(buyer)
        .corrects_invoice(
            number="FV/BASE/001/2026",
            issue_date=date(2026, 5, 1),
            reason="Rabat posprzedazowy",
        )
        .add_corrected_line_before_after(
            before=InvoiceLine.service(
                "Usluga konsultingowa",
                quantity="1",
                unit_net_price="1000",
                tax=VatClass.standard_23(),
            ),
            after=InvoiceLine.service(
                "Usluga konsultingowa",
                quantity="1",
                unit_net_price="800",
                tax=VatClass.standard_23(),
            ),
        )
        .build()
    )

    settlement = (
        FA3Invoice.settlement("FV/ROZ/001/2026")
        .issued_on(date(2026, 5, 16))
        .seller(seller)
        .buyer(buyer)
        .settles_advance(invoice_number="FV/ZAL/001/2026")
        .add_service_line(
            "Rozliczenie zaliczki",
            quantity="1",
            unit_net_price="1000",
            tax=VatClass.standard_23(),
        )
        .remaining_to_pay("1230.00")
        .build()
    )

    out_dir = Path("artifacts/fa3-special-cases")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "correction.xml").write_bytes(correction.to_xml(xsd_validate=True))
    (out_dir / "settlement.xml").write_bytes(settlement.to_xml(xsd_validate=True))
    print(out_dir.resolve())


if __name__ == "__main__":
    main()
