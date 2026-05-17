from __future__ import annotations

from datetime import date
from pathlib import Path

from ksef_client.documents.fa3 import FA3BatchDraft, FA3InvoiceBuilder, FA3Party


def main() -> None:
    seller = FA3Party(name="Sprzedawca Sp. z o.o.", tax_id="1234567890", address="ul. Prosta 1")
    buyer = FA3Party(name="Nabywca S.A.", tax_id="1111111111", address="ul. Jasna 2")

    draft = (
        FA3InvoiceBuilder(
            invoice_number="FV/JSON/001/2026",
            issue_date=date(2026, 5, 16),
            seller=seller,
            buyer=buyer,
        )
        .add_line("Usluga JSON", quantity="1", unit_net_price="800", vat_rate="23")
        .build()
    )

    batch = FA3BatchDraft((draft,))
    out_dir = Path("artifacts/fa3-json")
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "draft.json"
    batch.to_json(json_path)

    loaded = FA3BatchDraft.from_json(json_path)
    zip_path = loaded.to_xml_zip(out_dir / "draft.zip")
    print(zip_path.resolve())


if __name__ == "__main__":
    main()
