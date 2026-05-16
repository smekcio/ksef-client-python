# Workflow: FA(3) SDK only

Scenariusz obejmuje: zbudowanie faktury FA(3) w Pythonie, walidację biznesową, wygenerowanie XML,
opcjonalną walidację XSD oraz użycie wyniku w sesji online albo batch.

Rekomendowane podejście:

- typed buildery `FA3Invoice.basic(...)`, `FA3Invoice.correction(...)`, `FA3Invoice.advance(...)`,
  `FA3Invoice.settlement(...)` dla nowych integracji,
- `to_xml(xsd_validate=True)` przed wysyłką do KSeF,
- `OnlineSessionWorkflow` dla pojedynczych XML-i albo `BatchSessionWorkflow` dla ZIP-a z wieloma XML-ami,
- drafty `FA3Draft` / `FA3BatchDraft` tylko tam, gdzie potrzebny jest prosty JSON round-trip lub szybki ZIP na dysku.

## Przykład: faktura podstawowa do XML

```python
from datetime import date

from ksef_client.documents.fa3 import FA3Invoice, Party, VatClass

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

invoice = (
    FA3Invoice.basic("FV/001/2026")
    .issued_on(date(2026, 5, 16))
    .seller(seller)
    .buyer(buyer)
    .add_service_line(
        "Usługa konsultingowa",
        quantity="1",
        unit_net_price="1000",
        tax=VatClass.standard_23(),
    )
    .payment_due(date(2026, 5, 30))
    .build()
)

xml = invoice.to_xml(xsd_validate=True)
```

`build()` waliduje model biznesowo. `xsd_validate=True` dodatkowo sprawdza zgodność wygenerowanego XML-a
z oficjalną schemą FA(3).

## Przykład: korekta

Ten fragment używa `seller` i `buyer` z poprzedniego przykładu.

```python
from datetime import date

from ksef_client.documents.fa3 import FA3Invoice, InvoiceLine, VatClass

correction = (
    FA3Invoice.correction("FV/KOR/001/2026")
    .issued_on(date(2026, 5, 16))
    .seller(seller)
    .buyer(buyer)
    .corrects_invoice(
        number="FV/BASE/001/2026",
        issue_date=date(2026, 5, 1),
        reason="Rabat posprzedażowy",
    )
    .add_corrected_line_before_after(
        before=InvoiceLine.service(
            "Usługa konsultingowa",
            quantity="1",
            unit_net_price="1000",
            tax=VatClass.standard_23(),
        ),
        after=InvoiceLine.service(
            "Usługa konsultingowa",
            quantity="1",
            unit_net_price="800",
            tax=VatClass.standard_23(),
        ),
    )
    .build()
)

xml = correction.to_xml(xsd_validate=True)
```

Dla korekt SDK wymaga przyczyny i referencji do faktury korygowanej. Pozycje `before` i `after` są
serializowane jako para przed/po korekcie.

## Przykład: rozliczenie zaliczki

Ten fragment używa `seller` i `buyer` z pierwszego przykładu.

```python
from datetime import date

from ksef_client.documents.fa3 import FA3Invoice, VatClass

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

xml = settlement.to_xml(xsd_validate=True)
```

Faktury rozliczeniowe muszą wskazywać fakturę zaliczkową przez `settles_advance(...)` albo
`settles_advances(...)`.

## Przykład: wysyłka online

```python
from ksef_client import models as m
from ksef_client.services import OnlineSessionWorkflow

FORM_CODE = m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")
xml = invoice.to_xml(xsd_validate=True)

workflow = OnlineSessionWorkflow(client.sessions)
session = workflow.open_session(
    form_code=FORM_CODE,
    public_certificate=symmetric_key_certificate,
    access_token=access_token,
)
send = session.send_invoice(xml)
session.close()

print(send.reference_number)
```

Ten workflow zakłada, że masz już `access_token` i certyfikat do szyfrowania klucza symetrycznego.
Pełny scenariusz uwierzytelnienia i resume jest opisany w [`online-session.md`](online-session.md).

## Przykład: ZIP do sesji batch

```python
from ksef_client import models as m
from ksef_client.services import BatchSessionWorkflow
from ksef_client.utils import build_zip

FORM_CODE = m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")
zip_bytes = build_zip(
    {
        "fv-001.xml": invoice_1.to_xml(xsd_validate=True),
        "fv-002.xml": invoice_2.to_xml(xsd_validate=True),
    }
)

workflow = BatchSessionWorkflow(client.sessions, client.http_client)
session = workflow.open_session(
    form_code=FORM_CODE,
    zip_bytes=zip_bytes,
    public_certificate=symmetric_key_certificate,
    access_token=access_token,
)
session.upload_parts(parallelism=4)
session.close()
```

ZIP musi zawierać XML-e FA(3). Podział na części, szyfrowanie i upload na pre-signed URL wykonuje
`BatchSessionWorkflow`. Pełny scenariusz resume jest opisany w [`batch-session.md`](batch-session.md).

## Draft JSON i `FA3BatchDraft`

Jeżeli integracja wymienia dane jako JSON albo potrzebuje szybkiego ZIP-a na dysku, użyj warstwy draftowej:

```python
from datetime import date

from ksef_client.documents.fa3 import FA3BatchDraft, FA3InvoiceBuilder, FA3Party

seller = FA3Party(name="Sprzedawca Sp. z o.o.", tax_id="1234567890", address="ul. Prosta 1")
buyer = FA3Party(name="Nabywca S.A.", tax_id="1111111111", address="ul. Jasna 2")

draft = (
    FA3InvoiceBuilder(
        invoice_number="FV/JSON/001/2026",
        issue_date=date(2026, 5, 16),
        seller=seller,
        buyer=buyer,
    )
    .add_line("Usługa JSON", quantity="1", unit_net_price="800", vat_rate="23")
    .build()
)

batch = FA3BatchDraft((draft,))
batch.to_json("artifacts/fa3-json/draft.json")
batch.to_xml_zip("artifacts/fa3-json/draft.zip")
```

To jest prostsza ścieżka niż typed buildery. Nie obejmuje wszystkich wygodnych metod domenowych,
ale dobrze pasuje do prostych faktur, JSON round-trip i przykładów batch.

## Publiczne klasy i metody

Najważniejsze klasy:

- `FA3Invoice` – typed model faktury; ma `validate()` i `to_xml(...)`.
- `Party` / `InvoiceParty` – strony faktury; helpery `polish_company(...)`, `eu_company(...)`,
  `foreign_company(...)`, `without_tax_id(...)`.
- `InvoiceLine` – pozycje faktury; helpery `goods(...)`, `service(...)`, `corrected_before(...)`,
  `corrected_after(...)`.
- `VatClass` / `TaxCategory` – stawki i klasyfikacje VAT.
- `PaymentTerms`, `BankAccount`, `PartialPayment` – płatności.
- `FA3Draft`, `FA3InvoiceBuilder`, `FA3BatchDraft` – prostszy model draftowy z JSON/ZIP.

Najważniejsze metody:

- `FA3Invoice.basic(...)`, `correction(...)`, `advance(...)`, `settlement(...)` – wybór typu faktury.
- `seller(...)`, `buyer(...)`, `add_goods_line(...)`, `add_service_line(...)`, `payment_due(...)` – typowy builder faktury.
- `corrects_invoice(...)`, `add_corrected_line_before_after(...)` – korekty.
- `settles_advance(...)`, `remaining_to_pay(...)` – rozliczenia zaliczek.
- `build()` – zwraca gotową fakturę albo zgłasza błędy walidacji.
- `to_xml(xsd_validate=True)` – generuje XML i opcjonalnie waliduje XSD.
- `validate_fa3_xml_xsd(xml)` – waliduje istniejący XML.
- `audit_fa3_xsd_coverage(...)` – raportuje pokrycie elementów XSD przez SDK i scenariusze testowe.

## Przykłady uruchomieniowe

Skrypty z katalogu [`../examples`](../examples/README.md):

- `fa3_single_invoice_sdk.py` – pojedynczy XML FA(3),
- `fa3_batch_zip_sdk.py` – ZIP z wieloma XML-ami,
- `fa3_correction_settlement_sdk.py` – korekta i rozliczenie zaliczki,
- `fa3_json_roundtrip_sdk.py` – JSON draft → ZIP.
