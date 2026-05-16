# FA(3) SDK Only

Dokument opisuje programistyczny workflow FA(3) w warstwie SDK (`ksef_client.documents.fa3`).
Zakres obejmuje budowanie faktur, walidację biznesową, serializację XML oraz walidację XSD.

FA(3) w tym module jest **SDK-only**: biblioteka przygotowuje poprawny XML lub ZIP z XML-ami,
a wysyłkę wykonujesz później przez workflow sesji online/batch.

## Instalacja

Podstawowe budowanie modeli działa po instalacji pakietu SDK. Do walidacji XSD wymagany jest extra `fa3`:

```bash
pip install -e .[fa3]
```

Extra `fa3` instaluje `lxml`, który jest używany przez `to_xml(xsd_validate=True)` i
`validate_fa3_xml_xsd(...)`.

## Typowy przepływ

1. Zbuduj model faktury przez typed builder `FA3Invoice.basic(...)`, `FA3Invoice.correction(...)`,
   `FA3Invoice.advance(...)` albo `FA3Invoice.settlement(...)`.
2. Uzupełnij strony, pozycje, płatności i sekcje specyficzne dla rodzaju dokumentu.
3. Wywołaj `build()`; SDK wykona walidację biznesową i zwróci `FA3Invoice`.
4. Wygeneruj XML przez `invoice.to_xml(xsd_validate=True)`.
5. Przekaż XML do sesji online albo zapakuj wiele XML-i do ZIP-a i użyj sesji batch.

Minimalny przykład:

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

## Workflow: XML do sesji online

`FA3Invoice.to_xml(...)` zwraca `bytes`, więc wynik można przekazać bezpośrednio do workflow sesji online:

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
session.send_invoice(xml)
session.close()
```

Pełny opis otwierania, wznawiania i zamykania sesji znajduje się w
[`workflows/online-session.md`](workflows/online-session.md).

## Workflow: wiele XML-i do batch ZIP

Dla sesji batch przygotuj ZIP zawierający pliki XML FA(3). Możesz użyć narzędzia `build_zip(...)`:

```python
from ksef_client.utils import build_zip

zip_bytes = build_zip(
    {
        "fv-001.xml": invoice_1.to_xml(xsd_validate=True),
        "fv-002.xml": invoice_2.to_xml(xsd_validate=True),
    }
)
```

Następnie przekaż `zip_bytes` do `BatchSessionWorkflow.open_session(...)`. Pełny opis sesji batch
jest w [`workflows/batch-session.md`](workflows/batch-session.md).

Dla prostych integracji draftowych dostępny jest też `FA3BatchDraft(...).to_xml_zip(path)`, który
buduje ZIP na dysku z obiektów `FA3Draft`.

## Główne klasy

| Klasa | Zastosowanie |
| --- | --- |
| `FA3Invoice` | Typed model faktury FA(3). Tworzony przez buildery i serializowany przez `to_xml(...)`. |
| `BasicInvoiceBuilder`, `CorrectionInvoiceBuilder`, `AdvanceInvoiceBuilder`, `SettlementInvoiceBuilder` | Buildery dla konkretnych typów faktur. Zwracane przez metody fabryczne `FA3Invoice`. |
| `Party` / `InvoiceParty` | Dane sprzedawcy, nabywcy i podmiotów dodatkowych. Najczęściej używaj `Party.polish_company(...)`. |
| `PartyIdentifier`, `Address`, `Contact` | Składowe danych kontrahenta, gdy potrzebujesz bardziej szczegółowego modelowania. |
| `InvoiceLine` | Pozycja faktury. Dostępne są helpery `goods(...)`, `service(...)`, `corrected_before(...)`, `corrected_after(...)`. |
| `TaxCategory` / `VatClass` | Stawki i klasyfikacje VAT, np. `standard_23()`, `reduced_8()`, `exempt(...)`. |
| `PaymentTerms`, `BankAccount`, `PartialPayment` | Płatności: terminy, metoda, rachunki bankowe, płatności częściowe. |
| `CorrectionReference` | Referencja do faktury korygowanej. Najczęściej ustawiana przez `corrects_invoice(...)`. |
| `Settlement` | Dane rozliczenia faktury zaliczkowej. Najczęściej ustawiane metodami buildera rozliczenia. |
| `Attachment`, `Footer`, `Order`, `Transport` | Sekcje dodatkowe FA(3), używane tylko gdy dany proces ich wymaga. |
| `FA3Draft`, `FA3InvoiceBuilder`, `FA3BatchDraft` | Prostszy/draftowy model kompatybilny z JSON round-trip i przykładami wsadowymi. |

## Metody typed builderów

Metody fabryczne `FA3Invoice` wybierają rodzaj dokumentu:

| Metoda | Zwracany builder | Kiedy używać |
| --- | --- | --- |
| `FA3Invoice.basic(number)` | `BasicInvoiceBuilder` | Zwykła faktura sprzedaży. |
| `FA3Invoice.simplified(number)` | `SimplifiedInvoiceBuilder` | Faktura uproszczona. |
| `FA3Invoice.correction(number)` | `CorrectionInvoiceBuilder` | Korekta faktury. |
| `FA3Invoice.advance(number)` | `AdvanceInvoiceBuilder` | Faktura zaliczkowa. |
| `FA3Invoice.settlement(number)` | `SettlementInvoiceBuilder` | Rozliczenie faktury zaliczkowej. |
| `FA3Invoice.advance_correction(number)` | `AdvanceCorrectionInvoiceBuilder` | Korekta faktury zaliczkowej. |
| `FA3Invoice.settlement_correction(number)` | `SettlementCorrectionInvoiceBuilder` | Korekta faktury rozliczeniowej. |

Najczęściej używane metody wspólne:

- `issued_on(date)` – data wystawienia.
- `currency("PLN")`, `issue_place(...)`, `sale_date(...)`, `period(from_, to_)` – dane nagłówka.
- `seller(party)`, `buyer(party)`, `add_party(party, role)` – strony faktury.
- `add_goods_line(...)`, `add_service_line(...)`, `add_line(...)` – pozycje faktury.
- `payment_due(date)`, `paid(date)`, `partially_paid(...)`, `bank_account(...)` – płatności.
- `split_payment()`, `cash_method()`, `reverse_charge()`, `exemption(...)`, `margin(...)` – adnotacje VAT.
- `transaction_terms(...)`, `contract(...)`, `order_reference(...)`, `transport(...)` – warunki transakcji.
- `attachment_text(...)`, `attachment_table(...)`, `footer_info(...)`, `registry(...)` – załączniki i stopka.
- `build()` – kończy budowę i zwraca `FA3Invoice`.

Metody specyficzne dla korekt i zaliczek:

- `corrects_invoice(number=..., issue_date=..., reason=...)` – wskazuje fakturę korygowaną.
- `corrects_many(...)` – wskazuje wiele faktur korygowanych.
- `correction_type(...)` – ustawia typ korekty.
- `add_corrected_line_before_after(before=..., after=...)` – dodaje parę pozycji przed/po korekcie.
- `advance_payment(...)`, `order(...)`, `order_line(...)` – dane faktury zaliczkowej.
- `settles_advance(...)`, `settles_advances(...)`, `remaining_to_pay(...)` – rozliczenie zaliczki.

## Walidacja i serializacja

`build()` i `to_xml(validate=True)` uruchamiają walidację biznesową SDK. Wynik walidacji możesz też
sprawdzić jawnie:

```python
result = invoice.validate()
if not result.ok:
    result.raise_for_errors()
```

Serializacja:

```python
xml = invoice.to_xml()                    # walidacja biznesowa + XML
xml = invoice.to_xml(xsd_validate=True)   # dodatkowo walidacja XSD
```

Dla istniejącego XML-a użyj funkcji:

```python
from ksef_client.documents.fa3 import validate_fa3_xml_xsd

validate_fa3_xml_xsd(xml)
```

Błąd XSD jest zgłaszany jako `FA3XmlValidationError`.

## Drafty JSON i batch helper

`FA3Draft`, `FA3InvoiceBuilder` i `FA3BatchDraft` są prostszą warstwą draftową przydatną, gdy integracja
ma własny format JSON albo potrzebuje łatwego round-tripu:

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

Ta warstwa nie zastępuje typed builderów; jest wygodna dla prostych scenariuszy, migracji i przykładów
batch/JSON.

## Przykłady

- [`examples/fa3_single_invoice_sdk.py`](examples/fa3_single_invoice_sdk.py) – pojedyncza faktura draftowa do XML.
- [`examples/fa3_batch_zip_sdk.py`](examples/fa3_batch_zip_sdk.py) – wiele draftów do jednego ZIP-a.
- [`examples/fa3_correction_settlement_sdk.py`](examples/fa3_correction_settlement_sdk.py) – typed korekta i rozliczenie zaliczki.
- [`examples/fa3_json_roundtrip_sdk.py`](examples/fa3_json_roundtrip_sdk.py) – JSON draft → `FA3BatchDraft` → ZIP XML.
- [`workflows/fa3.md`](workflows/fa3.md) – gotowe workflow FA(3) z użyciem sesji online/batch.

## Audyt pokrycia XSD

Funkcja `audit_fa3_xsd_coverage(...)` realizuje audyt oparty o dowody:

- `SUPPORTED`: ścieżka XSD wystąpiła w XML wygenerowanym przez scenariusz testowy i XML przeszedł walidację XSD,
- `PARTIALLY_SUPPORTED`: istnieje mapowanie w SDK, ale brak dowodu wykonania w korpusie scenariuszy,
- `UNSUPPORTED`: brak mapowania i brak dowodu wykonania.

W praktyce audyt składa się z trzech warstw:

1. inwentaryzacji elementów ze schemy FA(3),
2. klasyfikacji ścieżek względem mapowania SDK,
3. agregacji śladów z XML wygenerowanych przez scenariusze testowe.

Aby domknąć brak pokrycia, należy dodać scenariusz, który generuje brakującą ścieżkę oraz przechodzi
`xsd_validate=True`.
