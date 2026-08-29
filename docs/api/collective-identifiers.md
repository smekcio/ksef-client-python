# Identyfikatory zbiorcze (`client.collective_identifiers`)

Obsługa identyfikatorów zbiorczych (IZ) wprowadzonych w KSeF API 2.7.0
i zaktualizowanych w 2.7.1.

IZ grupuje już wystawione faktury tego samego sprzedawcy (do 500 numerów KSeF) pod jednym
numerem płatniczym. Jedna faktura może należeć do maksymalnie 132 identyfikatorów zbiorczych
w ramach kontekstu.

## Uprawnienia

Wymagane jest **jedno z**: `InvoiceRead`, `InvoiceWrite`, `CollectiveIdentifierManage`.
`CollectiveIdentifierManage` wystarcza do operacji na IZ bez uprawnień do wystawiania faktur.

## Limity

| Limit | Wartość |
| --- | --- |
| Faktury w jednym IZ | 500 |
| IZ na jedną fakturę (w kontekście) | 132 |
| Zakres `dateCreatedFrom`–`dateCreatedTo` | 100 dni |
| `pageSize` query / by-ksef | 10–200 (domyślnie 10) |
| `pageSize` invoices | 10–500 (domyślnie 10) |
| IZ w jednym `list_invoices` | 10 |
| Rate limit grupy `collectiveIdentifier` | 20 / 120 / 240 |

Kody błędów `generate`:

| Kod | Znaczenie |
| --- | --- |
| `71001` | Faktura nie może zostać przypisana do IZ |
| `71002` | Faktura jest już przypisana do maksymalnej liczby IZ |

Stałe i mapowanie kodów: `ksef_client.utils.collective_identifier`
(`MAX_INVOICES_PER_IDENTIFIER`, `COLLECTIVE_IDENTIFIER_EXCEPTION_CODES`).
Błędy API nadal przychodzą jako `KsefApiError`.

## Scenariusz

1. Wyślij faktury sesją online albo wsadową.
2. Zbierz numery KSeF z UPO lub metadanych.
3. Złóż IZ i użyj numeru na przelewie:

```python
from ksef_client.utils.collective_identifier import make_collective_identifier_invoice

response = client.collective_identifiers.generate_for_ksef_numbers(
    ["5265877635-20250826-0100001AF629-AF"],
    access_token=access_token,
)
print(response.collective_identifier_number)

# płatności: typed generate() + fabryka z Decimal
from decimal import Decimal
from ksef_client.models import GenerateCollectiveIdentifierRequest

invoice = make_collective_identifier_invoice(
    "5265877635-20250826-0100001AF629-AF",
    amount=Decimal("150.00"),
    currency="PLN",
)
client.collective_identifiers.generate(
    GenerateCollectiveIdentifierRequest(invoices=[invoice]),
    access_token=access_token,
)
```

Paginacja list: query `pageSize` oraz nagłówek `x-continuation-token`. Token kontynuacji
jest też zwracany w body odpowiedzi (`continuationToken`). Helpery `iter_query`,
`iter_invoices` i `iter_by_ksef_number` schodzą po stronach same.

SDK waliduje format `collective_identifier_number` oraz `ksef_number` przed wysłaniem
żądania (`ValueError` przy niepoprawnym formacie/sumie kontrolnej). Dodatkowo fail-fast:
liczba faktur 1–500, unikalne numery KSeF, zakres dat ≤ 100 dni, `pageSize` 10–200
(query / by-ksef) albo 10–500 (`list_invoices`), maksymalnie 10 numerów IZ w `list_invoices`.

CLI: `ksef iz generate|query|invoices|by-ksef`.

## `generate(request_payload, access_token)`

Endpoint: `POST /collective-identifiers` (`201`).

Generuje identyfikator zbiorczy dla listy faktur (numery KSeF) tego samego sprzedawcy.

## `generate_for_ksef_numbers(ksef_numbers, access_token, descriptions=None)`

Składa `GenerateCollectiveIdentifierRequest` z numerów KSeF. Płatności zostaw przy
`generate()` i `make_collective_identifier_invoice`.

## `query(request_payload, access_token, page_size=None, continuation_token=None)`

Endpoint: `POST /collective-identifiers/query`.

Zwraca listę identyfikatorów zbiorczych powiązanych z kontekstem (filtr dat utworzenia
wymagany w payloadzie, max 100 dni).

## `query_by_created_range(date_from, date_to, access_token, ...)`

Convenience nad `query`. Daty `YYYY-MM-DD` są rozszerzane do początku/końca dnia UTC.

## `iter_query(request_payload, access_token, page_size=None)`

Iterator po wszystkich stronach `query`.

## `list_invoices(collective_identifier_numbers, access_token, page_size=None, continuation_token=None)`

Endpoint: `POST /collective-identifiers/invoices`.

Zwraca listę faktur wchodzących w skład podanych IZ (1–10 numerów). Pojedynczy
string jest akceptowany tak samo jak lista. Odpowiedź zawiera `collectiveIdentifierNumber`
przy każdej fakturze. `pageSize` ma zakres 10–500.

Od 2.7.1 transport to POST z listą IZ (w 2.7.0 był GET jednego numeru).

## `iter_invoices(collective_identifier_numbers, access_token, page_size=None)`

Iterator po stronach `list_invoices`.

## `list_by_ksef_number(ksef_number, access_token, page_size=None, continuation_token=None)`

Endpoint: `GET /collective-identifiers/ksef/{ksefNumber}`.

Zwraca listę identyfikatorów zbiorczych powiązanych z podanym numerem KSeF.

## `iter_by_ksef_number(ksef_number, access_token, page_size=None)`

Iterator po stronach `list_by_ksef_number`.
