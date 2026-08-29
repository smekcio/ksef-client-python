# Identyfikator zbiorczy (`ksef_client.utils.collective_identifier`)

Walidator formatu IZ (`NIP-IZYYYYMM-HEX12-CRC8`), zgodny z dokumentacją KSeF API 2.7.1,
oraz helpery domenowe używane przez `client.collective_identifiers`.

## Stałe

- `MAX_INVOICES_PER_IDENTIFIER` (500)
- `MAX_IDENTIFIERS_PER_INVOICE` (132)
- `MAX_IDENTIFIERS_PER_INVOICES_QUERY` (10)
- `MAX_QUERY_RANGE_DAYS` (100)
- `PAGE_SIZE_MIN` / `PAGE_SIZE_MAX` (10 / 200)
- `PAGE_SIZE_INVOICES_MAX` (500)
- `COLLECTIVE_IDENTIFIER_EXCEPTION_CODES` (`71001`, `71002`)

## `validate_collective_identifier_number(value) -> ValidationResult`

Sprawdza wzorzec, długość 35 znaków oraz checksum CRC-8 (ten sam algorytm co dla numeru KSeF).

## `is_valid_collective_identifier_number(value) -> bool`

## `require_collective_identifier_number(value) -> str`

Zwraca wartość albo rzuca `ValueError`. Używane przez `client.collective_identifiers.list_invoices`.

## `require_page_size(value, *, maximum=PAGE_SIZE_MAX) -> int`

## `require_invoices_query_identifiers(value) -> list[str]`

Normalizuje jeden numer albo listę (1–10, unikalne).

## `require_query_date_range(date_from, date_to) -> tuple[str, str]`

## `require_generate_invoices(invoices) -> list`

## `make_collective_identifier_invoice(ksef_number, *, description=None, amount=None, currency=None)`

Buduje `CollectiveIdentifierInvoice`. Kwota może być `Decimal`; model OpenAPI serializuje ją jako `float`.

```python
from decimal import Decimal
from ksef_client.utils.collective_identifier import make_collective_identifier_invoice

item = make_collective_identifier_invoice(
    "5265877635-20250826-0100001AF629-AF",
    description="przelew zbiorczy 08/2026",
    amount=Decimal("150.00"),
    currency="PLN",
)
```

`amount` i `currency` muszą wystąpić razem albo wcale. Opis ma limit 512 znaków.
