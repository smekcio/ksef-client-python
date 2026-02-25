# Latarnia (`client.lighthouse`)

`client.lighthouse` udostępnia publiczne endpointy Latarni KSeF (bez autoryzacji).

## `get_status()`

Endpoint: `GET /status` (API Latarni)

Zwraca `LighthouseStatusResponse`:
- `status`: `AVAILABLE`, `MAINTENANCE`, `FAILURE`, `TOTAL_FAILURE`
- `messages`: komunikaty powiązane z aktualnym statusem (lub brak dla pełnej dostępności)

## `get_messages()`

Endpoint: `GET /messages` (API Latarni)

Zwraca `list[LighthouseMessage]` z opublikowanymi komunikatami.

## Środowiska

Domyślne mapowanie dla `KsefClientOptions.base_url`:
- `TEST` -> `https://api-latarnia-test.ksef.mf.gov.pl`
- `DEMO` -> `https://api-latarnia-test.ksef.mf.gov.pl`
- `PROD` -> `https://api-latarnia.ksef.mf.gov.pl`

Nadpisanie mapowania:
- `KsefClientOptions(base_lighthouse_url="https://...")`
