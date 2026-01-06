# Sesje (`client.sessions`)

KSeF udostępnia dwa typy sesji wysyłkowych:
- `Online` – wysyłka interaktywna (pojedyncze faktury)
- `Batch` – wysyłka wsadowa (ZIP dzielony na party)

## `get_sessions(...)`

Endpoint: `GET /sessions`

Parametry:
- `session_type` (wymagane): `"Online"` albo `"Batch"`
- `page_size`, `continuation_token` – stronicowanie
- filtry dat (`date_created_from` / `to`, `date_closed_from` / `to`, `date_modified_from` / `to`)
- `statuses`: lista statusów, np. `["InProgress", "Succeeded", "Failed", "Cancelled"]`
- `access_token` – opcjonalnie (jak w innych klientach)

Stronicowanie:
- `x-continuation-token` jest przekazywany w żądaniu, a token kolejnej strony jest zwracany zwykle jako `continuationToken` w body odpowiedzi.

## `open_online_session(request_payload, access_token, upo_v43=False)`

Endpoint: `POST /sessions/online`

`request_payload` zawiera `formCode` i sekcję `encryption`. Do budowy payloadu i otwarcia sesji zalecane jest użycie `OnlineSessionWorkflow.open_session()`.

`upo_v43=True` dodaje nagłówek `X-KSeF-Feature: upo-v4-3` (negocjacja wersji UPO).

## `send_online_invoice(reference_number, request_payload, access_token)`

Endpoint: `POST /sessions/online/{referenceNumber}/invoices`

Wywołanie jest asynchroniczne (202). Odpowiedź zawiera `referenceNumber` faktury w sesji, wykorzystywany do pobrania statusu.

Payload może zostać zbudowany przez:
- `ksef_client.services.build_send_invoice_request()`
- `OnlineSessionWorkflow.send_invoice()`

## `close_online_session(reference_number, access_token)`

Endpoint: `POST /sessions/online/{referenceNumber}/close`

Zamknięcie inicjuje generowanie zbiorczego UPO (asynchronicznie).

## `open_batch_session(request_payload, access_token, upo_v43=False)`

Endpoint: `POST /sessions/batch`

Odpowiedź zawiera m.in. `partUploadRequests` (pre-signed URL + wymagane nagłówki).

Do pełnego przebiegu (ZIP → podział ≤100MB → szyfrowanie → wysyłka → zamknięcie) przeznaczony jest `BatchSessionWorkflow.open_upload_and_close()`.

## `close_batch_session(reference_number, access_token)`

Endpoint: `POST /sessions/batch/{referenceNumber}/close`

## `get_session_status(reference_number, access_token)`

Endpoint: `GET /sessions/{referenceNumber}`

Zwraca status sesji i (zależnie od typu) dodatkowe pola: m.in. informacje o UPO.

## `get_session_invoices(reference_number, ..., access_token)`

Endpoint: `GET /sessions/{referenceNumber}/invoices`

Lista faktur w sesji + stronicowanie (`page_size`, `continuation_token`).

## `get_session_failed_invoices(reference_number, ..., access_token)`

Endpoint: `GET /sessions/{referenceNumber}/invoices/failed`

## `get_session_invoice_status(reference_number, invoice_reference_number, access_token)`

Endpoint: `GET /sessions/{referenceNumber}/invoices/{invoiceReferenceNumber}`

Status przetwarzania jest udostępniany asynchronicznie; standardowym podejściem jest polling do momentu uzyskania `status.code == 200` albo kodu błędu.

## `get_session_invoice_upo_by_ref(reference_number, invoice_reference_number, access_token)`

Endpoint: `GET /sessions/{ref}/invoices/{invoiceRef}/upo`

Pobiera UPO dla faktury po `invoiceReferenceNumber`.

Zwraca bajty (XML/PDF – zależnie od tego, co zwraca API).

## `get_session_invoice_upo_by_ksef(reference_number, ksef_number, access_token)`

Endpoint: `GET /sessions/{ref}/invoices/ksef/{ksefNumber}/upo`

Pobiera UPO dla faktury po `ksefNumber`.

Zwraca bajty (XML/PDF – zależnie od tego, co zwraca API).

## `get_session_upo(reference_number, upo_reference_number, access_token)`

Endpoint: `GET /sessions/{referenceNumber}/upo/{upoReferenceNumber}`

Pobiera konkretne UPO po numerze referencyjnym.
