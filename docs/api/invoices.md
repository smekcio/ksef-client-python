# Faktury i eksport (`client.invoices`)

## `get_invoice(ksef_number, access_token)`

Endpoint: `GET /invoices/ksef/{ksefNumber}`

Zwraca `InvoiceContent` (tekst XML + opcjonalny hash).

Hash (jeśli jest zwracany) jest pobierany z nagłówka `x-ms-meta-hash`.

## `get_invoice_bytes(ksef_number, access_token)`

Endpoint: `GET /invoices/ksef/{ksefNumber}`

Zwraca `BinaryContent` (bytes + opcjonalny hash).

## `query_invoice_metadata(request_payload, access_token, page_offset=None, page_size=None, sort_order=None)`

Endpoint: `POST /invoices/query/metadata`

Endpoint służy do wyszukiwania metadanych faktur. `request_payload` zależy od API (filtry typu daty, subject, kierunek itp.).

Typowe zastosowanie: synchronizacja historii metadanych i późniejsze pobieranie treści XML po `ksefNumber`.

## `export_invoices(request_payload, access_token)`

Endpoint: `POST /invoices/exports`

Startuje eksport asynchroniczny (zwykle `201 Created`, czasem `202 Accepted`). Odpowiedź zawiera `referenceNumber`.

Wymagane minimum w `request_payload`:
- `encryption.encryptedSymmetricKey`
- `encryption.initializationVector`
- `filters` (np. `subjectType` + `dateRange`)

## `get_export_status(reference_number, access_token)`

Endpoint: `GET /invoices/exports/{referenceNumber}`

Zwraca status eksportu. Po zakończeniu w polu `package` dostępne są `parts` – lista części paczki (URL + metadane).

## `download_export_part(url)`

Pobiera pojedynczą część paczki eksportu z pre-signed URL.

Ważne:
- nie jest to endpoint KSeF wymagający tokena,
- wywołanie jest wykonywane z `skip_auth=True` (nagłówek `Authorization` nie jest przesyłany).

## `download_package_part(url)`

Alias funkcjonalny dla `download_export_part(url)` (pobranie partu z pre-signed URL bez tokena).

## `download_export_part_with_hash(url)`

Jak wyżej, ale dodatkowo zwraca `BinaryContent` z hashem z `x-ms-meta-hash` (jeśli był).
