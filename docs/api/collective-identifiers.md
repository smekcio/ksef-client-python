# Identyfikatory zbiorcze (`client.collective_identifiers`)

Obsługa identyfikatorów zbiorczych (IZ) wprowadzonych w KSeF API 2.7.0.

Wymagane uprawnienia zależą od operacji — zwykle jedno z: `InvoiceRead`, `InvoiceWrite`,
`CollectiveIdentifierManage`.

Paginacja list: query `pageSize` oraz nagłówek `x-continuation-token`. Token kontynuacji
jest też zwracany w body odpowiedzi (`continuationToken`).

SDK waliduje format `collective_identifier_number` oraz `ksef_number` przed wysłaniem
żądania (`ValueError` przy niepoprawnym formacie/sumie kontrolnej).

## `generate(request_payload, access_token)`

Endpoint: `POST /collective-identifiers` (`201`).

Generuje identyfikator zbiorczy dla listy faktur (numery KSeF) tego samego sprzedawcy.
Limit: do 500 faktur w jednym IZ.

## `query(request_payload, access_token, page_size=None, continuation_token=None)`

Endpoint: `POST /collective-identifiers/query`.

Zwraca listę identyfikatorów zbiorczych powiązanych z kontekstem (filtr dat utworzenia
wymagany w payloadzie).

## `list_invoices(collective_identifier_number, access_token, page_size=None, continuation_token=None)`

Endpoint: `GET /collective-identifiers/{collectiveIdentifierNumber}/invoices`.

Zwraca listę faktur wchodzących w skład wskazanego IZ.

## `list_by_ksef_number(ksef_number, access_token, page_size=None, continuation_token=None)`

Endpoint: `GET /collective-identifiers/ksef/{ksefNumber}`.

Zwraca listę identyfikatorów zbiorczych powiązanych z podanym numerem KSeF.
