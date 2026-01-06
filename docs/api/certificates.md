# Certyfikaty (`client.certificates`)

Ten podklient obsługuje enrollment certyfikatu KSeF, pobieranie listy certyfikatów i unieważnianie.

Przy pierwszej implementacji pomocny jest dokument `ksef-docs/certyfikaty-KSeF.md` (wymagania co do DN/CSR, typy certyfikatów).

## `get_limits(access_token)`

Endpoint: `GET /certificates/limits`

Zwraca limity certyfikatów dla kontekstu/podmiotu.

## `get_enrollment_data(access_token)`

Endpoint: `GET /certificates/enrollments/data`

Zwraca dane wejściowe do CSR (m.in. wartości do subject/DN). Typowy przebieg: pobranie danych i lokalne wygenerowanie CSR.

Powiązane: [CSR](../services/csr.md).

## `send_enrollment(request_payload, access_token)`

Endpoint: `POST /certificates/enrollments` (202)

Wysyła CSR i inicjuje proces wystawienia certyfikatu. Zwraca `referenceNumber`.

## `get_enrollment_status(reference_number, access_token)`

Endpoint: `GET /certificates/enrollments/{referenceNumber}`

Polling statusu enrollmentu.

## `query_certificates(request_payload, access_token, page_size=None, page_offset=None)`

Endpoint: `POST /certificates/query`

Lista certyfikatów wg filtrów.

## `retrieve_certificate(request_payload, access_token)`

Endpoint: `POST /certificates/retrieve`

Pobiera certyfikat (np. po serialu / identyfikatorach – zależnie od payloadu).

## `revoke_certificate(certificate_serial_number, request_payload, access_token)`

Endpoint: `POST /certificates/{serial}/revoke`

Unieważnia certyfikat.
