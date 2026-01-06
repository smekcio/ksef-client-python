# Tokeny KSeF (`client.tokens`)

Tokeny KSeF to tokeny „systemowe” (inne niż `accessToken`/`refreshToken`), wykorzystywane m.in. w `AuthCoordinator.authenticate_with_ksef_token(...)`.

## `generate_token(request_payload, access_token)`

Endpoint: `POST /tokens` (202)

Tworzy nowy token. Operacja jest asynchroniczna – odpowiedź zawiera numer referencyjny.

## `list_tokens(..., access_token)`

Endpoint: `GET /tokens`

Parametry:
- `statuses` – filtr statusów (lista)
- `description`, `author_identifier`, `author_identifier_type`
- `page_size`, `continuation_token`

## `get_token_status(reference_number, access_token)`

Endpoint: `GET /tokens/{referenceNumber}`

## `revoke_token(reference_number, access_token)`

Endpoint: `DELETE /tokens/{referenceNumber}` (204)
