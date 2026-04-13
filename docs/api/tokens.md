# Tokeny KSeF (`client.tokens`)

Tokeny KSeF to tokeny „systemowe” (inne niż `accessToken`/`refreshToken`), wykorzystywane m.in. w `AuthCoordinator.authenticate_with_ksef_token(...)`.

## `generate_token(request_payload, access_token)`

Endpoint: `POST /tokens` (202)

Tworzy nowy token. Operacja jest asynchroniczna – odpowiedź zawiera numer referencyjny.

## `list_tokens(..., access_token)`

Endpoint: `GET /tokens`

Od KSeF API 2.4.0 endpoint zwraca też informacje o tokenie użytym do bieżącego uwierzytelnienia,
nawet jeśli nie ma on uprawnień `CredentialsManage` / `CredentialsRead`.

Parametry:
- `statuses` – filtr statusów (lista)
- `description`, `author_identifier`, `author_identifier_type`
- `page_size`, `continuation_token`

## `get_token_status(reference_number, access_token)`

Endpoint: `GET /tokens/{referenceNumber}`

Od KSeF API 2.4.0 można pobrać status tokenu użytego do bieżącego uwierzytelnienia także bez
dodatkowych uprawnień do zarządzania tokenami.

## `revoke_token(reference_number, access_token)`

Endpoint: `DELETE /tokens/{referenceNumber}` (204)

Od KSeF API 2.4.0 można unieważnić token użyty do bieżącego uwierzytelnienia bez uprawnienia
`CredentialsManage`.

W CLI odpowiada temu komenda `ksef auth revoke-self-token`, która używa numeru referencyjnego
zapamiętanego podczas `ksef auth login-token`.
