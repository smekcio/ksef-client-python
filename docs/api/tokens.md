# Tokeny KSeF (`client.tokens`)

Tokeny KSeF to tokeny „systemowe” (inne niż `accessToken`/`refreshToken`), wykorzystywane m.in. w `AuthCoordinator.authenticate_with_ksef_token(...)`.

## `generate_token(request_payload, access_token)`

Endpoint: `POST /tokens` (202)

Tworzy nowy token. Operacja jest asynchroniczna – odpowiedź zawiera numer referencyjny.

## `list_tokens(..., access_token)`

Endpoint: `GET /tokens`

Od KSeF API 2.5.0 endpoint zwraca też informacje o tokenie użytym do bieżącego uwierzytelnienia,
nawet jeśli nie ma on uprawnień `CredentialsManage` / `CredentialsRead`.

Parametry:
- `statuses` – filtr statusów (lista)
- `description`, `author_identifier`, `author_identifier_type`
- `page_size`, `continuation_token`

## `get_token_status(reference_number, access_token)`

Endpoint: `GET /tokens/{referenceNumber}`

Od KSeF API 2.5.0 można pobrać status tokenu użytego do bieżącego uwierzytelnienia także bez
dodatkowych uprawnień do zarządzania tokenami.

## `revoke_token(reference_number, access_token)`

Endpoint: `DELETE /tokens/{referenceNumber}` (204)

Od KSeF API 2.5.0 można unieważnić token użyty do bieżącego uwierzytelnienia bez uprawnienia
`CredentialsManage`.

W CLI polecenie `ksef auth revoke-self-token` wymaga numeru referencyjnego
zapamiętanego podczas `ksef auth login-token` i poświadczeń powiązanych z tym
samym adresem API. Jeśli starsza sesja nie ma tego powiązania, zaloguj się
ponownie oryginalnym tokenem przed jego unieważnieniem.


## Operacje rev2 (KSeF API 2.10.0)

Metody są dostępne na klientach sync i async. Środowiska, na których działa
KSeF API 2.9.0, nadal korzystają z metod opisanych wyżej.

| Metoda | Operacja |
| --- | --- |
| `generate_token_rev2(request_payload)` | `POST /tokens/rev2` (202). Zwraca sekret tylko raz. |
| `list_tokens_rev2(...)` | `GET /tokens/rev2`. Przyjmuje także `valid_from` i `valid_to`, a kolejną stronę pobiera przez `continuation_token`. |
| `get_token_status_rev2(reference_number)` | `GET /tokens/rev2/{referenceNumber}`. Zwraca m.in. `status.code`, zakres ważności i żądane uprawnienia. |
| `approve_token(reference_number)` | `POST /tokens/{referenceNumber}/approve` (204). Wymaga uprawnień do zatwierdzenia oraz sesji uwierzytelnionej metodą dozwoloną przez KSeF, np. XAdES. |
| `revoke_token(reference_number)` | Wspólna operacja DELETE dla obu rewizji. |

Przekaż `models.GenerateTokenRequestRev2` z `description` i `permissions`.
Opcjonalne daty `valid_from` i `valid_to` są zapisane w formacie ISO 8601
z przesunięciem strefy. Domyślnie ważność rozpoczyna się od utworzenia i trwa
90 dni. Przy jawnych datach KSeF dopuszcza początek do 60 dni od utworzenia
oraz okres ważności do 365 dni od początku.

Po utworzeniu zapisz sekret z pola `token` w magazynie sekretów. Odpytuj status
po `reference_number`; sam HTTP 202 potwierdza rozpoczęcie operacji. Token rev2
utworzony w sesji uwierzytelnionej tokenem KSeF wymaga zatwierdzenia w ciągu 24 h
od przejścia do `AwaitingApproval`. Jeśli ważność jeszcze się nie rozpoczęła,
status po zatwierdzeniu to `NotYetActive`. Uwierzytelniaj się nowym tokenem
po przejściu do `Active`. `ApprovalExpired` wymaga utworzenia nowego tokenu.

`list_tokens_rev2(statuses=[models.TokenStatusFilterRev2.ACTIVE])` filtruje
po statusie. Wyniki używają `TokenStatusRev2Code`. Jeżeli KSeF zwróci
`FutureValue`, szczegółową wartość zawiera `status.raw_code`.

[Oficjalne zmiany KSeF 2.10.0](https://github.com/CIRFMF/ksef-api/blob/main/api-changelog.md#wersja-2100).
