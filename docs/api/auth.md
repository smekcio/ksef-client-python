# Auth API (`client.auth`)

Ten podklient obsługuje:
- challenge (`/auth/challenge`)
- rozpoczęcie auth (XAdES lub token KSeF)
- polling statusu
- redeem tokenów (`accessToken`/`refreshToken`)
- refresh `accessToken`

Workflow: [Uwierzytelnianie](../workflows/auth.md).

## `get_active_sessions(...)`

Pobiera listę aktywnych sesji uwierzytelnienia.

Parametry:
- `page_size` – rozmiar strony
- `continuation_token` – token kolejnej strony (zwykle `continuationToken` z odpowiedzi)
- `access_token` – opcjonalnie; w przypadku braku biblioteka używa tokena ustawionego w `KsefClient`

## `revoke_current_session(access_token)`

Unieważnia „bieżącą” sesję auth (dla podanego tokena).

## `revoke_session(reference_number, access_token)`

Unieważnia konkretną sesję auth po `reference_number`.

## `get_challenge()`

Endpoint: `POST /auth/challenge` (bez `accessToken`).

Zwraca JSON z polami m.in.:
- `challenge`
- `timestamp`
- `timestampMs`

Challenge jest ważny **10 minut**. W przypadku dłuższego procesu podpisu (np. HSM) należy pobrać nowe wyzwanie.

## `submit_xades_auth_request(signed_xml, verify_certificate_chain=None, enforce_xades_compliance=False)`

Endpoint: `POST /auth/xades-signature` (bez `accessToken`).

- `signed_xml` – podpisany XML `AuthTokenRequest`
- `verify_certificate_chain` – opcjonalna weryfikacja łańcucha certyfikatów (przydatne w TE)
- `enforce_xades_compliance` – gdy `True`, dodaje nagłówek `X-KSeF-Feature: enforce-xades-compliance` (przydatne do wcześniejszej walidacji reguł XAdES na DEMO/PROD)

Zwraca (202) obiekt inicjujący auth, m.in. `referenceNumber` i `authenticationToken`.

## `submit_ksef_token_auth(request_payload)`

Endpoint: `POST /auth/ksef-token` (bez `accessToken`).

`request_payload` to JSON w formacie oczekiwanym przez KSeF. Payload może zostać zbudowany przez:
- `ksef_client.services.build_ksef_token_auth_request()`
- albo w ogóle użyć `AuthCoordinator.authenticate_with_ksef_token()`

## `get_auth_status(reference_number, authentication_token)`

Endpoint: `GET /auth/{referenceNumber}`

Istotne: w nagłówku `Authorization: Bearer ...` przekazywany jest **authentication token** (nie `accessToken`).

Zwraca status operacji (pole `status.code` ma praktyczne znaczenie przy pollingu).

## `redeem_token(authentication_token)`

Endpoint: `POST /auth/token/redeem`

Zwraca parę tokenów: `accessToken` i `refreshToken`.

Ważne: `redeem` jest **jednorazowe** dla danego `authenticationToken`. Ponowne wywołanie dla tego samego tokena kończy się błędem.

## `refresh_access_token(refresh_token)`

Endpoint: `POST /auth/token/refresh`

Refresh token jest przekazywany w `Authorization: Bearer <refreshToken>`. Metoda `refresh_access_token()` mapuje to poprawnie; ręczne ustawianie nagłówka `Authorization` nie jest wymagane.
