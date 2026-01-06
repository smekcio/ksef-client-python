# Uwierzytelnianie – budowa payloadów (`ksef_client.services.auth`)

Funkcje wspierają ręczną budowę payloadów przy zachowaniu formatów oczekiwanych przez KSeF.

W większości integracji wykorzystywany jest `AuthCoordinator` (szczegóły: [Workflows i narzędzia pomocnicze](workflows.md)).

## `build_auth_token_request_xml(...) -> str`

Buduje XML `AuthTokenRequest` (bez podpisu).

Najważniejsze parametry:
- `challenge`: z `client.auth.get_challenge()`
- `context_identifier_type`: `"nip" | "internalId" | "nipVatUe" | "peppolId"` (case-insensitive)
- `context_identifier_value`: wartość identyfikatora kontekstu (np. NIP)
- `subject_identifier_type`: domyślnie `"certificateSubject"`; alternatywnie `"certificateFingerprint"`
- `authorization_policy_xml`: opcjonalnie fragment XML z polityką (np. allow-list IP)

## `encrypt_ksef_token(...) -> str`

Szyfruje payload `"{token}|{timestampMs}"` certyfikatem KSeF i zwraca Base64 (standardowe, nie Base64Url).

Parametry:
- `public_certificate`: PEM certyfikatu KSeF o usage `KsefTokenEncryption`
- `token`: token KSeF (string)
- `timestamp_ms`: z challenge (`timestampMs`)
- `method`: `"rsa"` lub `"ec"`
- `ec_output_format`: `"java"` lub `"csharp"` (ważne tylko dla `ec`)

Uwagi: przy porównaniu wyników z SDK Java i .NET, `ec_output_format` wpływa na kolejność `ciphertext/tag`.

## `build_ksef_token_auth_request(...) -> dict[str, Any]`

Buduje JSON dla `POST /auth/ksef-token`.

Parametry:
- `challenge`: z `get_challenge()`
- `context_identifier_type`, `context_identifier_value`: jak wyżej
- `encrypted_token_base64`: wynik `encrypt_ksef_token(...)`
- `authorization_policy`: opcjonalnie polityka (JSON, zależnie od API)
