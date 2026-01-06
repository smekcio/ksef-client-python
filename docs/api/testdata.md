# Testdata (`client.testdata`)

Endpointy przeznaczone do przygotowania danych i scenariuszy testowych na środowiskach TE/DEMO.

Uwaga praktyczna: część metod dopuszcza `access_token=None` (zależy od środowiska i konfiguracji KSeF).

## Podmiot / osoba

### `create_subject(request_payload, access_token=None)`

Endpoint: `POST /testdata/subject`

Tworzy podmiot testowy na środowisku testowym.

### `remove_subject(request_payload, access_token=None)`

Endpoint: `POST /testdata/subject/remove`

Usuwa podmiot testowy.

### `create_person(request_payload, access_token=None)`

Endpoint: `POST /testdata/person`

Tworzy osobę testową.

### `remove_person(request_payload, access_token=None)`

Endpoint: `POST /testdata/person/remove`

Usuwa osobę testową.

## Uprawnienia testowe

### `grant_permissions(request_payload, access_token=None)`

Endpoint: `POST /testdata/permissions`

Nadaje uprawnienia w scenariuszu testowym.

### `revoke_permissions(request_payload, access_token=None)`

Endpoint: `POST /testdata/permissions/revoke`

Cofa uprawnienia nadane w scenariuszu testowym.

## Załączniki testowe

### `enable_attachment(request_payload, access_token=None)`

Endpoint: `POST /testdata/attachment`

Włącza obsługę załączników w konfiguracji testowej.

### `disable_attachment(request_payload, access_token=None)`

Endpoint: `POST /testdata/attachment/revoke`

Wyłącza obsługę załączników w konfiguracji testowej.

## Limity i rate limits (test)

### `change_session_limits(request_payload, access_token)`

Endpoint: `POST /testdata/limits/context/session`

Ustawia limity sesji w kontekście testowym.

### `reset_session_limits(access_token)`

Endpoint: `DELETE /testdata/limits/context/session`

Resetuje limity sesji do wartości domyślnych dla środowiska testowego.

### `change_certificate_limits(request_payload, access_token)`

Endpoint: `POST /testdata/limits/subject/certificate`

Ustawia limity certyfikatów w kontekście testowym.

### `reset_certificate_limits(access_token)`

Endpoint: `DELETE /testdata/limits/subject/certificate`

Resetuje limity certyfikatów do wartości domyślnych dla środowiska testowego.

### `set_rate_limits(request_payload, access_token)`

Endpoint: `POST /testdata/rate-limits`

Ustawia rate limits w środowisku testowym.

### `reset_rate_limits(access_token)`

Endpoint: `DELETE /testdata/rate-limits`

Resetuje rate limits do wartości domyślnych dla środowiska testowego.

### `restore_production_rate_limits(access_token)`

Endpoint: `POST /testdata/rate-limits/production`

Przywraca wartości rate limits zgodne z konfiguracją produkcyjną (w ramach środowiska testowego).
