# Błędy, rate limits i retry

Obsługa błędów jest oparta o kody HTTP (>= 400). Biblioteka nie interpretuje logiki biznesowej po stronie klienta; odpowiedzi API są mapowane bezpośrednio na wyjątki, a treść JSON (jeśli występuje) jest dostępna w polach obiektu wyjątku.

## Typy wyjątków

### `ValueError` (walidacja pre-signed URL)

Dla żądań z `skip_auth=True` i absolutnym URL biblioteka wykonuje walidację bezpieczeństwa. W przypadku niespełnienia reguł (np. host `localhost`, loopback/private IP bez opt-in, host poza allowlistą, albo `http` przy `strict_presigned_url_validation=True`) rzucany jest `ValueError` z komunikatem bezpieczeństwa.

### `KsefHttpError`

Bazowy błąd HTTP.

- `status_code`: kod HTTP
- `message`: tekst (dla odpowiedzi nie-JSON)
- `response_body`: zwykle `None`

### `KsefApiError`

Występuje, gdy odpowiedź ma `Content-Type: application/json` i status >= 400.

- `exception_response`: legacy `ExceptionResponse`, jeśli API zwróci klasyczny format `application/json`
- `problem`: zmapowany model błędu, jeśli odpowiedź daje się rozpoznać

### `KsefRateLimitError`

Specjalny przypadek dla `429 Too Many Requests`.

- `retry_after`: wartość nagłówka `Retry-After`
- `problem`: `TooManyRequestsResponse` albo `TooManyRequestsProblemDetails`

## Problem Details i `exc.problem`

KSeF API 2.4.0 rozszerza odpowiedzi błędów o format `application/problem+json`.

SDK mapuje `exc.problem` do jednego z modeli:

- `BadRequestProblemDetails` dla `400 application/problem+json`
- `UnauthorizedProblemDetails` dla `401 application/problem+json`
- `ForbiddenProblemDetails` dla `403 application/problem+json`
- `TooManyRequestsProblemDetails` albo legacy `TooManyRequestsResponse` dla `429`
- `GoneProblemDetails` dla `410 application/problem+json`
- `ExceptionResponse` dla klasycznego formatu błędu KSeF
- `UnknownApiProblem`, gdy odpowiedź JSON nie pasuje do znanego modelu

`410 Gone` pojawia się m.in. po wygaśnięciu retencji technicznych statusów operacji asynchronicznych.

CLI ustawia ten nagłówek domyślnie dla klientów tworzonych przez warstwę `ksef ...`,
więc bogatsze hinty oparte o `exc.problem` działają bez dodatkowej konfiguracji.

Jeżeli używasz bezpośrednio SDK i chcesz wymusić bogatszy format błędów dla `400` i `429`,
ustaw nagłówek:

```python
from ksef_client import KsefClientOptions

options = KsefClientOptions(
    base_url="https://api-test.ksef.mf.gov.pl",
    custom_headers={"X-Error-Format": "problem-details"},
)
```

Publiczne API SDK nie dodaje osobnego parametru do tego nagłówka; używa istniejącego
`custom_headers`.

## Przykładowa obsługa 429 z `Retry-After`

```python
import time
from ksef_client import KsefRateLimitError

def call_with_backoff(fn):
    for attempt in range(10):
        try:
            return fn()
        except KsefRateLimitError as exc:
            wait_s = int(exc.retry_after or "1")
            time.sleep(max(wait_s, 1))
    raise TimeoutError("Zbyt dużo 429; przerwano po 10 próbach.")
```

Ważne: KSeF stosuje dynamiczne okno limitów, a kolejne przekroczenia mogą skutkować wydłużaniem `Retry-After`. Nagłówek `Retry-After` powinien być respektowany.
