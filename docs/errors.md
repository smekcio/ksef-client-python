# Błędy, rate limits i retry

Obsługa błędów jest oparta o kody HTTP. Sukcesem jest wyłącznie kod z `expected_status`
(domyślnie 2xx) — **każdy 3xx też jest błędem**, bo `httpx` nie podąża za przekierowaniem,
więc treść odpowiedzi pochodziłaby od pośrednika (albo byłaby pusta). Wyjątkiem jest
`expected_status={..., 302}` podane świadomie. Biblioteka nie interpretuje logiki
biznesowej po stronie klienta; odpowiedzi API są mapowane bezpośrednio na wyjątki,
a treść JSON (jeśli występuje) jest dostępna w polach obiektu wyjątku.

## Typy wyjątków

Wszystkie błędy biblioteki dziedziczą po `KsefError` (wyjątki walidacji danych
wejściowych pozostają `ValueError`). Dzięki temu można łapać całość przez `KsefError`,
a jednocześnie reagować na konkretną kategorię.

### `KsefError` (baza)

- `code`: `ErrorCode` — stabilny identyfikator kategorii (`"validation_failed"`,
  `"rate_limited"`, `"authentication_failed"`, …),
- `message`: czytelny opis,
- `to_dict(omit_none=False)`: stały kontrakt JSON dla CLI/MCP (bez `response_body`).

### `KsefHttpError`

Bazowy błąd HTTP (status >= 300 albo błąd transportu). Pola: `status_code`, `message`,
`response_body`, `problem`, `retry_after`, `retry_after_raw`.

### `KsefApiError` i podklasy

Dla odpowiedzi z JSON-em SDK wybiera klasę na podstawie statusu i kodów KSeF:

| Klasa | `ErrorCode` | Kiedy |
|---|---|---|
| `KsefBadRequestError` | `bad_request` | 400 bez rozpoznanego kodu |
| `KsefAuthenticationError` | `authentication_failed` | 401, 400 z kodami auth (w tym `9101`, `9102`, `9103`, `9105`; `21401` na `/auth/...`) |
| `KsefAuthorizationError` | `authorization_failed` | 403, 400/`21301` |
| `KsefPermissionError` | `permission_error` | `26xxx`, `30xxx` |
| `KsefCertificateError` | `certificate_error` | `25xxx` |
| `KsefValidationError` | `validation_failed` | `21001`, `21217`, `21405`, `21401` poza auth/fakturami |
| `KsefInvoiceRejectedError` | `invoice_rejected` | `21401` na ścieżkach faktur, `21402`–`21403` |
| `KsefInvoiceNotFoundError` | `invoice_not_found` | `21164` |
| `KsefInvoiceUnavailableError` | `invoice_unavailable` | `21165`–`21167` |
| `KsefUpoNotFoundError` | `upo_not_found` | `21178` |
| `KsefSessionError` | `session_error` | błędy sesji (`21155`–`21208`) |
| `KsefExportError` | `export_error` | `21175`, `21181`–`21183` |
| `KsefCollectiveIdentifierError` | `collective_identifier_error` | `71xxx` |
| `KsefInvalidContinuationTokenError` | `invalid_continuation_token` | `21418` |
| `KsefResourceGoneError` | `not_found` | 410 bez rozpoznanego kodu |
| `KsefServerError` | `server_error` | 5xx (poza 502/503/504) |
| `KsefServiceUnavailableError` | `service_unavailable` | 502/503/504 |
| `KsefApiError` | `api_error` | pozostałe odpowiedzi z JSON-em |
| `KsefRateLimitError` | `rate_limited` | 429 — specjalny przypadek, bez zmian |

Gdy odpowiedź zawiera kilka kodów, pierwszeństwo ma pierwsza rodzina w kolejności:
auth → autoryzacja → uprawnienia → certyfikaty → identyfikatory zbiorcze → eksport →
sesja → faktura niedostępna → faktura nie istnieje → UPO → odrzucenie faktury →
walidacja → token kontynuacji. Kod `21401` jest wyjątkiem: na `/auth/...` oznacza błąd
dokumentu uwierzytelniającego, na `/invoices/...` i `/sessions/...` — odrzucenie faktury,
a bez kontekstu ścieżki — błąd walidacji. Ścieżka jest normalizowana (dodawany jest
leading slash, obsługiwany jest też pełny URL), więc `auth/...` i `/auth/...` dają
identyczną klasyfikację.

### `KsefRateLimitError`

Specjalny przypadek dla `429 Too Many Requests` (nie jest podklasą `KsefApiError`):

- `retry_after`: wartość nagłówka `Retry-After` w sekundach, przycięta do zakresu
  `0..MAX_RETRY_AFTER_SECONDS` (300 s),
- `retry_after_raw`: surowa wartość nagłówka,
- `problem`: `TooManyRequestsResponse` albo `TooManyRequestsProblemDetails`.

### Błędy transportu i odpowiedzi bez JSON

- `KsefTransportError` (`transport_error`) — status `0`; żądanie nie dotarło do KSeF.
- Odpowiedzi bez JSON (proxy, HTML, puste body) pozostają `KsefHttpError` — nie niosą
  kontraktu błędów KSeF, więc nie ma z czego wywnioskować kodu.

### Właściwości `KsefApiError`

```python
exc.exception_codes          # tuple[int, ...] — wszystkie kody z payloadu
exc.known_exception_codes    # tuple[KsefExceptionCode, ...] — tylko znane SDK
exc.details                  # tuple[str, ...] — opisy z errors/exceptionDetailList,
                             #   a gdy ich brak — pole ``detail`` Problem Details
exc.reason_code              # str | None — surowy reasonCode z 403
exc.forbidden_reason         # ForbiddenReason | None — znana wartość reasonCode
exc.trace_id                 # str | None — traceId z payloadu
```

Przykład:

```python
from ksef_client.exceptions import KsefApiError, KsefExceptionCode, KsefValidationError

try:
    client.invoices.query_invoice_metadata(filters)
except KsefValidationError as exc:
    if KsefExceptionCode.INPUT_VALIDATION_FAILED in exc.known_exception_codes:
        print("Błąd walidacji:", exc.details)
except KsefApiError as exc:                  # nadal łapie wszystkie podklasy
    print(exc.code, exc.status_code, exc.to_dict())
```

### `KsefExceptionCode` i `ForbiddenReason`

`KsefExceptionCode` to `IntEnum` z 54 kodami `exceptionCode` z KSeF API 2.9.0
(kody są przyjmowane jako `int` albo tekst liczbowy; `float` i `bool` są ignorowane,
tak jak w CLI)
(m.in. `INVALID_SIGNATURE = 9105`, `INPUT_VALIDATION_FAILED = 21405`, `INVALID_CSR = 25004`,
`PERMISSION_ALREADY_EXISTS = 30001`). Nowe kody przyszłych wersji API nie wywracają
parsowania — pozostają jako `int` w `exc.exception_codes`.

`ForbiddenReason` to enum wartości `reasonCode` z 403 (`missing-permissions`,
`ip-not-allowed`, `insufficient-resource-access`, `auth-method-not-allowed`,
`security-service-blocked`, `context-type-not-allowed`).

### Błędy workflow

Błędy lokalne (bez odpowiedzi HTTP) dziedziczą po `KsefWorkflowError` i zachowują
zgodność z wbudowanymi typami:

- `KsefAuthenticationFailedError` — dziedziczy po `RuntimeError`,
- `KsefAuthenticationTimeoutError` — dziedziczy po `TimeoutError`.

Dzięki temu `except RuntimeError`/`except TimeoutError` nadal działa, a jednocześnie
można łapać `KsefError` i korzystać z `to_dict()`.

Uwaga: w `KsefAuthenticationFailedError` pole `status_code` to **kod statusu
autoryzacji KSeF** (np. `400`), a nie kod HTTP — request mógł zakończyć się `200`.

### Kontrakt dla CLI i MCP

`to_dict()` zwraca stały zestaw kluczy (domyślnie także `None`):

```json
{
  "code": "validation_failed",
  "message": "API error",
  "status_code": 400,
  "retry_after": null,
  "ksef_codes": [21405],
  "details": ["Błąd walidacji danych wejściowych."],
  "reason_code": null,
  "trace_id": "…"
}
```

- `code` jest stabilny — nowe wartości dodawajemy na końcu `ErrorCode`,
- `to_dict(omit_none=True)` pomija `None` (wygodne dla CLI),
- CLI ma `exit_code_for_error(exc)` mapujące `ErrorCode` na `ExitCode`,
- w `to_dict()` nigdy nie ma `response_body` ani nagłówków,
- `message` i `details` pochodzą z odpowiedzi KSeF i mogą zawierać fragmenty danych
  biznesowych (np. opisy walidacji) — w logach produkcyjnych rozważ redakcję.

## Problem Details i `exc.problem`

KSeF API 2.5.0 rozszerza odpowiedzi błędów o format `application/problem+json`.

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

## Automatyczny retry w SDK

Zamiast ręcznej pętli możesz włączyć retry w konfiguracji klienta — SDK respektuje
`Retry-After`, stosuje backoff z jitterem i ponawia tylko bezpieczne metody
(`GET`/`PUT`/`DELETE`; `POST` wyłącznie po jawnym dodaniu ścieżki):

```python
from ksef_client import KsefClientOptions, RetryConfig

options = KsefClientOptions(base_url="...", retry=RetryConfig())
```

Retry jest domyślnie wyłączony. Szczegóły i ograniczenia: [retry.md](retry.md).

Poniższy przykład pokazuje ręczną obsługę 429 — przydaje się, gdy potrzebujesz
pełnej kontroli nad pętlą.

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

Ważne: KSeF stosuje dynamiczne okno limitów, a kolejne przekroczenia mogą skutkować wydłużaniem `Retry-After`. Nagłówek `Retry-After` powinien być respektowany — SDK przycina go jednak do 300 s (`MAX_RETRY_AFTER_SECONDS`), żeby wartość podana przez serwer nie usypiała procesu na dni. Własna polityka retry, która chce czekać dłużej, ma do dyspozycji surowe `exc.retry_after_raw`.
