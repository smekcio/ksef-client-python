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

- `exception_response`: surowy JSON zwrócony przez API (zwykle zawiera kody i detale)

### `KsefRateLimitError`

Specjalny przypadek dla `429 Too Many Requests`.

- `retry_after`: wartość nagłówka `Retry-After` (zwykle sekundy jako string)
- `response_body`: model błędu z API (jeśli był JSON)

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
