# Retry HTTP (backoff i `Retry-After`)

SDK potrafi automatycznie ponawiać żądania, które KSeF odrzucił przejściowo
(429/502/503/504). Retry jest **opt-in** — dopóki nie ustawisz `retry` w opcjach,
każde żądanie leci dokładnie raz, tak jak w poprzednich wersjach biblioteki.

## Włączenie

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment, RetryConfig

options = KsefClientOptions(
    base_url=KsefEnvironment.DEMO.value,
    retry=RetryConfig(),          # domyślne: 3 ponowienia, 250 ms bazy, jitter 20%
)

with KsefClient(options) as client:
    ...
```

`AsyncKsefClient` przyjmuje te same opcje.

## Konfiguracja

```python
RetryConfig(
    max_retries=3,                    # 0..20 (0 = jedno żądanie, bez ponowień)
    base_delay_ms=250,                # baza backoffu wykładniczego
    jitter_ratio=0.2,                 # ±20% losowego rozrzutu
    max_delay_ms=30_000,              # sufit backoffu (None = tylko sufit bezpieczeństwa 5 min)
    retryable_methods=frozenset({"GET", "PUT", "DELETE"}),
    retryable_post_paths=frozenset(), # POST ponawiany tylko po jawnym dodaniu ścieżki
)
```

Walidacja odbywa się w konstruktorze — niepoprawne wartości kończą się `ValueError`.
`max_delay_ms` nie może przekraczać `MAX_RETRY_DELAY_MS` (5 min); to samo ograniczenie
obowiązuje, gdy `max_delay_ms=None`. Jedna pauza nigdy nie przekracza więc 5 minut.

## Które odpowiedzi są ponawiane

Retry dotyczy **wyłącznie** statusów `429`, `502`, `503`, `504` (`RETRYABLE_STATUS_CODES`)
i tylko metod z allowlisty:

| Metoda | Domyślnie | Uwagi |
|---|---|---|
| `GET` | tak | pobieranie danych, statusy operacji |
| `PUT` | tak | upload części paczki (pre-signed URL) — treść jest identyczna |
| `DELETE` | tak | zamknięcie sesji, revoke — operacje idempotentne |
| `POST` | **nie** | wysyłka faktury, redeem tokena, challenge — nie można ich powtórzyć bez ryzyka |

`POST` **nigdy** nie jest ponawiany na podstawie samej metody — dodanie `"POST"` do
`retryable_methods` kończy się `ValueError`. Jedyną furtką jest `retryable_post_paths`
z dokładną ścieżką. Nie dodawaj tam endpointów nieidempotentnych (wysyłka faktury,
redeem tokena).

Jeśli endpoint `POST` jest bezpieczny do powtórzenia (np. zapytanie o metadane), dodaj
jego ścieżkę jawnie:

```python
config = RetryConfig(
    retryable_post_paths=frozenset({"/invoices/query/metadata"}),
)
```

Ścieżki są dopasowywane dosłownie i muszą być względne (zaczynać się od `/`) — `POST` na
absolutny pre-signed URL nigdy nie jest ponawiany, a próba dodania takiego adresu kończy
się `ValueError`.

## Opóźnienia

1. Jeśli odpowiedź zawiera `Retry-After`, SDK czeka dokładnie tyle (z sufitem
   `MAX_RETRY_AFTER_SECONDS = 300` s — wartość od serwera nie może usypiać procesu na dni).
2. W przeciwnym razie działa backoff wykładniczy: `base_delay_ms * 2**(n-1)` z losowym
   rozrzutem `±jitter_ratio` i sufitem `max_delay_ms` (a gdy ten jest `None` — sufitem
   bezpieczeństwa 5 min, żeby opóźnienie zawsze mieściło się w zakresie `sleep`).

```python
# 429 z Retry-After: 30  →  czekaj 30 s
# 503 bez nagłówka       →  250 ms, 500 ms, 1 s (przy domyślnych ustawieniach)
```

## Ograniczenia

- **Błędy transportu nie są ponawiane.** `ConnectError`, timeouty i zerwane połączenia
  kończą się `KsefHttpError` (status `0`) — po read-timeout nie wiadomo, czy `POST`
  został przyjęty, więc automatyczne powtórzenie mogłoby zdublować operację.
- Najgorszy czas oczekiwania to `max_retries * 300 s` przy `Retry-After: 300`; jeśli
  to za dużo, zmniejsz `max_retries`.
- Retry działa w warstwie HTTP, więc obejmuje wszystkich klientów (również Latarnię).
- Klient uwierzytelniony sprawdza ważność tokena przed każdą próbą HTTP, także
  po pauzie `Retry-After`. Każda próba może obsłużyć własne 401 (refresh + jedna
  powtórka), więc maks. liczba żądań do endpointu to `2 * (max_retries + 1)`,
  a odświeżeń — do `max_retries + 1` (gdy każda próba zwróci 401). Dla
  `max_retries=2` to 6 żądań i 3 odświeżenia; budżet ponowień dla 429/502/503/504
  pozostaje wspólny dla całego wywołania.

## Interakcja z CLI

CLI ma własną pętlę retry w adapterach i **nie ustawia** `options.retry` — dzięki temu
nie dochodzi do podwójnego ponawiania. Nowy kod SDK może korzystać z `RetryConfig`
niezależnie od CLI.

## Zobacz też

- [Błędy i rate limits](errors.md) — `retry_after`/`retry_after_raw` na wyjątkach,
- [Klient uwierzytelniony i tokeny](token-manager.md) — refresh tokena po 401.
