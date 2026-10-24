# Konfiguracja (`KsefClientOptions`)

Konfiguracja jest celowo uproszczona: biblioteka nie wprowadza ukrytej automatyki i pozostawia kontrolę nad transportem HTTP (timeouty, proxy, nagłówki).

## `KsefClientOptions`

```python
from ksef_client import KsefClientOptions

options = KsefClientOptions(
    base_url="https://api-test.ksef.mf.gov.pl",
    timeout_seconds=30.0,
    verify_ssl=True,
    require_export_part_hash=True,
    proxy=None,
    custom_headers={"X-Custom-Header": "value"},
    follow_redirects=False,
    strict_presigned_url_validation=True,
    allowed_presigned_hosts=None,
    allow_private_network_presigned_urls=False,
    system_warning_handler=None,
    base_qr_url=None,
    base_lighthouse_url=None,
    retry=None,  # RetryConfig() włącza automatyczne ponawianie
    rate_limit_budget=None,  # wspólna instancja RateLimitBudget włącza planowanie żądań
    rate_limit_context_key=None,
    rate_limit_egress_key="default",
)
```

### `base_url`

- Adres środowiska KSeF (TEST/DEMO/PROD).
- Biblioteka dopina `/v2`, jeśli nie występuje w adresie (np. `https://api-test.ksef.mf.gov.pl` → `.../v2`).

Gotowe stałe:

```python
from ksef_client import KsefEnvironment

KsefEnvironment.TEST.value
KsefEnvironment.DEMO.value
KsefEnvironment.PROD.value
```

### `base_qr_url`

Używane przez `VerificationLinkService` do budowania linków pod QR.

- Jeśli `base_qr_url` nie jest ustawione, biblioteka dobiera je na podstawie `base_url` (TEST/DEMO/PROD).
- Dla niestandardowego `base_url` wymagane jest ustawienie `base_qr_url` jawnie.

### `base_lighthouse_url`

Używane przez `client.lighthouse` (`/status`, `/messages` API Latarni).

- Jeśli `base_lighthouse_url` nie jest ustawione, biblioteka mapuje je z `base_url`:
  - KSeF `TEST` -> Latarnia `TEST`
  - KSeF `DEMO` -> Latarnia `TEST`
  - KSeF `PROD` -> Latarnia `PROD`
- Dla niestandardowego `base_url` można ustawić `base_lighthouse_url` jawnie.

Gotowe stałe:

```python
from ksef_client import KsefLighthouseEnvironment

KsefLighthouseEnvironment.TEST.value
KsefLighthouseEnvironment.PROD.value
KsefLighthouseEnvironment.PRD.value  # alias
```

### `timeout_seconds`

Timeout dla pojedynczego żądania HTTP (httpx). W przypadku wysyłki partów i pobierania paczek eksportu może być wymagane zwiększenie wartości (duże paczki, wolniejsze łącza).

### `proxy`

Proxy przekazywane do httpx (string, np. `http://user:pass@host:port`).

### `custom_headers`

Stałe nagłówki dodawane do każdego żądania (np. identyfikator korelacji, nagłówki firmowe).

Na środowisku TEST można wymusić treść `X-System-Warning` nagłówkiem żądania:

```python
custom_headers={"X-Test-System-Warning": "[test]: synthetic warning"},
```

`X-Test-System-Warning` działa wyłącznie na TEST. Odpowiedź wraca jako `X-System-Warning`
i trafia do `system_warning_handler`.

Istotne: dla operacji wysyłki i pobierania partów KSeF zwraca wymagane nagłówki. W tych wywołaniach biblioteka używa `skip_auth=True`, ale `custom_headers` nadal są scalane z nagłówkami żądania. Ustawianie `Authorization` w `custom_headers` jest niewskazane, ponieważ dla pre-signed URL może powodować błędy autoryzacji.

### `follow_redirects`

Opcja zwykle nie jest potrzebna. Włączenie ma uzasadnienie wyłącznie w środowiskach, w których infrastruktura wymusza przekierowania.

**Ważne:** reguła dotyczy wyłącznie żądań uwierzytelnionych. Żądania z `skip_auth=True` (pre-signed URL do partów paczki, UPO, pobieranie faktur oraz wywołania `auth`/`security`/`peppol` bez nagłówka `Authorization`) **nigdy** nie podążają za przekierowaniem, niezależnie od tej opcji. Powód: walidacja bezpieczeństwa (`strict_presigned_url_validation`, `allowed_presigned_hosts`) dotyczy tylko adresu początkowego, więc podążenie za przekierowaniem wykonałoby żądanie pod adres wskazany przez serwer — także do sieci wewnętrznej — i zwróciło jego treść jako wynik. Odpowiedź 3xx jest w takim przypadku błędem (`KsefHttpError`), a nie pustym sukcesem.

### `verify_ssl`

Domyślnie `True`. Wyłączenie ma uzasadnienie wyłącznie w specyficznych środowiskach testowych (np. z własnym MITM/proxy).

### `require_export_part_hash`

Domyślnie `True`. Dotyczy pobierania partów eksportu (`ExportWorkflow`, `AsyncExportWorkflow`):

- dla każdego pobranego, zaszyfrowanego partu biblioteka liczy `SHA-256` i porównuje z nagłówkiem `x-ms-meta-hash` (base64), jeśli nagłówek jest obecny;
- jeśli `x-ms-meta-hash` nie ma i opcja jest `True`, biblioteka zgłasza `ValueError`;
- jeśli hash się nie zgadza, biblioteka zgłasza `ValueError`;
- ustawienie `False` pozwala przejść dalej, gdy nagłówek hash nie został zwrócony (nadal występuje walidacja, gdy hash jest obecny).

### `strict_presigned_url_validation`

Domyślnie `True`. Dla absolutnych URL używanych z `skip_auth=True` wymusza `https`. Przy wyłączeniu możliwe są URL `http`, ale nadal działa walidacja hosta/IP.

### `allowed_presigned_hosts`

Domyślnie `None` (brak allowlisty). Jeśli ustawione, host pre-signed URL musi pasować dokładnie albo jako subdomena (np. `a.uploads.example.com` pasuje do `uploads.example.com`).

### `allow_private_network_presigned_urls`

Domyślnie `False`. Gdy `False`, blokowane są hosty IP prywatne/link-local/reserved dla żądań `skip_auth=True`. Ustaw `True` wyłącznie w kontrolowanym środowisku.

### `system_warning_handler`

Opcjonalny callback `Callable[[str], None]` wywoływany, gdy KSeF zwróci nagłówek
`X-System-Warning`. Nagłówek przenosi ostrzeżenia techniczne i nie oznacza błędu operacji.
Na środowisku TEST można wymusić treść ostrzeżenia nagłówkiem `X-Test-System-Warning`.

### `retry`

Automatyczne ponawianie żądań HTTP (opt-in). `None` (domyślnie) oznacza brak retry —
zachowanie identyczne z wersjami bez tego pola.

```python
from ksef_client import KsefClientOptions, RetryConfig

options = KsefClientOptions(
    base_url="https://api-test.ksef.mf.gov.pl",
    retry=RetryConfig(max_retries=3, base_delay_ms=250, jitter_ratio=0.2),
)
```

Retry dotyczy wyłącznie 429/502/503/504, respektuje `Retry-After` (sufit 300 s) i ponawia
`GET`/`PUT`/`DELETE`; `POST` wymaga jawnej ścieżki w `retryable_post_paths`. Jedna pauza
nie przekracza 5 minut. Szczegóły i ograniczenia: [retry.md](retry.md).

## Przekazywanie `access_token`

Dostępne są trzy sposoby przekazywania `access_token`:

1) Przekazanie tokena w konstruktorze klienta:

```python
from ksef_client import models as m

client = KsefClient(options, access_token=access_token)
client.invoices.query_invoice_metadata(
    m.InvoiceQueryFilters(
        subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
        date_range=m.InvoiceQueryDateRange(
            date_type=m.InvoiceQueryDateType.ISSUE,
            from_="2026-01-01T00:00:00Z",
            to="2026-01-31T23:59:59Z",
        ),
    )
)
```

2) Przekazywanie `access_token` per-call (przydatne w przypadku obsługi wielu kontekstów):

```python
from ksef_client import models as m

client.invoices.query_invoice_metadata(
    m.InvoiceQueryFilters(
        subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
        date_range=m.InvoiceQueryDateRange(
            date_type=m.InvoiceQueryDateType.ISSUE,
            from_="2026-01-01T00:00:00Z",
            to="2026-01-31T23:59:59Z",
        ),
    ),
    access_token=access_token,
)
```

3) Klient zarządzający tokenem (`AuthenticatedClient` / `AsyncAuthenticatedClient`) —
   token jest wstrzykiwany i odświeżany automatycznie, więc nie przekazujesz go do metod:

```python
from ksef_client import AuthenticatedClient, models as m

with AuthenticatedClient.from_auth_result(options, auth_result) as client:
    client.invoices.query_invoice_metadata_by_date_range(
        subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
        date_type=m.InvoiceQueryDateType.ISSUE,
        date_from="2026-01-01T00:00:00Z",
        date_to="2026-01-31T23:59:59Z",
    )   # bez access_token
```

Szczegóły: [token-manager.md](token-manager.md).

## Budżet żądań i termin oczekiwania

`rate_limit_budget` jest opcjonalną, współdzieloną instancją `RateLimitBudget`.
Przy jej użyciu wymagany jest `rate_limit_context_key` zgodny z kontekstem
uwierzytelnienia. `rate_limit_egress_key` identyfikuje wyjściowy adres IP lub proxy.
Automatyczne przekierowania (`follow_redirects=True`) są wtedy niedozwolone.

Aktualne limity można pobrać przez `client.rate_limits.get_rate_limits()`.
Konfigurację sync/async, `request_control()` z terminem i anulowaniem oraz granice
współdzielenia opisuje [zarządzanie limitami API](rate-budgets.md).
