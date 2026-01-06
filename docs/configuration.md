# Konfiguracja (`KsefClientOptions`)

Konfiguracja jest celowo uproszczona: biblioteka nie wprowadza ukrytej automatyki i pozostawia kontrolę nad transportem HTTP (timeouty, proxy, nagłówki).

## `KsefClientOptions`

```python
from ksef_client import KsefClientOptions

options = KsefClientOptions(
    base_url="https://api-test.ksef.mf.gov.pl",
    timeout_seconds=30.0,
    verify_ssl=True,
    proxy=None,
    custom_headers={"X-Custom-Header": "value"},
    follow_redirects=False,
    base_qr_url=None,
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

### `timeout_seconds`

Timeout dla pojedynczego żądania HTTP (httpx). W przypadku wysyłki partów i pobierania paczek eksportu może być wymagane zwiększenie wartości (duże paczki, wolniejsze łącza).

### `proxy`

Proxy przekazywane do httpx (string, np. `http://user:pass@host:port`).

### `custom_headers`

Stałe nagłówki dodawane do każdego żądania (np. identyfikator korelacji, nagłówki firmowe).

Istotne: dla operacji wysyłki i pobierania partów KSeF zwraca wymagane nagłówki. W tych wywołaniach biblioteka używa `skip_auth=True`, ale `custom_headers` nadal są scalane z nagłówkami żądania. Ustawianie `Authorization` w `custom_headers` jest niewskazane, ponieważ dla pre-signed URL może powodować błędy autoryzacji.

### `follow_redirects`

Opcja zwykle nie jest potrzebna. Włączenie ma uzasadnienie wyłącznie w środowiskach, w których infrastruktura wymusza przekierowania.

### `verify_ssl`

Domyślnie `True`. Wyłączenie ma uzasadnienie wyłącznie w specyficznych środowiskach testowych (np. z własnym MITM/proxy).

## Przekazywanie `access_token`

Dostępne są dwa sposoby przekazywania `access_token`:

1) Przekazanie tokena w konstruktorze klienta:

```python
client = KsefClient(options, access_token=access_token)
client.invoices.query_invoice_metadata({...})
```

2) Przekazywanie `access_token` per-call (przydatne w przypadku obsługi wielu kontekstów):

```python
client.invoices.query_invoice_metadata({...}, access_token=access_token)
```
