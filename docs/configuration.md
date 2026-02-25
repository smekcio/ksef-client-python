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
    base_qr_url=None,
    base_lighthouse_url=None,
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

Istotne: dla operacji wysyłki i pobierania partów KSeF zwraca wymagane nagłówki. W tych wywołaniach biblioteka używa `skip_auth=True`, ale `custom_headers` nadal są scalane z nagłówkami żądania. Ustawianie `Authorization` w `custom_headers` jest niewskazane, ponieważ dla pre-signed URL może powodować błędy autoryzacji.

### `follow_redirects`

Opcja zwykle nie jest potrzebna. Włączenie ma uzasadnienie wyłącznie w środowiskach, w których infrastruktura wymusza przekierowania.

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
