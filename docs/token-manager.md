# Klient uwierzytelniony i auto-refresh tokena

`AuthenticatedClient` (oraz `AsyncAuthenticatedClient`) to klient KSeF, który sam
wstrzykuje token dostępowy do każdego żądania i odświeża go, zanim wygaśnie. Dzięki
temu **`access_token` nie jest już wymagany w żadnej metodzie** — podajesz go tylko
raz, przy tworzeniu klienta (albo wcale, jeśli używasz managera).

Dotychczasowy sposób pracy (`KsefClient(options, access_token=...)` i jawne
`access_token=...` w metodach) działa bez zmian.

## Szybki start

```python
from ksef_client import (
    AuthenticatedClient,
    KsefClient,
    KsefClientOptions,
    KsefEnvironment,
    models as m,
)
from ksef_client.services import AuthCoordinator

options = KsefClientOptions(base_url=KsefEnvironment.DEMO.value)

with KsefClient(options) as anon:
    cert_pem = anon.security.get_public_key_certificate_pem(
        m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION
    )
    auth_result = AuthCoordinator(anon.auth).authenticate_with_ksef_token(
        token="<TOKEN_KSEF>",
        public_certificate=cert_pem,
        context_identifier_type="nip",
        context_identifier_value="5265877635",
    )

with AuthenticatedClient.from_auth_result(options, auth_result) as client:
    page = client.invoices.query_invoice_metadata_by_date_range(   # bez access_token
        subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
        date_type=m.InvoiceQueryDateType.ISSUE,
        date_from="2026-01-01T00:00:00Z",
        date_to="2026-01-31T23:59:59Z",
    )
```

## `TokenManager`

Manager trzyma token dostępowy, token odświeżający i datę ważności. Można go zbudować
z wyniku uwierzytelnienia (`from_auth_result`), z odpowiedzi `/auth/token/redeem`
(`from_tokens`) albo z samych wartości:

```python
from ksef_client import TokenManager

manager = TokenManager(
    access_token="<ACCESS>",
    refresh_token="<REFRESH>",
    access_token_valid_until="2026-10-22T13:00:00+00:00",
)
client = AuthenticatedClient(options, manager)
```

### Kiedy następuje refresh?

* **Proaktywnie** — gdy do wygaśnięcia zostało mniej niż `refresh_margin_seconds`
  (domyślnie 60 s), token jest odświeżany **przed** wysłaniem żądania.
* **Reaktywnie** — odpowiedź 401 na żądanie z tokenem managera powoduje jedno
  odświeżenie i powtórzenie żądania; kolejny 401 trafia do wołającego.
* **Bez informacji o ważności** (`valid_until = None`) działa wyłącznie tryb reaktywny —
  SDK nie zgaduje, kiedy token wygaśnie.

### Współbieżność

Refresh odbywa się pod lockiem z podwójnym sprawdzeniem: przy dwóch równoległych
żądaniach wykonywany jest **jeden** refresh, a oba żądania dostają nowy token.
`TokenManager` używa `threading.Lock`, `AsyncTokenManager` — `asyncio.Lock`.

### Zapis nowego tokena

Po udanym odświeżeniu możesz zapisać token (np. do keyringa) przez `on_refresh`:

```python
def persist(info):                     # info: TokenInfo (token + valid_until)
    keyring.set_password("ksef", "access_token", info.token)

client = AuthenticatedClient.from_auth_result(options, auth_result, on_refresh=persist)
```

Wyjątek z callbacku propaguje do wołającego — jeśli zapis może zawieść, obsłuż go
wewnątrz callbacku.

Callbacki zapisu są wykonywane kolejno, również przy równoległych odświeżeniach.
Opóźniony callback jest pomijany, jeśli przed jego rozpoczęciem token został już
zastąpiony nowszym. Callback może odczytać stan managera (np. `snapshot()` albo
`get_access_token()`, gdy token jest ważny), ale **nie może zainicjować kolejnego
odświeżenia** — `force_refresh()` albo refresh wywołany z callbacku kończy się
natychmiast `TokenManagerError` zamiast zakleszczenia.

### Podgląd stanu bez sekretów

```python
snapshot = manager.snapshot()
snapshot.has_refresh_token          # bool
snapshot.access_token_expires_at    # datetime | None (UTC)
```

`TokenManager` nie zawiera wartości tokenów w `repr` — można go bezpiecznie logować.

## Wariant asynchroniczny

```python
from ksef_client import AsyncAuthenticatedClient, AsyncTokenManager

manager = AsyncTokenManager.from_tokens(auth_result.tokens, on_refresh=persist_async)
async with AsyncAuthenticatedClient(options, manager) as client:
    await client.invoices.get_invoice("...")     # bez access_token
```

`AsyncTokenManager` przyjmuje handler i callback sync albo async.

## Priorytety tokenów

1. Jawne `access_token=...` w metodzie — zawsze wygrywa (dotychczasowe zachowanie).
2. Jawne `refresh_token=...` — używane przez endpoint `/auth/token/refresh`.
3. Token z `TokenManager` — gdy powyższe nie zostały podane i `skip_auth=False`.
4. `skip_auth=True` (pre-signed URL) — **nigdy** nie dostaje nagłówka `Authorization`.

## Ograniczenia

* Endpoint `/auth/token/refresh` zwraca **tylko nowy token dostępowy** — token
  odświeżający pozostaje ten sam. Gdy wygaśnie, trzeba zalogować się ponownie.
* `refresh_margin_seconds` dotyczy tylko tokenów z datą ważności; przy jej braku
  działa wyłącznie retry po 401.
* `TokenManager` nie jest wspólny między procesami — każdy proces ma własny stan.
* `bind_auth_client` **nie nadpisuje własnego** `refresh_handler` podanego
  w konstruktorze; handler podłączony automatycznie jest zastępowany przy ponownym
  bindowaniu, więc manager można przenieść do nowego klienta. Jeśli klient został
  zamknięty, a manager nie został przebindowany, refresh może się nie udać.
* `AsyncTokenManager` używaj w jednej pętli zdarzeń (jak większość obiektów asyncio).

## Zobacz też

- [Retry HTTP](retry.md) — ponawianie 429/502/503/504,
- [`KsefClient`](api/client.md), [`client.auth`](api/auth.md).
