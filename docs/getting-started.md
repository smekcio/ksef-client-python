# Pierwsze kroki

## 1) Konfiguracja klienta

Konfiguracja opiera się o `base_url` (środowisko). Dla większości endpointów chronionych wymagany jest również `access_token`.

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment

options = KsefClientOptions(base_url=KsefEnvironment.DEMO.value)
client = KsefClient(options)
```

Zalecane jest użycie context managera, który zamyka połączenia HTTP:

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment

with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    ...
```

## 2) Uwierzytelnianie tokenem KSeF (pozyskanie `access_token`)

Typowy przebieg:
1) pobranie certyfikatów publicznych KSeF,
2) wybór certyfikatu o `usage = KsefTokenEncryption`,
3) uruchomienie workflow `AuthCoordinator`.

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment, models as m
from ksef_client.services import AuthCoordinator

with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    token_cert_pem = client.security.get_public_key_certificate_pem(
        m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
    )

    access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
        token="<TOKEN_KSEF>",
        public_certificate=token_cert_pem,
        context_identifier_type="nip",
        context_identifier_value="5265877635",
        max_attempts=90,
        poll_interval_seconds=2.0,
    ).access_token
```

## 2b) Klient z automatycznym odświeżaniem tokena

`AuthenticatedClient` wstrzykuje token do każdego żądania i odświeża go 60 s przed
wygaśnięciem — nie musisz przekazywać `access_token` do metod:

```python
from ksef_client import AuthenticatedClient
from ksef_client.services import AuthCoordinator

with KsefClient(options) as anonymous:
    auth_result = AuthCoordinator(anonymous.auth).authenticate_with_ksef_token(...)

with AuthenticatedClient.from_auth_result(options, auth_result) as client:
    invoice = client.invoices.get_invoice("<KSEF_NUMBER>")   # bez access_token
```

Szczegóły (refresh proaktywny/reaktywny, `on_refresh`, wariant async):
[token-manager.md](token-manager.md). Jeśli wolisz stare API, `access_token` w metodach
nadal działa i ma pierwszeństwo.

## 3) Pierwsze wywołanie API

`access_token` jest opcjonalny: przy `AuthenticatedClient` możesz go pominąć,
a przy zwykłym `KsefClient` przekazujesz go jawnie (tak jak dotychczas).

```python
metadata = client.invoices.query_invoice_metadata_by_date_range(
    subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
    date_type=m.InvoiceQueryDateType.ISSUE,
    date_from="...",
    date_to="...",
    access_token=access_token,
    page_size=10,
)
```

## 4) Wariant synchroniczny i asynchroniczny

Każdy podklient ma odpowiednik asynchroniczny:
- `KsefClient` – wywołania synchroniczne
- `AsyncKsefClient` – wywołania asynchroniczne (`await`)

```python
import asyncio
from ksef_client import AsyncKsefClient, KsefClientOptions, KsefEnvironment

async def main() -> None:
    async with AsyncKsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
        challenge = await client.auth.get_challenge()
        print(challenge)

asyncio.run(main())
```

## 5) Istotne zachowania API

- `POST /auth/token/redeem` jest **jednorazowe** dla danego `authenticationToken` (kolejne wywołanie → błąd 400).
- `POST /auth/token/refresh` wymaga przekazania refresh tokena w `Authorization: Bearer <refreshToken>` (metoda `refresh_access_token()` mapuje to poprawnie).
- Wysyłka partów w sesji wsadowej oraz pobieranie partów eksportu odbywają się **bez Bearer tokena** – są to pre-signed URL.
- `429 Too Many Requests` zawiera `Retry-After`, który powinien być respektowany (biblioteka zgłasza `KsefRateLimitError` z polem `retry_after`).
