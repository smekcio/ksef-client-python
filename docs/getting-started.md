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
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client.services import AuthCoordinator

with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    certs = client.security.get_public_key_certificates()
    token_cert_pem = next(
        c["certificate"]
        for c in certs
        if "KsefTokenEncryption" in (c.get("usage") or [])
    )

    result = AuthCoordinator(client.auth).authenticate_with_ksef_token(
        token="<TOKEN_KSEF>",
        public_certificate=token_cert_pem,
        context_identifier_type="nip",
        context_identifier_value="5265877635",
        max_attempts=90,
        poll_interval_seconds=2.0,
    )
    access_token = result.tokens.access_token.token
```

## 3) Pierwsze wywołanie API

```python
metadata = client.invoices.query_invoice_metadata(
    {"subjectType": "Subject1", "dateRange": {"dateType": "Issue", "from": "...", "to": "..."}},
    access_token=access_token,
    page_offset=0,
    page_size=10,
    sort_order="Asc",
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
