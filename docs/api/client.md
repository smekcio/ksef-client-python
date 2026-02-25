# Klient główny (`KsefClient`, `AsyncKsefClient`)

## Zakres

`KsefClient` (sync) i `AsyncKsefClient` (async) grupują podklientów domenowych:

- `client.auth`
- `client.sessions`
- `client.invoices`
- `client.lighthouse`
- `client.permissions`
- `client.certificates`
- `client.tokens`
- `client.limits`
- `client.rate_limits`
- `client.security`
- `client.testdata`
- `client.peppol`

## Inicjalizacja

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment

with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    ...
```

Wariant asynchroniczny:

```python
import asyncio
from ksef_client import AsyncKsefClient, KsefClientOptions, KsefEnvironment

async def main() -> None:
    async with AsyncKsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
        ...

asyncio.run(main())
```

## Token (`access_token`)

Token może zostać przekazany na dwa sposoby:

- w konstruktorze: `KsefClient(options, access_token=...)`
- per-call: `client.invoices.query_invoice_metadata(..., access_token=...)`

Wariant per-call jest preferowany w przypadku obsługi wielu kontekstów.

## Zamykanie połączeń

- `KsefClient.close()` – zamyka wewnętrznego `httpx.Client`
- `AsyncKsefClient.aclose()` – zamyka `httpx.AsyncClient`

Zalecane jest użycie context managera (`with` / `async with`), który zapewnia zamknięcie połączeń HTTP.

## `http_client` (zaawansowane)

`client.http_client` udostępnia obiekt transportowy używany przez SDK.

Typowe zastosowania:
- wywołania na pre-signed URL (wysyłka/pobieranie partów) poza podklientami domenowymi
- diagnostyka (np. podgląd nagłówków odpowiedzi)

W typowych scenariuszach zamiast tego stosowane są:
- `BatchUploadHelper` / `ExportDownloadHelper` (z `ksef_client.services`)
- albo gotowych workflow (`BatchSessionWorkflow`, `ExportWorkflow`)
