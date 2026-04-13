# API (endpointy) – referencja

Ta część dokumentacji opisuje metody dostępne w podklientach `KsefClient` / `AsyncKsefClient`.

Metody stanowią cienką warstwę nad HTTP: przyjmują typowane payloady z `ksef_client.models` tam, gdzie
endpoint oczekuje body JSON, a w wielu przypadkach zwracają modele odpowiedzi. Wyjątki dotyczą endpointów
zwracających treści binarne lub nietypowe nagłówki (np. `InvoicesClient.get_invoice()` → `InvoiceContent`).

Dla `AsyncKsefClient` zestaw metod jest taki sam – różni się tylko sposób wywołania (`await`).

Jeśli migrujesz starszy kod oparty o `dict`, zobacz [`../migration-typed-model-api.md`](../migration-typed-model-api.md).

## Strony

- [`KsefClient` i `AsyncKsefClient`](client.md)
- [`client.auth`](auth.md)
- [`client.sessions`](sessions.md)
- [`client.invoices`](invoices.md)
- [`client.lighthouse`](lighthouse.md)
- [`client.permissions`](permissions.md)
- [`client.certificates`](certificates.md)
- [`client.tokens`](tokens.md)
- [`client.limits`](limits.md)
- [`client.rate_limits`](rate-limits.md)
- [`client.security`](security.md)
- [`client.testdata`](testdata.md)
- [`client.peppol`](peppol.md)
