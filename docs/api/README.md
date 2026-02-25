# API (endpointy) – referencja

Ta część dokumentacji opisuje metody dostępne w podklientach `KsefClient` / `AsyncKsefClient`.

Metody stanowią cienką warstwę nad HTTP: wysyłają żądania i zwracają **surowy JSON** (zwykle `dict[str, Any]`). Wyjątki dotyczą endpointów zwracających treści binarne lub nietypowe nagłówki (np. `InvoicesClient.get_invoice()` → `InvoiceContent`).

Dla `AsyncKsefClient` zestaw metod jest taki sam – różni się tylko sposób wywołania (`await`).

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
