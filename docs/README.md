# KSeF Python SDK – dokumentacja

Dokumentacja opisuje **publiczne API** biblioteki `ksef-client-python` (import: `ksef_client`) oraz scenariusze (workflow) wspierające typowe procesy: uwierzytelnianie, sesje wysyłkowe (online/batch) i eksport faktur.

Opis kontraktu API (OpenAPI) oraz dokumenty procesowe i ograniczenia systemu znajdują się w `ksef-docs/`.

Kompatybilność SDK: **KSeF API `v2.1.2`**.

## Wymagania

- Python `>= 3.10`
- Dostęp do środowiska KSeF (TEST/DEMO/PROD) i odpowiednie dane uwierzytelniające

## Instalacja (lokalnie)

W katalogu projektu:

```bash
pip install -e .
```

Opcjonalne dodatki (extras):

```bash
pip install -e .[xml,qr]
```

- `xml` – podpis XAdES (`lxml`, `xmlsec`)
- `qr` – generowanie PNG z kodami QR (`qrcode`, `pillow`)

## Struktura SDK

Biblioteka udostępnia dwa poziomy użycia:

1) **Klient API (cienka warstwa)** – `KsefClient` / `AsyncKsefClient` oraz podklienci (`.auth`, `.sessions`, …). Metody odpowiadają endpointom KSeF i zwracają głównie surowy JSON (`dict`).
2) **Scenariusze (workflow)** – klasy z `ksef_client.services`, m.in. `AuthCoordinator`, `OnlineSessionWorkflow`, `BatchSessionWorkflow`, `ExportWorkflow`. Warstwa workflow łączy kilka wywołań API z operacjami lokalnymi (szyfrowanie, ZIP) i porządkuje typowe przepływy.

## Nawigacja

- [Start](getting-started.md)
- [Konfiguracja klienta](configuration.md)
- [Błędy i retry](errors.md)

**Referencja API (endpointy):**

- [`KsefClient` i `AsyncKsefClient`](api/client.md)
- [`client.auth`](api/auth.md)
- [`client.sessions`](api/sessions.md)
- [`client.invoices`](api/invoices.md)
- [`client.lighthouse`](api/lighthouse.md)
- [`client.permissions`](api/permissions.md)
- [`client.certificates`](api/certificates.md)
- [`client.tokens`](api/tokens.md)
- [`client.limits`](api/limits.md)
- [`client.rate_limits`](api/rate-limits.md)
- [`client.security`](api/security.md)
- [`client.testdata`](api/testdata.md)
- [`client.peppol`](api/peppol.md)

**Workflows:**

- [Uwierzytelnianie](workflows/auth.md)
- [Sesja interaktywna (online)](workflows/online-session.md)
- [Sesja wsadowa (batch)](workflows/batch-session.md)
- [Eksport (pobieranie paczek)](workflows/export.md)

**CLI:**

- [Specyfikacja `ksef` CLI](cli/README.md)

**Usługi / utils (zaawansowane, ale publiczne):**

- [Usługi (`ksef_client.services`)](services/README.md)
- [Utils (`ksef_client.utils`)](utils/README.md)

**Przykłady (skrypty):**

- [Przykłady](examples/README.md)
