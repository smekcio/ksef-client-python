# KSeF Python SDK – dokumentacja

Dokumentacja opisuje **publiczne API** biblioteki `ksef-client-python` (import: `ksef_client`) oraz scenariusze (workflow) wspierające typowe procesy: uwierzytelnianie, generowanie XML FA(3), sesje wysyłkowe (online/batch) i eksport faktur.

Opis kontraktu API (OpenAPI) oraz dokumenty procesowe i ograniczenia systemu znajdują się w repozytorium [`CIRFMF/ksef-api`](https://github.com/CIRFMF/ksef-api).

Kompatybilność SDK: **KSeF API `v2.9.0`**.

**Zacznij od [`Ksef` / `AsyncKsef`](getting-started.md#zalecany-start-ksef)**:
połącz się, wyślij XML i odbierz wynik przez `.wait()`.
[Przewodnik klienta](facade.md) pokazuje również batch, UPO, eksport na dysk
i wznowienie po przerwaniu.

Publiczny kontrakt SDK używa typowanych modeli `ksef_client.models`. Payloady requestów są
`typed-only`, a wiele metod klientów zwraca modele odpowiedzi zamiast surowych `dict`. Jeśli
migrujesz starszą integrację, zobacz [`migration-typed-model-api.md`](migration-typed-model-api.md).

Nowe API synchronizacji **metadanych**: [InvoiceSync / AsyncInvoiceSync](invoice-sync.md),
z niezależnym postępem ról i transakcyjnym przykładem SQLite.

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
pip install -e .[cli,xml,fa3,qr]
```

- `cli` – komenda `ksef` i zależności CLI (`typer`, `rich`, `keyring`)
- `xml` – podpis XAdES (`lxml`, `xmlsec`)
- `fa3` – walidacja XSD dla XML FA(3) (`lxml`)
- `qr` – generowanie PNG z kodami QR (`qrcode`, `pillow`)

Jeżeli pracujesz tylko z API Pythona, `pip install -e .` wystarcza. Do pracy z CLI użyj `pip install -e .[cli]`
albo pełnego zestawu extras.

## Struktura SDK

Wybierz sposób pracy:

- **Klient aplikacyjny (zalecany start)** – `Ksef` / `AsyncKsef` łączą logowanie, sesje, oczekiwanie i wznowienie operacji. Pełne SDK jest dostępne pod `client.api`.
- **Klient API** – `KsefClient` / `AsyncKsefClient` oraz podklienci (`.auth`, `.sessions`, …) odpowiadają endpointom KSeF; `AuthenticatedClient` / `AsyncAuthenticatedClient` dodają automatyczne wstrzykiwanie i odświeżanie tokena. Metody przyjmują typowane requesty z `ksef_client.models` i zwracają modele lub dane binarne.
- **Scenariusze (workflow)** – klasy z `ksef_client.services`, m.in. `AuthCoordinator`, `OnlineSessionWorkflow`, `BatchSessionWorkflow`, `ExportWorkflow`, pozwalają osobno składać kroki operacji API, szyfrowania i archiwizacji.
- **Dokumenty FA(3)** – moduł `ksef_client.documents.fa3` buduje faktury, serializuje XML i opcjonalnie waliduje XSD przed wysyłką online/batch.

Synchronizacja metadanych i XML: [trwała kolejka i gotowość dokumentów](invoice-xml-sync.md).

## Nawigacja

- [Fasada klienta, operacje `.wait()` i eksport strumieniowy](facade.md)
- [Historia wielu lat z jednym checkpointem](invoice-range-search.md)
- [Aktywne budżety limitów sync/async](rate-budgets.md)
- [Start](getting-started.md)
- [Migracja typed model API](migration-typed-model-api.md)
- [Konfiguracja klienta](configuration.md)
- [Błędy i retry](errors.md)
- [Retry HTTP (backoff i `Retry-After`)](retry.md)
- [Klient uwierzytelniony i auto-refresh tokena](token-manager.md)

**Referencja API (endpointy):**

- [`KsefClient` i `AsyncKsefClient`](api/client.md)
- [`client.auth`](api/auth.md)
- [`client.sessions`](api/sessions.md)
- [`client.invoices`](api/invoices.md)
- [`client.lighthouse`](api/lighthouse.md)
- [`client.permissions`](api/permissions.md)
- [`client.certificates`](api/certificates.md)
- [`client.collective_identifiers`](api/collective-identifiers.md)
- [`client.tokens`](api/tokens.md)
- [`client.limits`](api/limits.md)
- [`client.rate_limits`](api/rate-limits.md)
- [`client.security`](api/security.md)
- [`client.testdata`](api/testdata.md)
- [`client.peppol`](api/peppol.md)

**Workflows:**

- [Uwierzytelnianie](workflows/auth.md)
- [FA(3) SDK only](workflows/fa3.md)
- [Sesja interaktywna (online)](workflows/online-session.md)
- [Sesja wsadowa (batch)](workflows/batch-session.md)
- [Eksport (pobieranie paczek)](workflows/export.md)

**Konfiguracja i magazyny:**

- [Profile klienta (`ksef_client.profiles`)](profiles.md)
- [Magazyn certyfikatów (`ksef_client.certificates`)](certificate-store.md)

**Dokumenty FA(3):**

- [FA(3) SDK: klasy, metody i XSD](fa3-sdk.md)
- [Odczyt FA(3): XML → model](fa3-parsing.md)
- [Schematy XSD i dokumentacja MF (broszura FA(3), przykładowe pliki)](../src/ksef_client/documents/fa3/schemas/README.md)

**CLI:**

- [Specyfikacja `ksef` CLI](cli/README.md)

**Usługi / utils (zaawansowane, ale publiczne):**

- [Usługi (`ksef_client.services`)](services/README.md)
- [Utils (`ksef_client.utils`)](utils/README.md)

**Przykłady (skrypty):**

- [Przykłady](examples/README.md)


Zalecane API kompletnego pobierania: [paginacja z kursorami i checkpoint SQLite](reliable-pagination.md).
