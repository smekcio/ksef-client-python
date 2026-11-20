# KSeF dla Pythona

[![Wersja na PyPI](https://img.shields.io/pypi/v/ksef-client)](https://pypi.org/project/ksef-client/)
[![Obsługiwane wersje Pythona](https://img.shields.io/pypi/pyversions/ksef-client)](https://pypi.org/project/ksef-client/)
[![Testy SDK](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml/badge.svg?branch=main)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml)

Wysyłaj faktury FA(3) do Krajowego Systemu e-Faktur, odbieraj urzędowe poświadczenia odbioru (UPO) i pobieraj faktury zakupowe do lokalnego archiwum. Pakiet **`ksef-client`** udostępnia bibliotekę dla Pythona 3.10+ oraz polecenie `ksef` do pracy w terminalu.

SDK obsługuje uwierzytelnianie, szyfrowanie faktur i oczekiwanie na odpowiedź KSeF. Synchronizacja archiwum zapisuje postęp. Po przerwaniu pracy możesz wznowić pobieranie od miejsca, w którym skończył poprzedni proces.

[Dokumentacja](https://github.com/smekcio/ksef-client-python/blob/main/docs/README.md) · [Przykłady w Pythonie](https://github.com/smekcio/ksef-client-python/blob/main/docs/examples/README.md) · [Polecenia CLI](https://github.com/smekcio/ksef-client-python/blob/main/docs/cli/README.md)

<a id="szybki-start-sdk"></a>

## Zacznij w Pythonie

```sh
python -m pip install ksef-client
```

Na początek odczytaj numer i kwotę faktury bez konta w KSeF. Zapisz przykładowy XML jako `faktura-demo.xml` w katalogu, z którego uruchamiasz Pythona. [Pobierz fakturę FA(3)](https://raw.githubusercontent.com/smekcio/ksef-client-python/ba7beccf318acd231d387f94cb54bf9156b6bae7/docs/examples/faktura-demo.xml)

```python
from pathlib import Path

from ksef_client.documents.fa3 import parse_invoice_xml

faktura = parse_invoice_xml(Path("faktura-demo.xml").read_bytes())
print(faktura.invoice_number, faktura.total_gross, faktura.currency)
```

Dla przykładowej faktury otrzymasz kwotę brutto w złotych.

```text
DEMO/001 123.00 PLN
```

<a id="szybki-start-cli"></a>

## Zacznij w terminalu

```sh
python -m pip install "ksef-client[cli]"
ksef lighthouse status
```

Bez profilu i tokena polecenie pokaże status **testowej Latarni KSeF** oraz opublikowane komunikaty. Do pracy z fakturami skonfiguruj profil firmy i zaloguj się tokenem KSeF lub certyfikatem. [Konfiguracja profilu i logowanie](https://github.com/smekcio/ksef-client-python/blob/main/docs/cli/README.md)

## Wyślij fakturę i odbierz numer KSeF

Przygotuj XML FA(3) z NIP-em sprzedawcy, w którego imieniu występujesz, i zapisz go jako `faktura.xml`. Ustaw zmienne środowiskowe `KSEF_NIP` i `KSEF_TOKEN` dla środowiska **TEST**. Token musi pozwalać na wystawianie faktur w tym kontekście.

```python
import os
from pathlib import Path

from ksef_client import Ksef, KsefClientOptions, KsefEnvironment, TokenCredentials

with Ksef.connect(
    options=KsefClientOptions(base_url=KsefEnvironment.TEST.value),
    context_type="Nip",
    context_value=os.environ["KSEF_NIP"],
    credentials=TokenCredentials(os.environ["KSEF_TOKEN"]),
) as client:
    with client.online_session() as session:
        invoice = session.send_invoice(Path("faktura.xml").read_bytes()).wait(timeout=120)
    session.wait(timeout=120)
    print(invoice.ksef_number)
```

Po przyjęciu faktury przez KSeF zobaczysz jej numer. Aby pobrać UPO lub wysłać kilka faktur w jednej sesji, skorzystaj z [przewodnika wysyłki online](https://github.com/smekcio/ksef-client-python/blob/main/docs/workflows/online-session.md). Jeśli aplikacja korzysta z `asyncio`, ten sam przebieg obsługuje [klient `AsyncKsef`](https://github.com/smekcio/ksef-client-python/blob/main/docs/facade.md).

<a id="synchronizacja-metadanych-i-xml"></a>

## Pobieraj faktury zakupowe

Poniższy skrypt pobiera faktury w roli nabywcy (`Subject2`). Zapisuje pliki XML na dysku, a postęp w SQLite. Uruchamiaj go ponownie z tym samym katalogiem i kluczem synchronizacji. SDK sprawdzi, które dokumenty już zapisało.

<details>
<summary>Pokaż przykład synchronizacji w środowisku TEST</summary>

Użyj zmiennych `KSEF_NIP` i `KSEF_TOKEN` dla nabywcy z uprawnieniem do odczytu faktur. Wybierz datę rozpoczęcia importu i prywatny katalog dla danych firmy.

```python
import os

from ksef_client import (
    FileInvoiceXmlStore, Ksef, KsefClientOptions, KsefEnvironment,
    SQLiteInvoiceSyncStore, TokenCredentials,
)

with Ksef.connect(
    options=KsefClientOptions(base_url=KsefEnvironment.TEST.value),
    context_type="Nip",
    context_value=os.environ["KSEF_NIP"],
    credentials=TokenCredentials(os.environ["KSEF_TOKEN"]),
) as client:
    with FileInvoiceXmlStore("private/xml") as storage, SQLiteInvoiceSyncStore.open(
        "private/invoices.db", enqueue_xml=True, xml_storage_id=storage.storage_id,
    ) as store:
        sync = client.invoices.sync_documents(
            namespace="firma", sync_key="zakupy", since="2025-01-01T00:00:00Z",
            subject_types=("Subject2",),
        )
        report = sync.run_once(store, storage, time_budget=600)
        print(report.xml.ready, report.complete)
```

</details>

Pole `report.xml.ready` podaje liczbę gotowych dokumentów. Jeśli `report.complete` ma wartość `False`, zajrzyj do `report.to_dict()`, aby sprawdzić, co pozostało do pobrania. [Archiwum XML i wznawianie synchronizacji](https://github.com/smekcio/ksef-client-python/blob/main/docs/invoice-xml-sync.md)

## Walidacja, uprawnienia i śledzenie faktur

Poniższe funkcje dodano po wydaniu **0.25.0**. Jeśli używasz tej wersji z PyPI, możesz wypróbować je w lokalnej kopii repozytorium. W jego głównym katalogu uruchom poniższe polecenia.

```sh
python -m pip install -e ".[cli,fa3,pdf]"
ksef invoice validate docs/examples/faktura-demo.xml
```

| Chcę… | Jak to zrobić |
| --- | --- |
| Sprawdzić XML przed wysyłką | `ksef invoice validate` sprawdza strukturę FA(3) i reguły obsługiwane przez SDK. Dla błędnego dokumentu raport wskazuje pole i, gdy to możliwe, numer wiersza. Walidacja odbywa się lokalnie. [Walidacja FA(3)](https://github.com/smekcio/ksef-client-python/blob/main/docs/cli/README.md#ksef-invoice-validate) |
| Wrócić po wynik po restarcie aplikacji | Przy wysyłce podaj własny identyfikator, np. `FV-123`. Po ponownym uruchomieniu sprawdź stan pod tym samym ID. Polecenie `ksef online bundle` zapisze oryginalny XML, podgląd PDF i dostępne indywidualne UPO w jednym ZIP-ie. [Wysyłka i odbiór po własnym ID](https://github.com/smekcio/ksef-client-python/blob/main/docs/workflows/cli-operations.md) |
| Sprawdzić uprawnienia do sprzedaży lub zakupów | `ksef health permissions` pobiera nadania dla bieżącego kontekstu logowania. Opcja `--for` pozwala sprawdzić wybraną operację. [Diagnostyka uprawnień](https://github.com/smekcio/ksef-client-python/blob/main/docs/cli/README.md#ksef-health-permissions) |
| Przetworzyć pobrane faktury zakupowe | Polecenie `ksef archive next` pobiera dokument z lokalnego archiwum. Po zapisaniu wyniku w swojej aplikacji potwierdź przetworzenie przez `ksef archive ack`. [Odbiór faktur krok po kroku](https://github.com/smekcio/ksef-client-python/blob/main/docs/incoming-invoice-delivery.md) |

## Podgląd PDF faktur i UPO

Wersja rozwojowa zawiera oficjalny generator CIRFMF 1.1.48 dla FA(3) i UPO 4.2/4.3.
Po instalacji z repozytorium przez `python -m pip install -e ".[cli]"` i zapewnieniu Node.js 22 lub nowszego
możesz wyrenderować zapisane XML-e lokalnie.

```sh
ksef invoice render faktura.xml --out faktura.pdf
ksef upo render upo.xml --out upo.pdf
ksef online bundle --id FV-123 --state-dir ./private --pdf-renderer mf --out FV-123-mf.zip
```

API Pythona udostępnia także konteksty do QR online i offline. Pakiet MF zawiera XML faktury,
jej PDF i dostępne indywidualne UPO w obu formatach. [Wizualizacja i przykłady integracji](https://github.com/smekcio/ksef-client-python/blob/main/docs/invoice-bundle-pdf.md)

## Dalsza integracja

- **Duża liczba faktur.** Wysyłaj faktury w [sesji wsadowej](https://github.com/smekcio/ksef-client-python/blob/main/docs/workflows/batch-session.md) lub pobieraj je przez [wznawialny eksport na dysk](https://github.com/smekcio/ksef-client-python/blob/main/docs/workflows/export.md).
- **Praca offline.** Zapisz faktury w szyfrowanej kolejce, przygotuj dane do kodów QR i wznów wysyłkę po przywróceniu łączności. [Tryb offline](https://github.com/smekcio/ksef-client-python/blob/main/docs/workflows/online-session.md#trwała-wysyłka-offline)
- **Integracja z własną aplikacją.** Twórz faktury i korekty w Pythonie, korzystaj z typowanych metod API i kontroluj liczbę żądań wysyłanych do KSeF. [Tworzenie FA(3)](https://github.com/smekcio/ksef-client-python/blob/main/docs/fa3-sdk.md) · [Referencja API](https://github.com/smekcio/ksef-client-python/blob/main/docs/api/README.md) · [Limity żądań](https://github.com/smekcio/ksef-client-python/blob/main/docs/rate-budgets.md)

## Zgodność i testy

SDK obsługuje KSeF API `v2.10.0` w środowisku TEST oraz wersję 2.9.0 w DEMO i PROD. W CI sprawdzamy zgodność modeli ze specyfikacją, instalację pakietu oraz działanie SDK na obsługiwanych wersjach Pythona. Osobne testy integracyjne korzystają ze środowisk TEST i DEMO. [Zgodność ze specyfikacją](https://github.com/smekcio/ksef-client-python/actions/workflows/validate-models.yml) · [Testy integracyjne](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml) · [Historia wydań](https://github.com/smekcio/ksef-client-python/releases) · [Licencja MIT](https://github.com/smekcio/ksef-client-python/blob/main/LICENSE)
