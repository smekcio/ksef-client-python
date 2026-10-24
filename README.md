# KSeF Client Python

[![CI](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml/badge.svg)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml)
[![PyPI - License](https://img.shields.io/pypi/l/ksef-client)](https://github.com/smekcio/ksef-client-python/blob/main/LICENSE)
[![PyPI - Version](https://img.shields.io/pypi/v/ksef-client)](https://pypi.org/project/ksef-client/)

**KSeF Client Python** to SDK i narzędzia CLI dla integracji z Krajowym Systemem e-Faktur.
Pakiet jest publikowany na PyPI jako **`ksef-client`** i obsługuje aktualny kontrakt
**KSeF API `v2.9.0`** ([changelog API](https://github.com/CIRFMF/ksef-api/blob/main/api-changelog.md#wersja-290)).

Biblioteka pomaga integrować aplikacje napisane w Pythonie z KSeF bez ręcznego
składania żądań HTTP, szyfrowania, podpisów, obsługi sesji i pobierania paczek faktur.

Najważniejsze cechy:

- **typowane modele** `ksef_client.models` dla publicznych żądań i odpowiedzi SDK,
- **klient synchroniczny i asynchroniczny**: `KsefClient` oraz `AsyncKsefClient`,
- **CLI `ksef`** do konfiguracji, diagnostyki, uwierzytelniania, wysyłki i pobierania faktur,
- **profile i magazyn certyfikatów w SDK** — te same dane co CLI, bez zależności od `typer`/`keyring`,
- **kompletne pobieranie metadanych faktur** — `search_invoice_metadata()` w wersji sync i async,
  z paginacją, trwałymi kursorami, deduplikacją granic i kontrolą HWM,
- **automatyczne odświeżanie tokena** — `AuthenticatedClient`/`TokenManager` (sync i async):
  token wstrzykiwany do żądań, refresh 60 s przed wygaśnięciem i po 401,
- **retry HTTP** — `RetryConfig` (429/502/503/504, backoff z jitterem, `Retry-After`),
- **taksonomia błędów** — `KsefError`/`ErrorCode`, `KsefExceptionCode` (54 kody KSeF),
  błędy dokumentów i `to_dict()` dla CLI/MCP,
- **uwierzytelnianie tokenem KSeF i XAdES**, w tym obsługa PKCS#12 oraz PEM,
- **sesje online i wsadowe**, eksport faktur, UPO, linki weryfikacyjne, QR i Latarnia KSeF,
- **FA(3)**: budowanie XML faktur, walidacja XSD, przygotowanie paczek ZIP/TarGz oraz **odczyt XML → model**,
- narzędzia pomocnicze do szyfrowania, ZIP/TarGz, Base64Url i obsługi adresów pre-signed URL.

## 🧭 Spis treści

- [Kiedy użyć tej biblioteki](#kiedy-użyć-tej-biblioteki)
- [Instalacja](#instalacja)
- [Szybki start: CLI](#szybki-start-cli)
- [Szybki start: SDK](#szybki-start-sdk)
- [FA(3) SDK](#fa3-sdk)
- [Najważniejsze możliwości](#najważniejsze-możliwości)
- [Dokumentacja](#dokumentacja)
- [Jakość i rozwój](#jakość-i-rozwój)
- [Kontrybucja](#kontrybucja)

## ✅ Kiedy użyć tej biblioteki

Użyj `ksef-client`, jeżeli potrzebujesz:

- zbudować integrację z KSeF API w aplikacji napisanej w Pythonie,
- szybko sprawdzić konfigurację środowiska KSeF z terminala,
- obsłużyć pełny przepływ uwierzytelnienia, wysyłki faktury i pobrania UPO,
- pracować na typowanych modelach żądań i odpowiedzi,
- zautomatyzować odświeżanie tokena i ponawianie przejściowych błędów HTTP,
- korzystać z gotowych scenariuszy dla sesji online, sesji wsadowych i eksportu faktur,
- przygotowywać XML FA(3) programistycznie i walidować go z oficjalnym XSD,
- testować integrację w środowiskach TEST/DEMO przed przejściem na PROD.

Publiczny kontrakt SDK korzysta z modeli `ksef_client.models.*`.
Typy żądań, odpowiedzi i parametrów opisuje [referencja API](docs/api/README.md).

## 📦 Instalacja

Wymagany Python: **`>= 3.10`**.

Podstawowe SDK:

```bash
pip install ksef-client
```

SDK z interfejsem CLI:

```bash
pip install "ksef-client[cli]"
```

Pełniejszy zestaw z obsługą XAdES, FA(3), QR i CLI:

```bash
pip install "ksef-client[xml,fa3,qr,cli]"
```

Dodatki opcjonalne:

- `cli` — komenda `ksef` oraz zależności `typer`, `rich`, `keyring`,
- `xml` — podpis XAdES przez `lxml` i `xmlsec`,
- `fa3` — walidacja XSD dla XML FA(3) przez `lxml`,
- `qr` — generowanie kodów QR w PNG przez `qrcode` i `pillow`.

Po instalacji samego `ksef-client` SDK jest gotowe do użycia w kodzie. Jeżeli uruchomisz wtedy
komendę `ksef`, otrzymasz instrukcję doinstalowania dodatku `cli`.

## 🚀 Szybki start: CLI

CLI jest najkrótszą ścieżką do sprawdzenia profilu, uwierzytelnienia i podstawowych operacji bez pisania kodu.

```bash
pip install "ksef-client[cli]"
```

1. Utwórz profil i ustaw go jako aktywny:

```bash
ksef init --non-interactive --name demo --env DEMO --context-type nip --context-value <NIP> --set-active
```

2. Zaloguj się tokenem KSeF i sprawdź stan sesji:

```bash
ksef auth login-token --ksef-token <KSEF_TOKEN>
ksef auth status
ksef profile show
```

Alternatywnie możesz zalogować się certyfikatem XAdES:

```bash
ksef auth login-xades --pkcs12-path ./cert.p12 --pkcs12-password <HASLO_CERTYFIKATU>
ksef auth status
```

3. Wykonaj pierwsze operacje:

```bash
ksef invoice list --from 2026-01-01 --to 2026-01-31
ksef send online --invoice ./fa.xml --wait-upo --save-upo ./out/upo-online.xml
ksef invoice download --ksef-number <KSEF_NUMBER> --out ./out/
```

Najczęściej używane grupy komend:

- konfiguracja profili: `init`, `profile ...`,
- uwierzytelnianie: `auth login-token`, `auth login-xades`, `auth status`, `auth refresh`, `auth revoke-self-token`, `auth logout`,
- faktury i sesje: `invoice ...`, `send ...`, `upo ...`, `export ...`,
- diagnostyka: `health check`,
- Latarnia KSeF: `lighthouse status`, `lighthouse messages`.

Komendy Latarni są publiczne i działają bez logowania. Jeżeli nie masz aktywnego profilu, CLI używa domyślnie
środowiska testowego Latarni.

Pełna specyfikacja CLI: [`docs/cli/README.md`](docs/cli/README.md).

## 🧩 Szybki start: SDK

Najkrótsza droga: uwierzytelnij się raz, a `AuthenticatedClient` sam wstrzykuje
i odświeża token dostępowy (60 s przed wygaśnięciem i po 401). Retry HTTP włączasz
jednym polem konfiguracji:

```python
from ksef_client import (
    AuthenticatedClient,
    KsefClient,
    KsefClientOptions,
    KsefEnvironment,
    RetryConfig,
    models as m,
)
from ksef_client.services import AuthCoordinator

options = KsefClientOptions(
    base_url=KsefEnvironment.DEMO.value,
    retry=RetryConfig(
        retryable_post_paths=frozenset({"/invoices/query/metadata"}),
    ),                           # 429/502/503/504 + Retry-After
)

with KsefClient(options) as anonymous:
    certificate = anonymous.security.get_public_key_certificate_pem(
        m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
    )
    auth_result = AuthCoordinator(anonymous.auth).authenticate_with_ksef_token(
        token="<TOKEN_KSEF>",
        public_certificate=certificate,
        context_identifier_type="nip",
        context_identifier_value="5265877635",
    )

with AuthenticatedClient.from_auth_result(options, auth_result) as client:
    filters = m.InvoiceQueryFilters(
        subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
        date_range=m.InvoiceQueryDateRange(
            date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
            from_="2026-01-01T00:00:00Z",
            to="2026-01-31T23:59:59Z",
            restrict_to_permanent_storage_hwm_date=True,
        ),
    )
    search = client.invoices.search_invoice_metadata(
        filters,
        context_key="Nip:5265877635",
        page_size=100,
        sort_order="Asc",
    )
    invoice_count = sum(1 for invoice in search)  # odczyt wszystkich stron do HWM

print(f"Liczba faktur: {invoice_count}")
```

Szczegóły: [token-manager.md](docs/token-manager.md), [retry.md](docs/retry.md).

### 🔎 Odczyt faktury FA(3) (XML → model)

Dokument pobrany z KSeF można odczytać do tego samego modelu, którego używają buildery:

```python
from ksef_client.documents.fa3 import FA3Invoice, parse_invoice_xml

content = client.invoices.get_invoice_bytes(ksef_number)
invoice = parse_invoice_xml(content.content)

print(invoice.invoice_number, invoice.total_gross)
for line in invoice.lines:
    print(line.description, line.effective_net_amount)
for warning in invoice.warnings:  # elementy spoza modelu — nigdy po cichu
    print(warning.message)

assert FA3Invoice.from_xml(content.content).to_xml()  # roundtrip
```

Szczegóły i granice (zaliczki, marża, daty): [`docs/fa3-parsing.md`](docs/fa3-parsing.md).

### 📄 Paginacja metadanych faktur

`search_invoice_metadata()` pobiera kolejne strony i kontynuuje po obcięciu wyników.
Obiekt wyszukiwania jest leniwy: żądanie HTTP następuje podczas odczytu strony lub iteracji.
Możesz przetwarzać pojedyncze faktury przez `for invoice in search` albo pracować na stronach
i zapisywać checkpoint po każdej z nich.

Poniższy fragment korzysta z `options`, `auth_result` i `filters` z szybkiego startu:

```python
cursor = None  # Przy wznowieniu odczytaj kursor zapisany przez aplikację.

with AuthenticatedClient.from_auth_result(options, auth_result) as client:
    search = client.invoices.search_invoice_metadata(
        filters, context_key="Nip:5265877635", page_size=100, sort_order="Asc",
    )
    page = search.page(cursor=cursor)
    for invoice in page.items:
        print(invoice.ksef_number)
    next_cursor = page.next_cursor
```

Zapisuj `page.items` i `page.next_cursor` w jednej transakcji. Kursor pozwala odtworzyć
wyszukiwanie po restarcie z tymi samymi filtrami, kontekstem, środowiskiem i rozmiarem strony.
`next_cursor=None` potwierdza koniec odczytu; osobny znacznik ukończenia odróżnia go od
pierwszego uruchomienia. `pages(cursor=...)` i `items(cursor=...)` obsługują dalszą iterację.
Wersja async udostępnia `await search.page(...)` oraz `async for`.

Stabilny zbiór zapewnia `PermanentStorage` z ograniczeniem HWM. Wynik jest kompletny do
granicy `page.permanent_storage_hwm_date`, która może poprzedzać żądaną datę końcową.
Jeśli SDK nie może potwierdzić kompletności, zgłasza `KsefIncompletePaginationError`.
Kursory zawierają dane zapytania — przechowuj je prywatnie i nie umieszczaj ich w logach.

Gotowy przykład transakcyjnego zapisu faktur i checkpointu:
[`invoice_checkpoint_sqlite.py`](docs/examples/invoice_checkpoint_sqlite.py).
Szczegóły API sync/async i gwarancji: [paginacja z kursorami](docs/reliable-pagination.md).

### 🔐 Diagnostyka i sekrety

Do diagnostyki używaj `repr()` modeli i `ksef_client.redact_sensitive(value)`.
Ukrywają znane pola z tokenami, kluczami, podpisanymi adresami i payloadami.
`to_dict()` i `to_json()` służą do transportu i zapisu stanu, mogą więc zawierać sekrety.

### 🗂️ Profile i certyfikaty poza CLI

SDK czyta te same profile, które zapisuje `ksef init`, i potrafi przechować parę
certyfikat + klucz:

```python
from ksef_client import KsefClient, KsefClientOptions
from ksef_client.certificates import FileCertificateStore
from ksef_client.profiles import ProfileStore

client = KsefClient(KsefClientOptions.from_profile("demo"))

store = FileCertificateStore.default()
store.save("prod-2026", certificate=cert_pem, private_key=key_pem, environment="PROD")
certificate, private_key = store.load("prod-2026").key_pair()
```

Bez dodatku `cli` i bez nowych zależności. Opis: [`docs/profiles.md`](docs/profiles.md),
[`docs/certificate-store.md`](docs/certificate-store.md).

### 📤 Wysyłka faktury w sesji online

Do wysyłki faktur używaj scenariusza `OnlineSessionWorkflow`. Aktualny model pracy to:
`open_session() -> session.send_invoice() -> session.close()`.

Poniższy fragment zakłada, że jesteś wewnątrz bloku `with ... as client:` z szybkiego startu.

```python
from pathlib import Path

from ksef_client import models as m
from ksef_client.services import OnlineSessionWorkflow

invoice_xml = Path("./fa.xml").read_bytes()

symmetric_cert_pem = client.security.get_public_key_certificate_pem(
    m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION,
)

workflow = OnlineSessionWorkflow(client.sessions)
session = workflow.open_session(
    form_code=m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA"),
    public_certificate=symmetric_cert_pem,
)

send_result = session.send_invoice(invoice_xml)
session.close()

print(send_result.reference_number)
```

Pełne, uruchamialne przykłady znajdują się w [`docs/examples/`](docs/examples/README.md).

## 🧾 FA(3) SDK

Warstwa `ksef_client.documents.fa3` służy do programistycznego przygotowania faktur FA(3) przed wysyłką do KSeF. Zakres tej warstwy obejmuje:

- typed buildery dla faktur podstawowych, korekt, zaliczek i rozliczeń zaliczek,
- prostsze drafty `FA3Draft` / `FA3BatchDraft` przydatne dla integracji JSON i generowania ZIP,
- serializację do XML oraz opcjonalną walidację XSD przez `to_xml(xsd_validate=True)`,
- przygotowanie XML do sesji online i paczek ZIP do sesji wsadowych.

Walidacja XSD używa dodatku `fa3` (`pip install "ksef-client[fa3]"` albo lokalnie `pip install -e .[fa3]`).

Szczegóły: [`docs/fa3-sdk.md`](docs/fa3-sdk.md) oraz [`docs/workflows/fa3.md`](docs/workflows/fa3.md).

Przykłady uruchomieniowe:

- [`docs/examples/fa3_single_invoice_sdk.py`](docs/examples/fa3_single_invoice_sdk.py) — pojedyncza faktura FA(3) do XML,
- [`docs/examples/fa3_batch_zip_sdk.py`](docs/examples/fa3_batch_zip_sdk.py) — wiele faktur FA(3) do ZIP,
- [`docs/examples/fa3_correction_settlement_sdk.py`](docs/examples/fa3_correction_settlement_sdk.py) — korekta i rozliczenie zaliczki,
- [`docs/examples/fa3_json_roundtrip_sdk.py`](docs/examples/fa3_json_roundtrip_sdk.py) — JSON draft → ZIP XML.

## 🧰 Najważniejsze możliwości

| Obszar | Co dostajesz |
| --- | --- |
| Klienci API | `KsefClient`, `AsyncKsefClient` i podklienci mapujący endpointy KSeF. |
| Modele | Typowane modele żądań i odpowiedzi w `ksef_client.models`. |
| Uwierzytelnianie | Token KSeF, XAdES, odświeżanie tokenów i unieważnianie bieżącego tokena. |
| Sesje | Sesje online i wsadowe, obsługa ZIP, części, szyfrowania i zamykania sesji. |
| Faktury | Wyszukiwanie metadanych z pełną paginacją, kursorami i HWM (sync/async), pobieranie faktur, eksport paczek i narzędzia do ich przetwarzania. |
| FA(3) | Buildery, drafty, XML, walidacja XSD, **odczyt XML → model** i ZIP do sesji wsadowych. |
| Konfiguracja | Profile klienta wspólne z CLI oraz magazyn certyfikatów XAdES (`0600`). |
| UPO | Sprawdzanie statusów i pobieranie urzędowego poświadczenia odbioru. |
| CLI | Operacje administracyjne i diagnostyczne bez pisania kodu. |
| Latarnia | Publiczny status dostępności KSeF i komunikaty serwisowe. |
| QR i linki | Linki weryfikacyjne, podpisy i generowanie kodów QR. |

## 📚 Dokumentacja

Główna dokumentacja znajduje się w katalogu [`docs/`](docs/README.md):

- [pierwsze kroki](docs/getting-started.md),
- [konfiguracja klienta](docs/configuration.md),
- [błędy, retry i limity](docs/errors.md),
- [automatyczne odświeżanie tokena i klient uwierzytelniony](docs/token-manager.md),
- [retry HTTP (backoff, `Retry-After`)](docs/retry.md),
- [paginacja z kursorami, HWM i checkpoint SQLite](docs/reliable-pagination.md),
- [referencja API](docs/api/README.md),
- [profile klienta](docs/profiles.md),
- [magazyn certyfikatów](docs/certificate-store.md),
- [scenariusze sesji i eksportu](docs/workflows/README.md),
- [usługi pomocnicze](docs/services/README.md),
- [narzędzia użytkowe](docs/utils/README.md),
- [przykłady Python](docs/examples/README.md).

## 🧪 Jakość i rozwój

Instalacja zależności developerskich:

```bash
pip install -r requirements-dev.txt
```

Podstawowe sprawdzenia lokalne:

```bash
pytest
pytest --cov=ksef_client --cov-report=term-missing --cov-fail-under=100
python tools/lint.py
```

Repozytorium zawiera też narzędzia do synchronizacji modeli ze specyfikacją KSeF oraz kontroli pokrycia
obsługiwanych endpointów:

```bash
python tools/sync_generated.py --check
python tools/check_coverage.py --src src/ksef_client/clients
```

```bash
python tools/check_cli_packaging.py
```

`check_cli_packaging.py` buduje wheel i sdist w świeżym venv (wymaga sieci) i sprawdza zawartość
artefaktów: pliki XSD oraz smoke test `to_xml(xsd_validate=True)` z zainstalowanego wheela, zachowanie
`ksef` bez dodatku `cli` i z nim, a także to, że sdist nie niesie testów, których nie da się z niego
uruchomić.

Testy E2E wymagają osobnej konfiguracji środowiska KSeF i danych dostępowych. Szczegóły scenariuszy oraz
zmiennych środowiskowych są opisane w dokumentacji i testach.

Publikację uruchamiaj z `main`, wskazując istniejący tag wersji. Brama wydawnicza wymaga
pięciu rzeczywistych scenariuszy KSeF TEST na dokładnie tym pliku wheel, który trafi na PyPI.
Konfiguracja środowisk GitHub, sekretów i Trusted Publishera:
[publikacja potwierdzona TEST](docs/reliable-pagination.md#publikacja-potwierdzona-rzeczywistym-test).

## 🤝 Kontrybucja

Zgłoszenia błędów, propozycje zmian i pull requesty są mile widziane.

Rekomendowany przebieg pracy:

- opisz problem albo propozycję w Issue,
- pracuj w osobnej gałęzi,
- dodaj testy dla zmian zachowania,
- uruchom lokalnie `python tools/lint.py` oraz testy,
- w PR opisz zakres zmiany, uzasadnienie i sposób weryfikacji.
