# KSeF Client Python

[![CI](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml/badge.svg)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml)
[![PyPI - License](https://img.shields.io/pypi/l/ksef-client)](https://github.com/smekcio/ksef-client-python/blob/main/LICENSE)
[![PyPI - Version](https://img.shields.io/pypi/v/ksef-client)](https://pypi.org/project/ksef-client/)

**KSeF Client Python** to SDK i narzędzia CLI dla integracji z Krajowym Systemem e-Faktur.
Pakiet jest publikowany na PyPI jako **`ksef-client`** i obsługuje aktualny kontrakt
**KSeF API `v2.6.0`** ([changelog API](https://github.com/CIRFMF/ksef-api/blob/main/api-changelog.md#wersja-260)).

Biblioteka pomaga integrować aplikacje napisane w Pythonie z KSeF bez ręcznego
składania żądań HTTP, szyfrowania, podpisów, obsługi sesji i pobierania paczek faktur.

Najważniejsze cechy:

- **typowane modele** `ksef_client.models` zamiast surowych słowników dla publicznych żądań SDK,
- **klient synchroniczny i asynchroniczny**: `KsefClient` oraz `AsyncKsefClient`,
- **CLI `ksef`** do konfiguracji, diagnostyki, uwierzytelniania, wysyłki i pobierania faktur,
- **uwierzytelnianie tokenem KSeF i XAdES**, w tym obsługa PKCS#12 oraz PEM,
- **sesje online i wsadowe**, eksport faktur, UPO, linki weryfikacyjne, QR i Latarnia KSeF,
- **FA(3)**: budowanie XML faktur, walidacja XSD i przygotowanie paczek ZIP/TarGz,
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
- pracować na typowanych modelach zamiast utrzymywać własne słowniki i mapowania JSON,
- korzystać z gotowych scenariuszy dla sesji online, sesji wsadowych i eksportu faktur,
- przygotowywać XML FA(3) programistycznie i walidować go z oficjalnym XSD,
- testować integrację w środowiskach TEST/DEMO przed przejściem na PROD.

Publiczny kontrakt SDK jest typowany: do metod klientów przekazuj obiekty `ksef_client.models.*`,
a nie surowe `dict`. Jeżeli migrujesz starszą integrację, zacznij od
[`docs/migration-typed-model-api.md`](docs/migration-typed-model-api.md).

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
komendę `ksef`, otrzymasz czytelną instrukcję doinstalowania dodatku `cli`, zamiast tracebacka.

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

Minimalny przepływ w kodzie zwykle wygląda tak:

1. tworzysz klienta dla wybranego środowiska,
2. pobierasz publiczny certyfikat KSeF do szyfrowania tokena,
3. uzyskujesz `access_token`,
4. wykonujesz wywołanie API na typowanych modelach.

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client import models as m
from ksef_client.services import AuthCoordinator

KSEF_TOKEN = "<TOKEN_KSEF>"
CONTEXT_TYPE = "nip"
CONTEXT_VALUE = "5265877635"

with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    token_cert_pem = client.security.get_public_key_certificate_pem(
        m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
    )

    access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
        token=KSEF_TOKEN,
        public_certificate=token_cert_pem,
        context_identifier_type=CONTEXT_TYPE,
        context_identifier_value=CONTEXT_VALUE,
        max_attempts=90,
        poll_interval_seconds=2.0,
    ).access_token

    metadata = client.invoices.query_invoice_metadata_by_date_range(
        subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
        date_type=m.InvoiceQueryDateType.ISSUE,
        date_from="2026-01-01T00:00:00Z",
        date_to="2026-01-31T23:59:59Z",
        access_token=access_token,
        page_size=10,
    )

print(f"Liczba faktur: {len(metadata.invoices)}")
```

### 📤 Wysyłka faktury w sesji online

Do wysyłki faktur używaj scenariusza `OnlineSessionWorkflow`. Aktualny model pracy to:
`open_session() -> session.send_invoice() -> session.close()`.

Poniższy fragment zakłada, że jesteś wewnątrz bloku `with KsefClient(...) as client:` i masz już `access_token` z poprzedniego kroku.

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
    access_token=access_token,
)

send_result = session.send_invoice(invoice_xml, access_token=access_token)
session.close(access_token=access_token)

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
| Faktury | Lista metadanych, pobieranie faktur, eksport paczek i narzędzia do ich przetwarzania. |
| FA(3) | Buildery, drafty, XML, walidacja XSD i ZIP do sesji wsadowych. |
| UPO | Sprawdzanie statusów i pobieranie urzędowego poświadczenia odbioru. |
| CLI | Operacje administracyjne i diagnostyczne bez pisania kodu. |
| Latarnia | Publiczny status dostępności KSeF i komunikaty serwisowe. |
| QR i linki | Linki weryfikacyjne, podpisy i generowanie kodów QR. |

## 📚 Dokumentacja

Główna dokumentacja znajduje się w katalogu [`docs/`](docs/README.md):

- [pierwsze kroki](docs/getting-started.md),
- [konfiguracja klienta](docs/configuration.md),
- [błędy, retry i limity](docs/errors.md),
- [referencja API](docs/api/README.md),
- [scenariusze sesji i eksportu](docs/workflows/README.md),
- [usługi pomocnicze](docs/services/README.md),
- [narzędzia użytkowe](docs/utils/README.md),
- [przykłady Python](docs/examples/README.md),
- [migracja z `dict` na typowane modele](docs/migration-typed-model-api.md).

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

Testy E2E wymagają osobnej konfiguracji środowiska KSeF i danych dostępowych. Szczegóły scenariuszy oraz
zmiennych środowiskowych są opisane w dokumentacji i testach.

## 🤝 Kontrybucja

Zgłoszenia błędów, propozycje zmian i pull requesty są mile widziane.

Rekomendowany przebieg pracy:

- opisz problem albo propozycję w Issue,
- pracuj w osobnej gałęzi,
- dodaj testy dla zmian zachowania,
- uruchom lokalnie `python tools/lint.py` oraz testy,
- w PR opisz zakres zmiany, uzasadnienie i sposób weryfikacji.
