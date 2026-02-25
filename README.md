# KSeF Client Python

[![CI](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml/badge.svg)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml)
[![PyPI - License](https://img.shields.io/pypi/l/ksef-client)](https://github.com/smekcio/ksef-client-python/blob/main/LICENSE)
[![PyPI - Version](https://img.shields.io/pypi/v/ksef-client)](https://pypi.org/project/ksef-client/)

`ksef-client-python` to produkcyjne SDK do integracji z KSeF API, publikowane na PyPI jako **`ksef-client`**.

Projekt odwzorowuje oficjalne przepływy KSeF i zapewnia spójny model pracy w dwóch warstwach:
- **SDK Python API** do integracji aplikacyjnych,
- **CLI** do diagnostyki i operacji bez pisania kodu.

## 🔄 Kompatybilność

Aktualna kompatybilność: **KSeF API `v2.1.2`** ([api-changelog.md](https://github.com/CIRFMF/ksef-docs/blob/2.1.2/api-changelog.md)).

## 🧭 Spis treści

- [Zakres funkcjonalny](#zakres-funkcjonalny)
- [Instalacja](#instalacja)
- [Szybki start: CLI w 2-3 minuty](#szybki-start-cli-w-2-3-minuty)
- [Szybki start: SDK](#szybki-start-sdk)
- [Najważniejsze scenariusze SDK](#najważniejsze-scenariusze-sdk)
- [Dokumentacja](#dokumentacja)
- [Testy i jakość](#testy-i-jakość)
- [Kontrybucja](#kontrybucja)

## ✅ Zakres funkcjonalny

- Klienci API: `KsefClient`, `AsyncKsefClient`, mapujące endpointy KSeF.
- Uwierzytelnianie: token KSeF i podpis XAdES, w tym `XadesKeyPair` dla PKCS#12 lub PEM.
- Workflows wysyłki: sesje online i batch z ZIP, partiami i pre-signed URL.
- Eksport/pobieranie: obsługa paczek i narzędzi do odszyfrowania/rozpakowania.
- Latarnia: publiczne endpointy dostępności KSeF (`client.lighthouse`, `ksef lighthouse ...`).
- Narzędzia pomocnicze: AES/ZIP/Base64Url, linki weryfikacyjne, QR.
- CLI `ksef`: szybka ścieżka od konfiguracji do pierwszych operacji: `init -> auth -> invoice/send/upo`.

## 📦 Instalacja

Wymagania: Python `>= 3.10`.

Podstawowe SDK:

```bash
pip install ksef-client
```

SDK + CLI:

```bash
pip install "ksef-client[cli]"
```

Dodatki opcjonalne:

```bash
pip install "ksef-client[xml,qr,cli]"
```

- `xml` - podpis XAdES z `lxml` i `xmlsec`
- `qr` - generowanie PNG z kodami QR przez `qrcode` i `pillow`
- `cli` - interfejs wiersza poleceń oparty o `typer`, `rich`, `keyring`

## 🚀 Szybki start: CLI

CLI `ksef` zostało zaprojektowane tak, aby skrócić wejście w SDK do minimum.

1. Utwórz i aktywuj profil:

```bash
ksef init --non-interactive --name demo --env DEMO --context-type nip --context-value <NIP> --set-active
```

2. Zaloguj się tokenem i sprawdź sesję:

```bash
ksef auth login-token --ksef-token <KSEF_TOKEN>
ksef auth status
ksef profile show
```

Alternatywnie, logowanie certyfikatem XAdES:

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

Najważniejsze grupy komend:
- onboarding/profiles: `init`, `profile ...`
- auth: `auth login-token`, `auth login-xades`, `auth status`, `auth refresh`, `auth logout`
- operacje: `invoice ...`, `send ...`, `upo ...`, `export ...`
- diagnostyka: `health check`
- latarnia: `lighthouse status`, `lighthouse messages`

Pełna specyfikacja CLI: [`docs/cli/README.md`](docs/cli/README.md)

## 🧩 Szybki start: SDK

Minimalny przebieg integracji:
- uzyskanie `access_token` przez token KSeF lub XAdES,
- wykonanie pierwszego wywołania API, np. listowania metadanych faktur.

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client.services.workflows import AuthCoordinator

with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    token_cert_pem = ...  # usage: KsefTokenEncryption, client.security.get_public_key_certificates

    access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
        token=KSEF_TOKEN,
        public_certificate=token_cert_pem,
        context_identifier_type="nip",
        context_identifier_value="5265877635",
    ).tokens.access_token.token

    metadata = client.invoices.query_invoice_metadata(
        {...},
        access_token=access_token,
        page_offset=0,
        page_size=10,
        sort_order="Desc",
    )
```

## 🔐 Najważniejsze scenariusze SDK

### Autoryzacja tokenem KSeF

```python
tokens = AuthCoordinator(client.auth).authenticate_with_ksef_token(
    token=KSEF_TOKEN,
    public_certificate=token_cert_pem,
    context_identifier_type="nip",
    context_identifier_value="5265877635",
).tokens
```

### Autoryzacja certyfikatem XAdES

Wymaga dodatku `xml`: `pip install "ksef-client[xml]"`.

```python
from ksef_client.services import XadesKeyPair

key_pair = XadesKeyPair.from_pkcs12_file(pkcs12_path="cert.p12", pkcs12_password="***")
tokens = AuthCoordinator(client.auth).authenticate_with_xades_key_pair(
    key_pair=key_pair,
    context_identifier_type="nip",
    context_identifier_value="5265877635",
    subject_identifier_type="certificateSubject",
    enforce_xades_compliance=False,
).tokens
```

### Wysyłka faktury w sesji online

```python
from ksef_client.services.workflows import OnlineSessionWorkflow

send_result = OnlineSessionWorkflow(client.sessions).send_invoice(
    session_reference_number=session_reference_number,
    invoice_xml=invoice_xml_fa3_bytes,
    encryption_data=encryption_data,
    access_token=access_token,
)
```

### Wysyłka wsadowa batch ZIP

```python
from ksef_client.services.workflows import BatchSessionWorkflow

session_reference_number = BatchSessionWorkflow(client.sessions, client.http_client).open_upload_and_close(
    form_code={"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"},
    zip_bytes=zip_bytes,
    public_certificate=symmetric_cert_pem,
    access_token=access_token,
    parallelism=4,
)
```

### Odczyt statusu Latarni

```python
status = client.lighthouse.get_status()
messages = client.lighthouse.get_messages()
```

## 📚 Dokumentacja

Dokumentacja SDK znajduje się w `docs/`:
- indeks: [`docs/README.md`](docs/README.md)
- start: [`docs/getting-started.md`](docs/getting-started.md)
- konfiguracja: [`docs/configuration.md`](docs/configuration.md)
- błędy i retry: [`docs/errors.md`](docs/errors.md)
- API: [`docs/api/README.md`](docs/api/README.md)
- workflows: [`docs/workflows/README.md`](docs/workflows/README.md)
- usługi: [`docs/services/README.md`](docs/services/README.md)
- utils: [`docs/utils/README.md`](docs/utils/README.md)
- przykłady: [`docs/examples/README.md`](docs/examples/README.md)

## 🧪 Testy i jakość

[![Python E2E TEST token](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml/badge.svg)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml?query=job%3A%22E2E+TEST+%28token%29%22)
[![Python E2E TEST cert](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml/badge.svg)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml?query=job%3A%22E2E+TEST+%28xades%29%22)
[![Python E2E DEMO token](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml/badge.svg)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml?query=job%3A%22E2E+DEMO+%28token%29%22)
[![Python E2E DEMO cert](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml/badge.svg)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml?query=job%3A%22E2E+DEMO+%28xades%29%22)

Instalacja zależności developerskich:

```bash
pip install -r requirements-dev.txt
```

Uruchomienie testów:

```bash
pytest
```

Uruchomienie testów z kontrolą pokrycia:

```bash
pytest --cov=ksef_client --cov-report=term-missing --cov-fail-under=100
```

Testy E2E w `tests/test_e2e_token_flows.py` wymagają osobnej konfiguracji środowiska i danych dostępowych.

## 🤝 Kontrybucja

Wkład w rozwój projektu przyjmowany jest w formie pull requestów i zgłoszeń Issues.

Rekomendowany przebieg:
- opisz problem lub propozycję zmiany w Issue,
- pracuj w osobnej gałęzi,
- dołącz testy dla zmian zachowania,
- utrzymaj jakość: `pytest`, `pytest --cov=ksef_client --cov-fail-under=100`,
- opisz zakres i uzasadnienie zmian w PR.
