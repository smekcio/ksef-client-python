# KSeF Client (Python)

[![CI](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml/badge.svg)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-application.yml)
[![PyPI - License](https://img.shields.io/pypi/l/ksef-client)](https://github.com/smekcio/ksef-client-python/blob/main/LICENSE)
[![PyPI - Version](https://img.shields.io/pypi/v/ksef-client)](https://pypi.org/project/ksef-client/)



`ksef-client-python` jest repozytorium biblioteki (SDK) publikowanej na PyPI jako **`ksef-client`** (import: `ksef_client`).

SDK zostało zaprojektowane w oparciu o oficjalne biblioteki referencyjne KSeF dla ekosystemów **Java** oraz **C#/.NET**, z naciskiem na zachowanie spójności pojęć oraz przepływów (workflow).

## 🔄 Kompatybilność API KSeF

Aktualna kompatybilność: **KSeF API `v2.1.1`** ([api-changelog.md](https://github.com/CIRFMF/ksef-docs/blob/2.1.1/api-changelog.md)).

## ✅ Funkcjonalności

- Klienci API (`KsefClient`, `AsyncKsefClient`) mapujący wywołania na endpointy KSeF.
- Uwierzytelnianie tokenem KSeF oraz podpisem XAdES (w tym `XadesKeyPair` dla PKCS#12 lub zestawu PEM+hasło).
- Sesje wysyłkowe: online (pojedyncze faktury) oraz batch (ZIP, party, pre-signed URL).
- Eksport i pobieranie paczek faktur (pre-signed URL) wraz z odszyfrowaniem i rozpakowaniem.
- Narzędzia kryptograficzne i pomocnicze (AES/ZIP/Base64Url, linki weryfikacyjne, QR).

## 📦 Instalacja

Wymagania: Python `>= 3.10`.

Instalacja z PyPI:

```bash
pip install ksef-client
```

Opcjonalne dodatki (extras):

```bash
pip install "ksef-client[xml,qr]"
```

- `xml` – podpis XAdES (`lxml`, `xmlsec`)
- `qr` – generowanie PNG z kodami QR (`qrcode`, `pillow`)

## 📚 Dokumentacja

Dokumentacja SDK znajduje się w katalogu `docs/`:

- Indeks: [`docs/README.md`](docs/README.md)
- Start: [`docs/getting-started.md`](docs/getting-started.md)
- Konfiguracja: [`docs/configuration.md`](docs/configuration.md)
- Błędy i retry: [`docs/errors.md`](docs/errors.md)
- API (endpointy): [`docs/api/README.md`](docs/api/README.md)
- Workflows: [`docs/workflows/README.md`](docs/workflows/README.md)
- Usługi: [`docs/services/README.md`](docs/services/README.md)
- Utils: [`docs/utils/README.md`](docs/utils/README.md)
- Przykłady (skrypty): [`docs/examples/README.md`](docs/examples/README.md)

## 🚀 Quick start

Minimalny przebieg integracji obejmuje:
- uzyskanie `access_token` (token KSeF albo XAdES),
- wykonanie wywołania API, np. wyszukiwania metadanych faktur.

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client.services.workflows import AuthCoordinator

with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    token_cert_pem = ...  # usage: KsefTokenEncryption (client.security.get_public_key_certificates)
    access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
        token=KSEF_TOKEN,
        public_certificate=token_cert_pem,
        context_identifier_type="nip",
        context_identifier_value="5265877635",
    ).tokens.access_token.token

    metadata = client.invoices.query_invoice_metadata(
        {...}, access_token=access_token, page_offset=0, page_size=10, sort_order="Desc"
    )
```

## 🔐 Najważniejsze snippety

Fragmenty pokazują kluczowe wywołania. Pełne, uruchamialne przykłady znajdują się w `docs/examples/`.

### Autoryzacja tokenem KSeF

```python
token_cert_pem = ...  # usage: KsefTokenEncryption
tokens = AuthCoordinator(client.auth).authenticate_with_ksef_token(
    token=KSEF_TOKEN,
    public_certificate=token_cert_pem,
    context_identifier_type="nip",
    context_identifier_value="5265877635",
).tokens
```

### Autoryzacja certyfikatem (XAdES)

Wymaga dodatku `xml`: `pip install "ksef-client[xml]"`.

```python
from ksef_client.services import XadesKeyPair

key_pair = XadesKeyPair.from_pkcs12_file(pkcs12_path="cert.p12", pkcs12_password="***")
tokens = AuthCoordinator(client.auth).authenticate_with_xades_key_pair(
    key_pair=key_pair,
    context_identifier_type="nip",
    context_identifier_value="5265877635",
    subject_identifier_type="certificateSubject",
    enforce_xades_compliance=False,  # ustaw True, aby dodać X-KSeF-Feature: enforce-xades-compliance
).tokens
```

### Listowanie faktur (metadane)

```python
metadata = client.invoices.query_invoice_metadata(
    {...}, access_token=access_token, page_offset=0, page_size=10, sort_order="Desc"
)
```

### Wysyłka faktury (sesja online, FA(3) XML)

Wywołanie zakłada, że dostępne są `session_reference_number` oraz `encryption_data` (utworzone przy otwarciu sesji online).

```python
from ksef_client.services.workflows import OnlineSessionWorkflow

send_result = OnlineSessionWorkflow(client.sessions).send_invoice(
    session_reference_number=session_reference_number,
    invoice_xml=invoice_xml_fa3_bytes,
    encryption_data=encryption_data,
    access_token=access_token,
)
```

### Wysyłka wsadowa (batch, ZIP z wieloma XML)

Wywołanie zakłada dostępność `zip_bytes` (ZIP z wieloma plikami XML faktur) oraz certyfikatu KSeF do szyfrowania klucza symetrycznego (`SymmetricKeyEncryption`).

```python
from ksef_client.services.workflows import BatchSessionWorkflow

session_reference_number = BatchSessionWorkflow(client.sessions, client.http_client).open_upload_and_close(
    form_code={"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"},
    zip_bytes=zip_bytes,
    public_certificate=symmetric_cert_pem,  # usage: SymmetricKeyEncryption
    access_token=access_token,
    parallelism=4,
)
```

## 🧪 Testy

[![Python E2E](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml/badge.svg)](https://github.com/smekcio/ksef-client-python/actions/workflows/python-e2e.yml)

Testy uruchamiane są przez `pytest`.

Instalacja zależności testowych:

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

Testy E2E (marker `e2e`) są wyłączone w standardowym przebiegu i wymagają osobnej konfiguracji
środowiska oraz danych dostępowych.

Scenariusz E2E obejmuje:
- logowanie tokenem KSeF,
- logowanie certyfikatem (XAdES),
- wystawienie faktury,
- pobranie UPO,
- listowanie faktur,
- pobranie ostatniej faktury.

Plik testów E2E:
- `tests/test_e2e_token_flows.py`

Dostępne testy:
- `test_e2e_test_environment_full_flow_token`
- `test_e2e_test_environment_full_flow_xades`
- `test_e2e_demo_environment_full_flow_token`
- `test_e2e_demo_environment_full_flow_xades`

Lokalne uruchomienie (token, TEST):

```bash
KSEF_E2E=1 \
KSEF_TEST_TOKEN=... \
KSEF_TEST_CONTEXT_TYPE=nip \
KSEF_TEST_CONTEXT_VALUE=... \
pytest tests/test_e2e_token_flows.py::test_e2e_test_environment_full_flow_token
```

Lokalne uruchomienie (XAdES, TEST):

```bash
KSEF_E2E=1 \
KSEF_TEST_CONTEXT_TYPE=nip \
KSEF_TEST_CONTEXT_VALUE=... \
KSEF_TEST_XADES_CERT_CRT="$(cat cert.crt)" \
KSEF_TEST_XADES_PRIVATE_KEY_PEM="$(cat key.pem)" \
KSEF_TEST_XADES_PRIVATE_KEY_PASSWORD=... \
pytest tests/test_e2e_token_flows.py::test_e2e_test_environment_full_flow_xades
```

## 🤝 Kontrybucja

Wkład w rozwój projektu przyjmowany jest w formie pull requestów oraz zgłoszeń w Issues. Zalecany przebieg prac:

- opis problemu lub propozycji zmiany (Issue),
- implementacja w osobnej gałęzi,
- dołączenie testów dla zmian zachowania,
- utrzymanie jakości: `pytest` oraz `pytest --cov=ksef_client --cov-fail-under=100`,
- krótki opis zmian i uzasadnienie w PR.
