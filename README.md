# KSeF Client Python

Python SDK dla **KSeF API 2.0 (v2)**.

## Instalacja (lokalnie)
```bash
pip install -e .
```

## Opcjonalne extras
```bash
pip install -e .[xml,qr]
```

- `xml` – podpis XAdES (`lxml`, `xmlsec`)
- `qr` – generowanie PNG z kodami QR (`qrcode`, `pillow`)

## Konfiguracja

```python
from ksef_client import KsefClient, KsefClientOptions

options = KsefClientOptions(
    base_url="https://api-test.ksef.mf.gov.pl",
    timeout_seconds=30.0,
    verify_ssl=True,
    proxy=None,
    custom_headers={"X-Custom-Header": "value"},
    follow_redirects=False,
    base_qr_url=None,
)

client = KsefClient(options)
```

## Szybki start (sync)
```python
from ksef_client import KsefClient, KsefClientOptions

with KsefClient(KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")) as client:
    challenge = client.auth.get_challenge()
```

## Szybki start (async)
```python
import asyncio
from ksef_client import AsyncKsefClient, KsefClientOptions

async def main():
    async with AsyncKsefClient(KsefClientOptions(base_url="https://api-test.ksef.mf.gov.pl")) as client:
        challenge = await client.auth.get_challenge()

asyncio.run(main())
```

## Uwierzytelnianie (workflow)

### XAdES (wymaga extra `xml`)
```python
from ksef_client.services import AuthCoordinator

result = AuthCoordinator(client.auth).authenticate_with_xades(
    context_identifier_type="nip",
    context_identifier_value="5265877635",
    subject_identifier_type="certificateSubject",
    certificate_pem=cert_pem,
    private_key_pem=key_pem,
)
access_token = result.tokens.access_token.token
```

### Token KSeF (RSA lub EC)
```python
from ksef_client.services import AuthCoordinator

certs = client.security.get_public_key_certificates()
token_cert_pem = next(
    c["certificate"] for c in certs if "KsefTokenEncryption" in (c.get("usage") or [])
)

result = AuthCoordinator(client.auth).authenticate_with_ksef_token(
    token=ksef_token,
    public_certificate=token_cert_pem,
    context_identifier_type="nip",
    context_identifier_value="5265877635",
    method="ec",
    ec_output_format="java",
)
access_token = result.tokens.access_token.token
```

`ec_output_format` ma znaczenie tylko dla `method="ec"` i opisuje format bajtów zaszyfrowanego tokena:
- `java`: `ephemeralPublicKey(SPKI DER) + nonce(12B) + ciphertext||tag`
- `csharp`: `ephemeralPublicKey(SPKI DER) + nonce(12B) + tag(16B) + ciphertext`

Jeśli integrujesz się z SDK Java, użyj `java`. Jeśli porównujesz z implementacją .NET, użyj `csharp`.

## Sesja interaktywna (workflow)
```python
from ksef_client.services import OnlineSessionWorkflow

workflow = OnlineSessionWorkflow(client.sessions)
session = workflow.open_session(
    form_code={"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"},
    public_certificate=symmetric_cert_pem,
    access_token=access_token,
)

send = workflow.send_invoice(
    session_reference_number=session.session_reference_number,
    invoice_xml=invoice_xml_bytes,
    encryption_data=session.encryption_data,
    access_token=access_token,
)
```

## Sesja wsadowa (workflow)
```python
from ksef_client.services import BatchSessionWorkflow
from ksef_client.utils import build_zip

zip_bytes = build_zip({"invoice1.xml": invoice_xml_bytes})
workflow = BatchSessionWorkflow(client.sessions, client.http_client)
reference_number = workflow.open_upload_and_close(
    form_code={"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"},
    zip_bytes=zip_bytes,
    public_certificate=symmetric_cert_pem,
    access_token=access_token,
    parallelism=4,
)
```

## Eksport (workflow)
```python
from ksef_client.services import ExportWorkflow

export = ExportWorkflow(client.invoices, client.http_client)
status = client.invoices.get_export_status(reference_number, access_token=access_token)
package = status["package"]
result = export.download_and_process_package(package, encryption_data)
```

## Narzędzia (tools/)

### `tools/generate_openapi_models.py`
Generuje `src/ksef_client/openapi_models.py` na podstawie `ksef-docs/open-api.json` (modele: dataclasses/enumy/aliasy).

### `tools/lint.py`
Lokalny runner jakości, który uruchamia:
- `python -m compileall src tests`,
- `python -m pip check`,
- opcjonalnie `ruff` i `mypy` (konfiguracja w `pyproject.toml`).

## Testy
```bash
pytest
```

Testy E2E są oznaczone markerem `e2e` i wymagają `KSEF_E2E=1` oraz zmiennych środowiskowych z danymi dostępowymi.

## Notatki
- Upload części paczek wsadowych i download części eksportu muszą iść bez Bearer tokena.
- Refresh token jest wysyłany jako `Authorization: Bearer <refreshToken>`.
