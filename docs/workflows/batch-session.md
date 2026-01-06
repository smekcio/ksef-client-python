# Workflow: sesja wsadowa (batch)

Scenariusz obejmuje: przygotowanie ZIP z wieloma XML, podział na części ≤100MB, szyfrowanie, otwarcie sesji wsadowej, wysyłkę partów na pre-signed URL oraz zamknięcie sesji.

Rekomendowane podejście: `BatchSessionWorkflow.open_upload_and_close()`.

## Przykład (sync)

```python
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client.services import AuthCoordinator, BatchSessionWorkflow
from ksef_client.utils import build_zip

KSEF_TOKEN = "<TOKEN_KSEF>"
CONTEXT_TYPE = "nip"
CONTEXT_VALUE = "5265877635"

FORM_CODE = {"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"}

zip_bytes = build_zip({
    "invoice1.xml": b\"\"\"<Invoice>...</Invoice>\"\"\",
    "invoice2.xml": b\"\"\"<Invoice>...</Invoice>\"\"\",
})

with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    certs = client.security.get_public_key_certificates()
    token_cert = next(c["certificate"] for c in certs if "KsefTokenEncryption" in (c.get("usage") or []))
    sym_cert = next(c["certificate"] for c in certs if "SymmetricKeyEncryption" in (c.get("usage") or []))

    access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
        token=KSEF_TOKEN,
        public_certificate=token_cert,
        context_identifier_type=CONTEXT_TYPE,
        context_identifier_value=CONTEXT_VALUE,
        max_attempts=90,
        poll_interval_seconds=2.0,
    ).tokens.access_token.token

    workflow = BatchSessionWorkflow(client.sessions, client.http_client)
    session_ref = workflow.open_upload_and_close(
        form_code=FORM_CODE,
        zip_bytes=zip_bytes,
        public_certificate=sym_cert,
        access_token=access_token,
        offline_mode=None,
        parallelism=4,
    )

print(session_ref)
```

## Uwagi

- Wysyłka partów odbywa się na pre-signed URL: **bez Bearer tokena** (workflow wykonuje wywołania z `skip_auth=True`).
- Limit czasu wysyłki w sesji wsadowej wynosi **liczba partów × 20 minut na każdy part**; liczba partów wpływa bezpośrednio na czas dostępny na wysyłkę.
- Podział ZIP musi nastąpić **przed szyfrowaniem** (biblioteka wykonuje to w `encrypt_batch_parts()`).
- Korelacja statusów z plikami źródłowymi jest możliwa przez zapisanie hashy SHA-256 faktur (przed szyfrowaniem) i mapowanie ich na identyfikatory w procesie weryfikacji (`invoiceHash`).
