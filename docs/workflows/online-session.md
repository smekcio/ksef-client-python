# Workflow: sesja interaktywna (online)

Scenariusz obejmuje: otwarcie sesji, wysyłkę jednej lub wielu faktur, sprawdzanie statusów, zamknięcie sesji oraz pobranie UPO.

Rekomendowane podejście: `OnlineSessionWorkflow` oraz metody `client.sessions.*` do sprawdzania statusów.

## Przykład (sync)

```python
import time
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client.services import AuthCoordinator, OnlineSessionWorkflow

KSEF_TOKEN = "<TOKEN_KSEF>"
CONTEXT_TYPE = "nip"
CONTEXT_VALUE = "5265877635"
INVOICE_XML = b\"\"\"<Invoice>...</Invoice>\"\"\"  # bytes

FORM_CODE = {"systemCode": "FA (3)", "schemaVersion": "1-0E", "value": "FA"}

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

    workflow = OnlineSessionWorkflow(client.sessions)
    session = workflow.open_session(
        form_code=FORM_CODE,
        public_certificate=sym_cert,
        access_token=access_token,
        upo_v43=False,
    )

    send = workflow.send_invoice(
        session_reference_number=session.session_reference_number,
        invoice_xml=INVOICE_XML,
        encryption_data=session.encryption_data,
        access_token=access_token,
        offline_mode=None,
        hash_of_corrected_invoice=None,
    )
    invoice_reference = send["referenceNumber"]

    for _ in range(60):
        status = client.sessions.get_session_invoice_status(
            session.session_reference_number,
            invoice_reference,
            access_token=access_token,
        )
        code = int(status.get("status", {}).get("code", 0))
        if code == 200:
            break
        if code not in {100, 150}:
            raise RuntimeError(status)
        time.sleep(2)

    workflow.close_session(session.session_reference_number, access_token)

print("OK")
```

## Uwagi

- `encryption_data` z `open_session()` musi być użyte dla wszystkich faktur wysyłanych w ramach sesji.
- Status przetwarzania jest udostępniany asynchronicznie; sprawdzanie statusu odbywa się przez polling.
- Pobranie UPO:
  - dla faktury: `get_session_invoice_upo_by_ref()` / `...by_ksef()`
  - dla sesji: `get_session_upo()`
- `upo_v43=True` dodaje nagłówek `X-KSeF-Feature: upo-v4-3` przy otwieraniu sesji.
