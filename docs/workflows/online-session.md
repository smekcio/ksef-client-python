# Workflow: sesja interaktywna (online)

Scenariusz obejmuje: otwarcie sesji, serializację lekkiego stanu JSON, wznowienie po restarcie procesu,
wysyłkę jednej lub wielu faktur, sprawdzanie statusów, zamknięcie sesji oraz pobranie UPO.

Rekomendowane podejście:
- `OnlineSessionWorkflow.open_session()` do otwarcia sesji,
- `OnlineSessionHandle` do dalszych operacji na sesji,
- `OnlineSessionWorkflow.resume_session()` do wznowienia z `OnlineSessionState`.

## Przykład (sync, z resume)

```python
import time

from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment, models as m
from ksef_client.services import AuthCoordinator, OnlineSessionState, OnlineSessionWorkflow

KSEF_TOKEN = "<TOKEN_KSEF>"
CONTEXT_TYPE = "nip"
CONTEXT_VALUE = "5265877635"
INVOICE_XML = b"""<Invoice>...</Invoice>"""

FORM_CODE = m.FormCode(system_code="FA (3)", schema_version="1-0E", value="FA")

# Proces 1: auth + open + zapis lekkiego stanu JSON
with KsefClient(KsefClientOptions(base_url=KsefEnvironment.DEMO.value)) as client:
    token_cert = client.security.get_public_key_certificate_pem(
        m.PublicKeyCertificateUsage.KSEFTOKENENCRYPTION,
    )
    sym_cert = client.security.get_public_key_certificate_pem(
        m.PublicKeyCertificateUsage.SYMMETRICKEYENCRYPTION,
    )

    access_token = AuthCoordinator(client.auth).authenticate_with_ksef_token(
        token=KSEF_TOKEN,
        public_certificate=token_cert,
        context_identifier_type=CONTEXT_TYPE,
        context_identifier_value=CONTEXT_VALUE,
        max_attempts=90,
        poll_interval_seconds=2.0,
    ).access_token

    workflow = OnlineSessionWorkflow(client.sessions)
    session = workflow.open_session(
        form_code=FORM_CODE,
        public_certificate=sym_cert,
        access_token=access_token,
        upo_v43=False,
    )
    state_json = session.get_state().to_json()

# Proces 2: nowy klient + resume z JSON
state = OnlineSessionState.from_json(state_json)

with KsefClient(
    KsefClientOptions(base_url=KsefEnvironment.DEMO.value),
    access_token=access_token,
) as client:
    workflow = OnlineSessionWorkflow(client.sessions)
    session = workflow.resume_session(state)

    send = session.send_invoice(INVOICE_XML)
    invoice_reference = send.reference_number

    for _ in range(60):
        status = session.get_invoice_status(invoice_reference)
        code = int(status.status.code)
        if code == 200:
            break
        if code not in {100, 150}:
            raise RuntimeError(status.to_dict())
        time.sleep(2)

    session.close()

print("OK")
```

## Kontrakt stanu SDK

`OnlineSessionState` serializuje wyłącznie dane potrzebne do wznowienia sesji:
- `schema_version`
- `kind="online"`
- `reference_number`
- `form_code`
- `valid_until`
- `symmetric_key_base64`
- `iv_base64`
- `upo_v43`

Nie są serializowane:
- `access_token`
- XML faktur
- wynik wysyłki / `invoice_reference`

Oznacza to, że po wznowieniu musisz nadal mieć ważny token dostępu:
- przekazany jawnie do `resume_session(..., access_token=...)`, albo
- ustawiony na kliencie: `KsefClient(..., access_token=...)`.

## Publiczne API handle'a

`OnlineSessionHandle` udostępnia:
- `reference_number`
- `session_reference_number` jako alias kompatybilności
- `valid_until`
- `form_code`
- `encryption_data`
- `get_state()`
- `send_invoice()`
- `get_status()`
- `list_invoices()`
- `list_failed_invoices()`
- `get_invoice_status()`
- `get_invoice_upo_by_ref()`
- `get_invoice_upo_by_ksef()`
- `get_upo()`
- `close()`

Zgodność wsteczna:
- `OnlineSessionResult` pozostaje aliasem do `OnlineSessionHandle`,
- kod używający `session_reference_number` i `encryption_data` nadal działa.

## Uwagi

- `encryption_data` z `open_session()` musi być użyte dla wszystkich faktur wysyłanych w ramach tej sesji; dlatego jest odtwarzane również przy `resume_session()`.
- `resume_session()` odtwarza tylko stan sesji i materiał kryptograficzny. Statusy faktur wysłanych wcześniej trzeba śledzić osobno przez `invoice_reference`.
- Dla `FA_RR (1)` w wersji `1-1E` przekazuj `formCode.value="FA_RR"` zamiast `RR`.
- Status przetwarzania jest udostępniany asynchronicznie; sprawdzanie statusu odbywa się przez polling.
- Pobranie UPO:
  - dla faktury: `get_invoice_upo_by_ref()` / `get_invoice_upo_by_ksef()`
  - dla sesji: `get_upo()`
- `upo_v43=True` dodaje nagłówek `X-KSeF-Feature: upo-v4-3` przy otwieraniu sesji.
- `AsyncOnlineSessionWorkflow` i `AsyncOnlineSessionHandle` oferują lustrzane API asynchroniczne.
