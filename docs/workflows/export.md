# Workflow: eksport i pobranie paczki faktur

Eksport obejmuje dwa kroki:
1) zainicjowanie eksportu (`POST /invoices/exports`),
2) sprawdzenie statusu oraz pobranie części paczki z pre-signed URL (bez Bearer).

Biblioteka udostępnia klasę `ExportWorkflow`, która realizuje krok (2): pobranie → odszyfrowanie → rozpakowanie.

## Przykład (sync)

```python
import time
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment
from ksef_client.services import AuthCoordinator, ExportWorkflow, build_encryption_data

KSEF_TOKEN = "<TOKEN_KSEF>"
CONTEXT_TYPE = "nip"
CONTEXT_VALUE = "5265877635"

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

    encryption = build_encryption_data(sym_cert)
    export_request = {
        "encryption": {
            "encryptedSymmetricKey": encryption.encryption_info.encrypted_symmetric_key,
            "initializationVector": encryption.encryption_info.initialization_vector,
        },
        "filters": {
            "subjectType": "Subject1",
            "dateRange": {
                "dateType": "PermanentStorage",
                "from": "2025-08-28T09:22:13.388+00:00",
                "to": "2025-09-28T09:22:13.388+00:00",
                "restrictToPermanentStorageHwmDate": True,
            },
        },
    }

    start = client.invoices.export_invoices(export_request, access_token=access_token)
    reference_number = start["referenceNumber"]

    for _ in range(120):
        status = client.invoices.get_export_status(reference_number, access_token=access_token)
        code = int(status.get("status", {}).get("code", 0))
        if code == 200:
            package = status["package"]
            break
        if code not in {100, 150}:
            raise RuntimeError(status)
        time.sleep(2)

    export = ExportWorkflow(client.invoices, client.http_client)
    result = export.download_and_process_package(package, encryption)

print(len(result.metadata_summaries), len(result.invoice_xml_files))
```

## Uwagi

- Części paczki są dostępne pod `package.parts[].url` i są pobierane **bez Bearer tokena** (pre-signed URL).
- Linki do partów wygasają; pobranie powinno nastąpić bez zbędnej zwłoki.
- Paczka eksportu zawiera `_metadata.json` (dla deduplikacji i synchronizacji przyrostowej).

Do HWM i deduplikacji: [HWM](../services/hwm.md).
