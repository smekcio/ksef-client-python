# Workflow: eksport i pobranie paczki faktur

Eksport obejmuje dwa kroki:
1) zainicjowanie eksportu (`POST /invoices/exports`),
2) sprawdzenie statusu oraz pobranie części paczki z pre-signed URL (bez Bearer).

Biblioteka udostępnia klasę `ExportWorkflow`, która realizuje krok (2): pobranie → odszyfrowanie → rozpakowanie.

## Przykład (sync)

```python
import time
from ksef_client import KsefClient, KsefClientOptions, KsefEnvironment, models as m
from ksef_client.services import AuthCoordinator, ExportWorkflow, build_encryption_data

KSEF_TOKEN = "<TOKEN_KSEF>"
CONTEXT_TYPE = "nip"
CONTEXT_VALUE = "5265877635"

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

    encryption = build_encryption_data(sym_cert)
    assert encryption.encryption_info is not None
    export_request = m.InvoiceExportRequest(
        encryption=encryption.encryption_info,
        only_metadata=False,
        filters=m.InvoiceQueryFilters(
            subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
            date_range=m.InvoiceQueryDateRange(
                date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
                from_="2025-08-28T09:22:13.388+00:00",
                to="2025-09-28T09:22:13.388+00:00",
                restrict_to_permanent_storage_hwm_date=True,
            ),
        ),
    )

    start = client.invoices.export_invoices(export_request, access_token=access_token)
    reference_number = start.reference_number

    for _ in range(120):
        status = client.invoices.get_export_status(reference_number, access_token=access_token)
        code = int(status.status.code)
        if code == 200:
            package = status.package
            assert package is not None
            break
        if code not in {100, 150}:
            raise RuntimeError(status.to_dict())
        time.sleep(2)

    export = ExportWorkflow(client.invoices, client.http_client)
    result = export.download_and_process_package(package, encryption)

print(len(result.metadata_summaries), len(result.invoice_xml_files))
```

## Uwagi

- Części paczki są dostępne pod `package.parts[].url` i są pobierane **bez Bearer tokena** (pre-signed URL).
- Ustaw `onlyMetadata=True`, jeśli potrzebujesz wyłącznie `_metadata.json` bez XML faktur.
- Dla każdego pobranego (zaszyfrowanego) partu workflow liczy hash `SHA-256` (base64) i porównuje z `x-ms-meta-hash`, jeśli nagłówek jest obecny.
- Domyślnie (`KsefClientOptions.require_export_part_hash=True`) brak `x-ms-meta-hash` powoduje `ValueError`.
- Niezgodność hash (`x-ms-meta-hash` vs. wyliczony hash) zawsze powoduje `ValueError`.
- Jeśli integracja wymaga tolerowania braku nagłówka, ustaw `require_export_part_hash=False` w `KsefClientOptions` lub podczas tworzenia workflow.
- Linki do partów wygasają; pobranie powinno nastąpić bez zbędnej zwłoki.
- Paczka eksportu zawiera `_metadata.json` (dla deduplikacji i synchronizacji przyrostowej).

Do HWM i deduplikacji: [HWM](../services/hwm.md).
