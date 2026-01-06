# Usługi (`ksef_client.services`)

Warstwa lokalna obejmuje kryptografię, XAdES, CSR, QR, narzędzia do wysyłki i pobierania partów oraz scenariusze (workflow).

W typowych scenariuszach wykorzystywane są przede wszystkim:
- `AuthCoordinator`, `OnlineSessionWorkflow`, `BatchSessionWorkflow`, `ExportWorkflow`

W sytuacjach wymagających pełnej kontroli nad payloadami (np. własny magazyn kluczy, strumieniowanie plików, niestandardowe archiwum ZIP) dostępne są funkcje niższego poziomu, m.in. `build_send_invoice_request()` oraz `encrypt_batch_parts()`.

Spis:

- [Workflows i narzędzia pomocnicze](workflows.md)
- [Auth (budowa żądań + szyfrowanie tokena)](auth.md)
- [Kryptografia sesji (AES/RSA/EC, metadane)](crypto.md)
- [Batch (podział i szyfrowanie partów)](batch.md)
- [XAdES](xades.md)
- [CSR](csr.md)
- [Linki weryfikacyjne](verification-link.md)
- [QR PNG](qr.md)
- [HWM i deduplikacja](hwm.md)
- [Person token (inspekcja JWT)](person-token.md)
