# Linki weryfikacyjne (`ksef_client.services.verification_link`)

Usługa buduje adresy URL przeznaczone do umieszczenia na fakturze (np. jako kod QR).

## `VerificationLinkService(options)`

Wymaga `KsefClientOptions`; wartość `base_qr_url` jest wykorzystywana jako baza (alternatywnie dobierana na podstawie środowiska).

## `build_invoice_verification_url(nip, issue_date, invoice_hash) -> str`

Buduje URL dla „KOD I” (weryfikacja faktury).

- `issue_date`: `date`, `datetime` albo string (format `DD-MM-YYYY`)
- `invoice_hash`: może być Base64 albo Base64Url – biblioteka akceptuje oba formaty i generuje Base64Url bez paddingu

## `build_certificate_verification_url(...) -> str`

Buduje URL dla „KOD II” (offline – podpisany link certyfikatem).

Parametry, które mają największe znaczenie:
- `seller_nip`
- `context_identifier_type`, `context_identifier_value` – np. `nip`, `526...`
- `certificate_serial`
- `invoice_hash` (Base64 lub Base64Url)
- `private_key_pem` – wymagany (podpis URL jest wykonywany lokalnie)
- `signature_format`: `"p1363"` (domyślnie) albo `"der"` dla ECDSA

Powiązane: [QR PNG](qr.md).
