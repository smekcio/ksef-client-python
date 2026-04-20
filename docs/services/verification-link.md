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
- `private_key_password` – opcjonalny; wymagany, jeśli `private_key_pem` jest zaszyfrowany
- `signature_format`: `"p1363"` (domyślnie) albo `"der"` dla ECDSA

Podpis obejmuje fragment URL bez prefiksu `https://` / `http://`, np.:

```text
qr-test.ksef.mf.gov.pl/certificate/nip/1234567890/1234567890/1/YQ
```

Biblioteka podpisuje ten ciąg algorytmem zgodnym z kluczem:
- RSA-PSS z `SHA-256`, `MGF1(SHA-256)` i długością soli `32` bajty
- ECDSA P-256 z `SHA-256`; wynik może być zwrócony jako `"p1363"` (domyślnie) albo `"der"`

Przykład z zaszyfrowanym PEM:

```python
url = service.build_certificate_verification_url(
    seller_nip="1234567890",
    context_identifier_type="nip",
    context_identifier_value="1234567890",
    certificate_serial="1",
    invoice_hash="YQ==",
    signing_certificate_pem=certificate_pem,
    private_key_pem=private_key_pem,
    private_key_password="tajne-haslo",
)
```

Jeżeli korzystasz już z `XadesKeyPair.from_pem_files(...)` albo `XadesKeyPair.from_pkcs12_file(...)`, możesz też najpierw znormalizować klucz do niezaszyfrowanego PKCS#8 PEM, a następnie przekazać wynikowe `certificate_pem` i `private_key_pem` do `VerificationLinkService`.

Powiązane: [QR PNG](qr.md).
