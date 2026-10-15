# Linki weryfikacyjne (`ksef_client.services.verification_link`)

Usługa buduje adresy URL przeznaczone do umieszczenia na fakturze (np. jako kod QR).

## `VerificationLinkService(options)`

Wymaga `KsefClientOptions`; wartość `base_qr_url` jest wykorzystywana jako baza (alternatywnie dobierana na podstawie środowiska).

## `build_invoice_verification_url(nip, issue_date, invoice_hash) -> str`

Buduje URL dla „KOD I” (weryfikacja faktury).

- `issue_date`: `date`, `datetime` albo string. String przyjmujemy w formacie
  docelowym `DD-MM-YYYY` albo w ISO-8601 (`YYYY-MM-DD`, konwertowany); każdy inny
  zapis kończy się `ValueError` — np. `2026/02/01` dokładał do ścieżki dodatkowy
  segment i dawał kod odrzucany jako uszkodzony.
- `invoice_hash`: może być Base64 albo Base64Url – biblioteka akceptuje oba formaty i generuje Base64Url bez paddingu

## `build_certificate_verification_url(...) -> str`

Buduje URL dla „KOD II” (offline – podpisany link certyfikatem).

Parametry, które mają największe znaczenie:
- `seller_nip`
- `context_identifier_type` – jeden z czterech segmentów kontraktu: `Nip`,
  `InternalId`, `NipVatUe`, `PeppolId`; zapis bez rozróżniania wielkości liter
  (`nip`) jest normalizowany, a wartość spoza listy kończy się `ValueError`
- `context_identifier_value` – np. `526...`
- `certificate_serial`
- `invoice_hash` (Base64 lub Base64Url)
- `private_key_pem` – wymagany (podpis URL jest wykonywany lokalnie)
- `private_key_password` – opcjonalny; wymagany, jeśli `private_key_pem` jest zaszyfrowany
- `signature_format`: `"p1363"` (domyślnie) albo `"der"` dla ECDSA

Podpis obejmuje fragment URL bez prefiksu `https://` / `http://`, np.:

```text
qr-test.ksef.mf.gov.pl/certificate/Nip/1234567890/1234567890/1/YQ
```

Biblioteka podpisuje ten ciąg algorytmem zgodnym z kluczem:
- RSA-PSS z `SHA-256`, `MGF1(SHA-256)` i długością soli `32` bajty
- ECDSA P-256 z `SHA-256`; wynik może być zwrócony jako `"p1363"` (domyślnie) albo `"der"`

Przykład z zaszyfrowanym PEM:

```python
url = service.build_certificate_verification_url(
    seller_nip="1234567890",
    context_identifier_type="Nip",
    context_identifier_value="1234567890",
    certificate_serial="1",
    invoice_hash="Utbj3k-g3MKZRmlfk5QMPn8m8w4eOfSxpJrZiDkRJ4Y",
    signing_certificate_pem=certificate_pem,
    private_key_pem=private_key_pem,
    private_key_password="tajne-haslo",
)
```

Jeżeli korzystasz już z `XadesKeyPair.from_pem_files(...)` albo `XadesKeyPair.from_pkcs12_file(...)`, możesz też najpierw znormalizować klucz do niezaszyfrowanego PKCS#8 PEM, a następnie przekazać wynikowe `certificate_pem` i `private_key_pem` do `VerificationLinkService`.

Powiązane: [QR PNG](qr.md).
