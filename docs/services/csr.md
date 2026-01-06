# CSR (`ksef_client.services.csr`)

CSR jest potrzebny przy enrollment certyfikatu KSeF.

## `CsrResult`

- `csr_base64`: CSR w DER zakodowany Base64
- `private_key_base64`: klucz prywatny w DER (PKCS8) zakodowany Base64

## `generate_csr_rsa(info, key_size=2048) -> CsrResult`

Generuje CSR na RSA (domyślnie 2048).

## `generate_csr_ec(info) -> CsrResult`

Generuje CSR na krzywej P-256 (SECP256R1).

## `info` – jakie pola są używane

Funkcje składają subject/DN na podstawie kluczy w `info`:
- `commonName`
- `organizationName`
- `countryName`
- `organizationIdentifier`
- `serialNumber`
- `uniqueIdentifier`

`info` pochodzi zwykle z `client.certificates.get_enrollment_data(...)` i powinno zostać odwzorowane na format oczekiwany przez te funkcje.

Najczęstszy problem: DN w CSR musi pasować do danych z KSeF (KSeF to weryfikuje). W przypadku błędów enrollmentu w pierwszej kolejności należy porównać subject/DN.
