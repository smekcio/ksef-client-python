# Kryptografia i metadane (`ksef_client.services.crypto`)

Te funkcje są wykorzystywane w sesjach online/batch oraz w eksporcie.

W typowych scenariuszach wywołania są realizowane przez workflow (`OnlineSessionWorkflow`, `BatchSessionWorkflow`, `ExportWorkflow`).

## `EncryptionData`

Struktura trzymająca komplet danych szyfrowania:

- `key`: 32 bajty (AES-256)
- `iv`: 16 bajtów (AES-CBC)
- `encryption_info`: `EncryptionInfo` z polami zakodowanymi base64 (`encrypted_symmetric_key`, `initialization_vector`)

## `build_encryption_data(public_certificate) -> EncryptionData`

Generuje nowy klucz symetryczny + IV i szyfruje klucz publicznym certyfikatem KSeF (RSA-OAEP SHA-256).

`public_certificate` to certyfikat o usage `SymmetricKeyEncryption`.

## `build_send_invoice_request(...) -> dict`

Buduje payload do wysyłki faktury w sesji online:
- liczy `invoiceHash` i `encryptedInvoiceHash` (SHA-256 base64)
- szyfruje fakturę AES-256-CBC/PKCS7
- wstawia `encryptedInvoiceContent` jako Base64

Parametry:
- `offline_mode`: flaga trybu offline (jeśli dotyczy)
- `hash_of_corrected_invoice`: dla korekty technicznej

## AES (szyfrowanie/odszyfrowanie)

- `encrypt_aes_cbc_pkcs7(data, key, iv) -> bytes`
- `decrypt_aes_cbc_pkcs7(data, key, iv) -> bytes`

## Generatory

- `generate_symmetric_key() -> bytes` (32B)
- `generate_iv() -> bytes` (16B)

## Metadane

- `get_file_metadata(data: bytes) -> FileMetadata` (rozmiar + SHA-256 base64)
- `get_stream_metadata(stream) -> FileMetadata` (to samo, ale dla strumienia; przywraca pozycję, jeśli się da)

## Szyfrowanie tokena KSeF (niskopoziomowe)

Dostępne są również funkcje niskopoziomowe zwracające bajty zamiast Base64:

- `encrypt_ksef_token_rsa(public_certificate, token, timestamp_ms) -> bytes`
- `encrypt_ksef_token_ec(public_certificate, token, timestamp_ms, output_format="java") -> bytes`

W praktyce częściej wykorzystywana jest funkcja wyższego poziomu: `ksef_client.services.encrypt_ksef_token()`.
