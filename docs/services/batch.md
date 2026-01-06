# Batch – przygotowanie paczki (`ksef_client.services.batch`)

Te funkcje przygotowują paczkę wsadową do wysyłki:
- split ZIP na części ≤100MB **przed szyfrowaniem**
- szyfrowanie każdej części (AES)
- metadane `batchFile` i `fileParts` do payloadu otwarcia sesji

## `encrypt_batch_parts(zip_bytes, key, iv, max_part_size=MAX_BATCH_PART_SIZE_BYTES)`

Zwraca `(encrypted_parts, batch_file_info)`:

- `encrypted_parts`: lista zaszyfrowanych partów (kolejność = `ordinalNumber`)
- `batch_file_info`: dict w formacie oczekiwanym przez KSeF jako `batchFile`

W przypadku paczek większych niż 100MB, `max_part_size` nie powinien być zwiększany – limit 100MB jest ograniczeniem po stronie KSeF.

## `build_batch_file_info(zip_bytes, encrypted_parts) -> dict`

Buduje metadane ZIP-a i partów:
- SHA-256 base64 i rozmiar całego ZIP-a (przed szyfrowaniem)
- SHA-256 base64 i rozmiar każdej zaszyfrowanej części (po szyfrowaniu)

Najczęściej wywoływane wewnętrznie przez `encrypt_batch_parts()`.
