# Workflows i narzędzia pomocnicze (`ksef_client.services.workflows`)

Klasy łączące wywołania API z operacjami lokalnymi (kryptografia, ZIP) w spójne scenariusze. W większości integracji stanowią podstawową warstwę użycia biblioteki.

## Klasy pomocnicze do wysyłki i pobierania partów

### `BatchUploadHelper.upload_parts(part_upload_requests, parts, parallelism=1)`

Wysyła party paczki wsadowej na pre-signed URL zwrócone w `partUploadRequests`.

Zasady wynikające z KSeF:
- nagłówek `Authorization` nie jest przesyłany (wysyłka po pre-signed URL),
- pary łączone są po `ordinalNumber` (dlatego `parts` może zostać przekazane jako `list[bytes]` albo `list[tuple[int, bytes]]`).

`parallelism` wykorzystuje `ThreadPoolExecutor` (sync). Dla większych paczek zwykle skraca czas wysyłki.

### `AsyncBatchUploadHelper.upload_parts(part_upload_requests, parts)`

Wariant asynchroniczny – wysyła party równolegle przez `asyncio.gather()`.

### `ExportDownloadHelper.download_parts(parts)` / `download_parts_with_hash(parts)`

Pobiera części paczki eksportu (pre-signed URL). Token nie jest wymagany.

`download_parts_with_hash()` zwraca `(bytes, x-ms-meta-hash)` dla każdej części.

Async odpowiednik: `AsyncExportDownloadHelper`.

## Auth workflow

### `AuthCoordinator.authenticate_with_xades_key_pair(...) -> AuthResult`

Wariant uwierzytelnienia XAdES oparty o `XadesKeyPair`. Zamiast przekazywania surowych stringów PEM, wykorzystywany jest obiekt wczytany z kontenera PKCS#12 (`.pfx`/`.p12`) albo z pary plików certyfikat/klucz.

Powiązane: `XadesKeyPair` (opis: `services/xades.md`).

### `AuthCoordinator.authenticate_with_xades(...) -> AuthResult`

Scenariusz:
1) `POST /auth/challenge`
2) budowa XML `AuthTokenRequest`
3) podpis XAdES (wymaga dodatku `xml`)
4) `POST /auth/xades-signature`
5) polling `GET /auth/{referenceNumber}` aż `status.code == 200`
6) `POST /auth/token/redeem` → `accessToken` + `refreshToken`

Najczęściej używane parametry:
- `context_identifier_type`: `"nip" | "internalId" | "nipVatUe" | "peppolId"`
- `context_identifier_value`: np. NIP
- `subject_identifier_type`: np. `"certificateSubject"` (lub `"certificateFingerprint"`)
- `verify_certificate_chain`: przydatne w TE
- `enforce_xades_compliance`: gdy `True`, ustawia nagłówek `X-KSeF-Feature: enforce-xades-compliance`
- `poll_interval_seconds`, `max_attempts`: parametry pollingu

### `AuthCoordinator.authenticate_with_ksef_token(...) -> AuthResult`

Scenariusz analogiczny, ale zamiast XAdES:
- szyfrowanie wartości `token|timestampMs` certyfikatem KSeF (`KsefTokenEncryption`)
- wysłanie JSON na `POST /auth/ksef-token`

Parametry:
- `method`: `"rsa"` (domyślnie) albo `"ec"`
- `ec_output_format`: `"java"` lub `"csharp"` – ważne tylko dla `ec` (format bajtów zgodny z ekosystemem)

Async odpowiednik: `AsyncAuthCoordinator`.

### `AuthResult`

- `reference_number`: numer operacji uwierzytelnienia
- `authentication_token`: token tymczasowy (do statusu + redeem)
- `tokens`: `AuthenticationTokensResponse` (`access_token`, `refresh_token`)

## Sesja interaktywna (online)

### `OnlineSessionWorkflow.open_session(...) -> OnlineSessionResult`

Buduje `EncryptionData` na bazie certyfikatu KSeF (`SymmetricKeyEncryption`), otwiera sesję i zwraca:

- `session_reference_number`
- `encryption_data` (klucz/IV + encryptionInfo)

### `OnlineSessionWorkflow.send_invoice(...)`

Szyfruje XML faktury (AES-256-CBC/PKCS7), liczy hashe/rozmiary i wysyła na:
`POST /sessions/online/{referenceNumber}/invoices`

Parametry:
- `offline_mode`: flaga trybu offline (jeśli dotyczy)
- `hash_of_corrected_invoice`: wymagane dla korekty technicznej (jeśli dotyczy)

### `OnlineSessionWorkflow.close_session(reference_number, access_token)`

Zamyka sesję i inicjuje generowanie UPO.

Async odpowiednik: `AsyncOnlineSessionWorkflow`.

### `OnlineSessionResult`

- `session_reference_number`
- `encryption_data` (`EncryptionData`)

## Sesja wsadowa (batch)

### `BatchSessionWorkflow.open_upload_and_close(...) -> str`

Scenariusz:
1) budowa `EncryptionData` z `SymmetricKeyEncryption`
2) ZIP → podział ≤100MB → szyfrowanie partów
3) `POST /sessions/batch` (open)
4) wysyłka partów wg `partUploadRequests` (bez Bearer)
5) `POST /sessions/batch/{referenceNumber}/close`

Parametry:
- `offline_mode`: flaga trybu offline (jeśli dotyczy)
- `parallelism`: poziom równoległości wysyłki (sync)
- `upo_v43`: negocjacja UPO v4-3 nagłówkiem `X-KSeF-Feature`

Zwraca `referenceNumber` sesji wsadowej.

Async odpowiednik: `AsyncBatchSessionWorkflow`.

## Eksport (pobieranie paczek)

### `ExportWorkflow.download_and_process_package(package, encryption_data) -> PackageProcessingResult`

Pobiera wszystkie części paczki (pre-signed URL), odszyfrowuje je AES i skleja w ZIP.
Potem rozpakowuje ZIP bezpiecznie (`unzip_bytes_safe`) i zwraca:
- `metadata_summaries` – rekordy z `_metadata.json` (jeśli plik był w paczce)
- `invoice_xml_files` – mapę `nazwaPliku.xml -> treść XML`

Async odpowiednik: `AsyncExportWorkflow`.

### `PackageProcessingResult`

- `metadata_summaries: list[dict[str, Any]]`
- `invoice_xml_files: dict[str, str]`
