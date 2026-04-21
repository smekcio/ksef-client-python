# Workflows i narzędzia pomocnicze (`ksef_client.services.workflows`)

Klasy łączące wywołania API z operacjami lokalnymi: kryptografia, ZIP, upload partów i polling.
W większości integracji stanowią podstawową warstwę użycia biblioteki.

## Klasy pomocnicze do wysyłki i pobierania partów

### `BatchUploadHelper.upload_parts(part_upload_requests, parts, parallelism=1, skip_ordinals=None, progress_callback=None)`

Wysyła party paczki wsadowej na pre-signed URL zwrócone w `partUploadRequests`.

Zasady wynikające z KSeF:
- nagłówek `Authorization` nie jest przesyłany,
- pary łączone są po `ordinalNumber`, dlatego `parts` może być przekazane jako `list[bytes]`
  albo `list[tuple[int, bytes]]`.

Parametry:
- `parallelism`: wykorzystuje `ThreadPoolExecutor` w wariancie sync,
- `skip_ordinals`: pomija wskazane numery partów,
- `progress_callback(ordinal_number)`: wywoływany po każdym udanym uploadzie partu.

### `AsyncBatchUploadHelper.upload_parts(part_upload_requests, parts, skip_ordinals=None, progress_callback=None)`

Wariant asynchroniczny. Również obsługuje `skip_ordinals` i `progress_callback`.

### `ExportDownloadHelper.download_parts(parts)` / `download_parts_with_hash(parts)`

Pobiera części paczki eksportu z pre-signed URL. Token nie jest wymagany.

`download_parts_with_hash()` zwraca `(bytes, x-ms-meta-hash)` dla każdej części.

Async odpowiednik: `AsyncExportDownloadHelper`.

## Auth workflow

### `AuthCoordinator.authenticate_with_xades_key_pair(...) -> AuthResult`

Wariant uwierzytelnienia XAdES oparty o `XadesKeyPair`.

### `AuthCoordinator.authenticate_with_xades(...) -> AuthResult`

Scenariusz:
1. `POST /auth/challenge`
2. budowa XML `AuthTokenRequest`
3. podpis XAdES
4. `POST /auth/xades-signature`
5. polling `GET /auth/{referenceNumber}` aż `status.code == 200`
6. `POST /auth/token/redeem`

### `AuthCoordinator.authenticate_with_ksef_token(...) -> AuthResult`

Scenariusz analogiczny, ale z szyfrowaniem wartości `token|timestampMs` certyfikatem KSeF
(`KsefTokenEncryption`) i wysyłką na `POST /auth/ksef-token`.

Async odpowiednik: `AsyncAuthCoordinator`.

### `AuthResult`

- `reference_number`
- `authentication_token`
- `tokens` / wygodne aliasy `access_token`, `refresh_token`

## Sesja interaktywna (online)

### `OnlineSessionWorkflow.open_session(...) -> OnlineSessionHandle`

Buduje `EncryptionData` na bazie certyfikatu KSeF (`SymmetricKeyEncryption`), otwiera sesję
i zwraca handle sesji.

### `OnlineSessionWorkflow.resume_session(state, *, access_token=None) -> OnlineSessionHandle`

Wznawia sesję z `OnlineSessionState`. Stan nie zawiera tokenu, więc po wznowieniu:
- przekaż `access_token` jawnie, albo
- ustaw token na kliencie `KsefClient(..., access_token=...)`.

### `OnlineSessionHandle`

Publiczne pola i metody:
- `reference_number`
- `session_reference_number` jako alias kompatybilności
- `valid_until`
- `form_code`
- `encryption_data`
- `get_state() -> OnlineSessionState`
- `send_invoice(...)`
- `get_status()`
- `list_invoices()`
- `list_failed_invoices()`
- `get_invoice_status(...)`
- `get_invoice_upo_by_ref(...)`
- `get_invoice_upo_by_ksef(...)`
- `get_upo(...)`
- `close()`

### `OnlineSessionState`

Lekki, wersjonowany stan JSON przeznaczony do resume:
- `schema_version`
- `kind="online"`
- `reference_number`
- `form_code`
- `valid_until`
- `symmetric_key_base64`
- `iv_base64`
- `upo_v43`

Nie zawiera:
- tokenów,
- XML faktur,
- `invoice_reference`.

### Zgodność wsteczna

`OnlineSessionResult` pozostaje aliasem do `OnlineSessionHandle`.

Async odpowiedniki:
- `AsyncOnlineSessionWorkflow`
- `AsyncOnlineSessionHandle`

## Sesja wsadowa (batch)

### `BatchSessionWorkflow.open_session(...) -> BatchSessionHandle`

Scenariusz:
1. budowa `EncryptionData` z `SymmetricKeyEncryption`,
2. ZIP -> podział <=100MB -> szyfrowanie partów,
3. `POST /sessions/batch` (open),
4. zwrot handle'a gotowego do uploadu partów.

### `BatchSessionWorkflow.resume_session(state, *, zip_bytes, access_token=None) -> BatchSessionHandle`

Wznawia sesję z `BatchSessionState` i odtwarza zaszyfrowane party na podstawie przekazanego
`zip_bytes`.

Workflow weryfikuje, że odtworzony `BatchFileInfo` jest identyczny z zapisanym w stanie.
Jeśli źródło batch się zmieniło, resume kończy się błędem i upload nie jest wykonywany.

### `BatchSessionWorkflow.open_upload_and_close(...) -> str`

One-shot convenience API z zachowaną zgodnością wsteczną:
`open_session() -> upload_parts() -> close()`.

### `BatchSessionHandle`

Publiczne pola i metody:
- `reference_number`
- `session_reference_number` jako alias kompatybilności
- `form_code`
- `batch_file`
- `part_upload_requests`
- `encryption_data`
- `get_state() -> BatchSessionState`
- `upload_parts(parallelism=1, skip_ordinals=None, progress_callback=None)`
- `get_status()`
- `list_invoices()`
- `list_failed_invoices()`
- `get_upo(...)`
- `close()`

### `BatchSessionState`

Lekki, wersjonowany stan JSON przeznaczony do resume:
- `schema_version`
- `kind="batch"`
- `reference_number`
- `form_code`
- `batch_file`
- `part_upload_requests`
- `symmetric_key_base64`
- `iv_base64`
- `upo_v43`
- `offline_mode`

Nie zawiera:
- tokenów,
- ZIP-a,
- XML faktur,
- listy już wysłanych `uploaded_ordinals`,
- ścieżki do źródła batch.

Te dane powinny być utrzymywane przez warstwę workflow/CLI po stronie aplikacji.

Async odpowiedniki:
- `AsyncBatchSessionWorkflow`
- `AsyncBatchSessionHandle`

## Eksport (pobieranie paczek)

### `ExportWorkflow.download_and_process_package(package, encryption_data) -> PackageProcessingResult`

Pobiera wszystkie części paczki eksportu, odszyfrowuje je AES i skleja w ZIP.
Potem rozpakowuje ZIP bezpiecznie (`unzip_bytes_safe`) i zwraca:
- `metadata_summaries`
- `invoice_xml_files`

Async odpowiednik: `AsyncExportWorkflow`.

### `PackageProcessingResult`

- `metadata_summaries: list[dict[str, Any]]`
- `invoice_xml_files: dict[str, str]`
