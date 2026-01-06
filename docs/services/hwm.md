# HWM i deduplikacja (`ksef_client.services.hwm`)

W przyrostowym pobieraniu faktur typowo pojawiają się zagadnienia:
- HWM (High Water Mark)
- paczkami obciętymi (`isTruncated`)
- duplikatami między oknami czasowymi

Funkcje wspierają utrzymanie poprawnego punktu kontynuacji.

## `update_continuation_point(continuation_points, subject_type, package) -> None`

Aktualizuje słownik `continuation_points` na podstawie pól paczki eksportu:
- jeśli `isTruncated` i jest `lastPermanentStorageDate` → to jest punkt startowy następnego okna
- w przeciwnym razie, jeśli jest `permanentStorageHwmDate` → to jest punkt startowy następnego okna
- jeśli nie ma nic sensownego → usuwa punkt kontynuacji dla `subject_type`

## `get_effective_start_date(continuation_points, subject_type, window_from) -> str`

Zwraca:
- `continuation_points[subject_type]` jeśli istnieje,
- w przeciwnym razie `window_from`.

## `dedupe_by_ksef_number(metadata_summaries) -> dict[str, dict]`

Usuwa duplikaty na podstawie `ksefNumber` (case-insensitive).

Działa na rekordach z `_metadata.json` zwróconych przez `ExportWorkflow.download_and_process_package()`.
