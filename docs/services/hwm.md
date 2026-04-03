# HWM i deduplikacja (`ksef_client.services.hwm`)

W przyrostowym pobieraniu faktur typowo pojawiają się zagadnienia:
- HWM (High Water Mark)
- paczkami obciętymi (`isTruncated`)
- duplikatami między oknami czasowymi

Funkcje wspierają utrzymanie poprawnego punktu kontynuacji.

## `update_continuation_point(continuation_points, subject_type, package) -> None`

Aktualizuje słownik `continuation_points` według priorytetu:
- jeśli odpowiedź zawiera oficjalny watermark serwera `permanentStorageHwmDate` → używa jego
- w przeciwnym razie, jeśli odpowiedź jest obcięta (`isTruncated`) i zawiera `lastPermanentStorageDate` → używa jego
- w przeciwnym razie, dla odpowiedzi metadata query bez jawnego watermarka, liczy lokalny fallback jako maksymalne `permanentStorageDate` z listy faktur
- jeśli nie ma nic sensownego → usuwa punkt kontynuacji dla `subject_type`

Ważne: lokalny fallback z rekordów jest deterministyczny i nie zależy od kolejności faktur na stronie.

## `get_effective_start_date(continuation_points, subject_type, window_from) -> str`

Zwraca:
- `continuation_points[subject_type]` jeśli istnieje,
- w przeciwnym razie `window_from`.

## `dedupe_by_ksef_number(metadata_summaries) -> dict[str, dict]`

Usuwa duplikaty na podstawie `ksefNumber` (case-insensitive).

Działa na rekordach z `_metadata.json` zwróconych przez `ExportWorkflow.download_and_process_package()`.
