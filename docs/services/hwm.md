# HWM i deduplikacja (`ksef_client.services.hwm`)

W przyrostowym pobieraniu faktur typowo pojawiają się zagadnienia:
- HWM (High Water Mark)
- paczkami obciętymi (`isTruncated`)
- duplikatami między oknami czasowymi

Funkcje wspierają utrzymanie poprawnego punktu kontynuacji.

## `update_continuation_point(continuation_points, subject_type, package) -> None`

Aktualizuje słownik `continuation_points` według priorytetu z dokumentacji MF
(„Przyrostowe pobieranie faktur”):
- jeśli odpowiedź jest **obcięta** (`isTruncated`) i zawiera `lastPermanentStorageDate` → używa jego
  (to ostatnia faktura, która zmieściła się w paczce)
- w przeciwnym razie, jeśli odpowiedź zawiera oficjalny watermark serwera
  `permanentStorageHwmDate` → używa jego
- w przeciwnym razie, dla odpowiedzi metadata query bez jawnego watermarka, liczy lokalny fallback
  jako **najnowsze** `permanentStorageDate` z listy faktur (porównanie po rzeczywistym czasie, a nie
  po zapisie tekstowym — znaczniki z różnymi strefami i 7-cyfrowym ułamkiem sekundy sortują się
  chronologicznie)
- jeśli nie ma nic sensownego → usuwa punkt kontynuacji dla `subject_type`

Kolejność ma znaczenie: dla paczki obciętej watermark serwera wskazuje **koniec** okna, więc
wznowienie od niego pomijałoby faktury z przedziału między obiema datami.

Ważne: lokalny fallback z rekordów jest deterministyczny i nie zależy od kolejności faktur na stronie.

## `get_effective_start_date(continuation_points, subject_type, window_from) -> str`

Zwraca:
- `continuation_points[subject_type]` jeśli istnieje,
- w przeciwnym razie `window_from`.

## `dedupe_by_ksef_number(metadata_summaries) -> dict[str, dict]`

Usuwa duplikaty na podstawie `ksefNumber` (case-insensitive).

Działa na rekordach z `_metadata.json` zwróconych przez `ExportWorkflow.download_and_process_package()`.
