# Odbiór lokalny InvoiceSync

Data: 28 października 2026. Gałąź: `feat/invoice-metadata-sync`.
Kod i testy: `0c5e125281d1a23a90b64bf09ce18ddb29d640dd`.
Drzewo źródeł SDK: `5569613d29398932bbc926111ef8c6dc476e496a`.
Późniejszy commit tego raportu nie zmienia kodu SDK ani testów.

Implementacja obejmuje pełne obserwacje stron, identity i walidację kursora bez
I/O, ograniczony transport HTTP, niezmienne checkpointy, pull API, koordynację
niezależnych ról, sync/async, CAS/receipt, SQLite i procedury odzyskania.
Nowe API pozostaje w lokalnej gałęzi rozwojowej po 0.21.0; publikacja wymaga
wydania minor i przejścia obowiązkowej bramy TEST.

## Testy i narzędzia

| Środowisko | Wynik pełnego pytest |
| --- | --- |
| Linux / Python 3.10.20 | 3333 passed, 13 skipped, 61 subtests passed |
| Linux / Python 3.11.2 | 3333 passed, 13 skipped, 61 subtests passed |
| Linux / Python 3.12.13 | 3333 passed, 13 skipped, 61 subtests passed; **100% pokrycia SDK** |
| Linux / Python 3.13.13 | 3333 passed, 13 skipped, 61 subtests passed |
| Linux / Python 3.14.4 | 3333 passed, 13 skipped, 61 subtests passed |
| Windows / Python 3.12.9 | 3326 passed, 20 skipped, 61 subtests passed; **100% pokrycia SDK** |

Na Linux wszystkie 13 pominięć dotyczy testów live wymagających `KSEF_E2E=1`.
Windows ma dodatkowe pominięcia zależne od platformy lub opcjonalnych komponentów.
Żaden deterministyczny test synchronizacji nie jest xfail ani pomijany;
test grup procesów watchdogu jest przeznaczony dla Linux CI.
Ostrzeżenia obejmują istniejącą deprecjację Pillow; nie są awariami testów.

Zaliczone:

- `tools/lint.py --strict`: Ruff, mypy dla 273 plików, compileall, pip check
  oraz kontrola wygenerowanych modeli ze snapshotu OpenAPI;
- `tools/generate_async_facade.py --check` oraz test semantyczny czystej fabryki;
- osobny przykład konsumenta async pull API sprawdzony przez mypy;
- build wheel i sdist, kompletność źródeł i schematów, instalacja bazowa,
  CLI oraz walidacja FA(3) z wheela;
- **601 passed i 15 subtests passed** dla regresji na zainstalowanym dokładnym
  wheelu, bez importowania lokalnego `src`.

Podczas równoległych przebiegów wykryto kolizję współdzielonego cache mypy
w istniejącym teście modeli. Test otrzymał prywatny katalog cache, bez zmiany
asercji. Pełne przebiegi powtórzono i zakończyły się powodzeniem.

## Zweryfikowane granice poprawności

- A → HWM → zamknięcie bazy → B → wznowienie inkluzywnie od HWM; dokładne
  zbiory numerów, cztery role, brak wczesnego przesunięcia HWM.
- Wieloletnie okna, restart po każdej stronie, stare parametry aktywnego cyklu,
  równe daty, puste wyniki i precyzja siedmiu cyfr ułamka z różnymi offsetami.
- Round-robin i 403 jednej roli przy postępie pozostałych; oddzielne limity
  globalne/kroku, nadrzędny deadline i cancellation.
- Konflikty hashy na stronie, między stronami, po wznowieniu i między zadaniami;
  obserwacje ról oraz outbox zachowują właściwe klucze idempotencji.
- Rzeczywista SQLite: awaria przed i po każdym SQL, również COMMIT;
  dane i checkpoint razem albo żadne. Default oraz autocommit.
- Dwa procesy konkurujące o ten sam scope; dwa różne zadania konkurujące
  o wspólny dokument ze sprzecznymi hashami.
- Nieprawidłowe receipts, uszkodzone checkpointy, limity przed i po kanonikalizacji,
  nieczytelny load, izolacja namespace/środowiska/kontekstu, restart i fencing.
- Async: odbiór rozpoczętego commita po wielokrotnym anulowaniu, pobranie wyjątku
  zadania i jawny adapter z SQLite w osobnym workerze.
- Transport: Content-Length i rzeczywiste bajty, kompresja, 3xx, wolne porcje
  z lokalnego serwera HTTP, nested auth, 401 → refresh → 200/401, cooldown 429
  przy błędzie body oraz izolacja współbieżnych zwykłych i limited requestów.
- Redakcja str/repr/to_dict i pełnych tracebacków błędów magazynu.

Przegląd transportu wykrył oczekiwanie na pełny blok 64 KiB przed kontrolą
deadline'u. Zastąpiono je sprawdzaniem każdej porcji sieciowej i dodano regresję
z lokalnym wolnym serwerem. Przegląd zapisu domknął bezpieczną obsługę błędów
rollbacku; przegląd API poprawił publiczne typowanie async stream handles.

Kontrakt TEST ponownie sprawdzono 28.10.2026: API 2.9.0, okna do 100 dni UTC,
przyrosty przez PermanentStorage/Asc. Źródło: [OpenAPI TEST](https://api-test.ksef.mf.gov.pl/docs/v2/openapi.json).

## Pamięć i czasy

Linux WSL2, kernel 6.18.54.1, CPython 3.12.13, httpx i modele SDK,
SQLite z cache 2 MiB. Każdy rozmiar zbioru uruchomiony w świeżym procesie.
Strona 250, identyczne dane wiersza i konfiguracja; RSS z
`resource.getrusage(RUSAGE_SELF).ru_maxrss * 1024`.

| Para | Peak RSS 50 tys. | Peak RSS 500 tys. | max(0, różnica) |
| --- | ---: | ---: | ---: |
| 1 | 56,688 MiB | 57,410 MiB | 0,723 MiB |
| 2 | 57,168 MiB | 57,398 MiB | 0,230 MiB |
| 3 | 57,090 MiB | 57,297 MiB | 0,207 MiB |

Maksymalna różnica: **757 760 B**, poniżej **32 MiB**.
Limit nie dotyczy całkowitego RAM procesu. Zbiór jest generowany stronami,
a odbiorca zapisuje dokumenty w SQLite bez materializowania całej historii.

Dodatkowy stress test granicy 10 000 równoczasowych rekordów: 40 kroków,
checkpoint do **262 406 B**, peak RSS **63 692 800 B**. Mediana serializacji
checkpointu **0,273 ms**, commit p50/p95 **19,94/24,30 ms**, krok p50/p95
**35,37/46,71 ms**.

Osobny stress test strony o maksymalnym page_size=250 i licznych zagnieżdżonych
metadanych: snapshot **14 598 251 B**, peak RSS **121 536 512 B**, krok **728 ms**.
Nie narzucano arbitralnego limitu 32/64 MiB na cały proces; body i snapshot
pozostają ograniczone do 16 MiB.

To syntetyczne pomiary lokalnego odbiorcy. Czas nadrobienia rzeczywistej historii
zależy także od kwot i opóźnień KSeF. Surowe bezpieczne wyniki znajdują się
w [invoice-sync-measurements.json](invoice-sync-measurements.json).
Odtwarzanie: `python tools/benchmark_invoice_sync.py --output result.json`
na Linux/Python 3.12; warianty stresowe używają `--worker 10000 --boundary 10000`
oraz `--worker 250 --boundary 250 --dense-page`.

## Dokładne artefakty i brama live

Artefakty z commita `0c5e125281d1a23a90b64bf09ce18ddb29d640dd`, wersja robocza 0.21.0:

- wheel SHA-256: `26b53d785464278904cc7bd0d54abfc86012073ec20a560bc6775679916e937a`;
- sdist SHA-256: `88173d098a6cf468f81f85d9e9e8a4545906ca5b983f7414474e0e06e6c5b3f1`.

Manifest został zapisany i zweryfikowany przez `tools/release_artifacts.py`.
Lokalne pliki oraz logi pozostają w `.tmp/acceptance-dist/` i `.tmp/acceptance-*`.

Nowy obowiązkowy node bramy TEST:
`tests/test_e2e_invoice_sync.py::test_e2e_test_environment_invoice_sync_restart`.
Jeden node nadzoruje bootstrap A/H1 i drugi proces z B/wznowieniem. Sprawdza
installed-wheel mode, bajty SDK, granice skanu i requestów, HWM oraz trwałą SQLite.
Watchdog ma wspólne 1800 s, sprzątanie grup procesów, ograniczone oczekiwanie
na zakończenie i brak ujawniania wyjścia prywatnych workerów. Testy watchdogu
potwierdziły zakończenie potomków ignorujących SIGTERM.

**Live nie wykonano lokalnie — zgodnie z decyzją użytkownika pozostaje do
obowiązkowej, chronionej bramy CI.** Manifest/kontroler wymagają rzeczywistego
zaliczenia node'a i odrzucają skip, failure, brak wyniku lub ponowienie scenariusza.
Nie zmieniano ochrony środowiska, pochodzenia zaufanych testów ani wyjątków gałęzi.
Nie wykonywano push, PR ani publikacji.
