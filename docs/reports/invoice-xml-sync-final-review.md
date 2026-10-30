# Finalne bug review i security review — 2026-10-29

Przegląd gałęzi `feat/invoice-xml-sync`, PR #115, na bazie
`bcbd0525ce06fa2d06fe2372519aae72182ff110`. Poprawki przygotowano lokalnie na
`fix/invoice-xml-final-review`.

**Końcowy wynik: 100,00% pokrycia SDK — 20144/20144 linii, zero brakujących.**
Pełny przebieg na rzeczywistym Linuksie (Debian przez WSL, CPython 3.12.13)
z wymaganym `--cov-fail-under=100`: **3752 passed, 14 skipped, 61 subtests passed**.
Obejmuje końcowe poprawki i wszystkie 30 nowych przypadków regresyjnych.
Nie zmieniano konfiguracji pokrycia ani nie dodawano wykluczeń kodu.

## Potwierdzone i poprawione błędy

**P1: przerwanie retry HTTP 502/503/504 gubiło trwały Retry-After i licznik błędów.**

Przy włączonym retry transportu i odpowiedzi np. HTTP 503 z
`Retry-After: 86400`, przekroczenie deadline'u lub anulowanie podczas oczekiwania
powodowało zapis `document_time_budget`/`cancelled` oraz ponowienie po 5 sekundach.
Serwer żądał doby przerwy. Licznik `failures` pozostawał bez zmian, więc powtarzane
przerwania mogły także omijać `max_failures`. Trwała kolejka nie respektowała
wówczas deklarowanego harmonogramu i mogła zwiększać obciążenie niedostępnego API.

Przyczyną było odzyskiwanie poprzedniego wyjątku HTTP wyłącznie dla statusu 429.
Worker korzysta teraz ze wspólnej klasyfikacji `_failure` dla poprzedniego błędu
HTTP także po przerwaniu retry. Zachowuje pełny termin, klasyfikację i licznik
błędów. Anulowanie nadal jest przekazywane do wywołującego.

Test regresyjny przed poprawką odtworzył błąd dla HTTP 502: oczekiwano
`transient_http`, otrzymano `document_time_budget`. Nowy zestaw obejmuje 24
kombinacje: sync/async, HTTP 429/502/503/504 oraz deadline, anulowanie kooperacyjne
i `asyncio.CancelledError`. Sprawdza również brak możliwości przedwczesnego claimu.

**P2: cyfry Unicode w numerze KSeF zatrzymywały synchronizację metadanych.**

Wspólny walidator numerów używał `\d` bez ograniczenia do ASCII. Przykładowo
cyfra arabsko-indyjska w NIP przechodziła przez regex, po czym kodowanie do ASCII
na potrzeby CRC zgłaszało `UnicodeEncodeError`. Nowy adapter SQLite wywołuje ten
walidator przy zapisie metadanych, więc wadliwy identyfikator zatrzymywał cały
commit zamiast tworzyć pojedyncze zadanie `blocked`. Ten sam problem dotyczył
walidacji historycznych wierszy podczas migracji lub przejmowania zadań.

Dodano `re.ASCII` do wzorca. Odrzucenie następuje teraz jako zwykły niepoprawny
format. Sześć testów sync/async z cyfrą Unicode na różnych pozycjach NIP
sprawdza ukończenie metadanych, izolację błędnej pozycji jako
`invalid_ksef_number` bez pobierania oraz poprawne pobranie innej faktury.
Przed poprawką test potwierdził `UnicodeEncodeError` z kodu tego worktree.

## Zakres przeglądu bezpieczeństwa

Sprawdzono granice środowiska i kontekstu, walidację numerów i hashy, ograniczenia
odbioru HTTP, przekierowania i kodowanie odpowiedzi, publikację bez nadpisywania,
dowiązania/reparse points i pliki specjalne, prywatność diagnostyki, migracje
SQLite, transakcje, fencing, odzyskiwanie po przerwaniu oraz ścieżki anulowania
sync/async. Poza opisanymi błędami nie potwierdzono dodatkowej podatności wymagającej
zmiany kodu. Archiwum i baza nadal wymagają prywatnego katalogu bez niezaufanych
procesów zapisujących, zgodnie z udokumentowanym kontraktem.

## Walidacja

- Windows, CPython 3.12.2; świeże `.venv` utworzone przez `uv venv`, zależności
  z `requirements-dev.txt` i `build`.
- `.venv/Scripts/python.exe tools/lint.py --strict`: PASS; obejmuje zgodność
  generowanych artefaktów, kompilację, `pip check`, Ruff oraz mypy dla `src/tests`.
- `uvx pip-audit --no-deps --disable-pip -r requirements-ci.lock`: brak znanych
  podatności w przypiętych zależnościach.
- `uvx pip-audit --path .venv/Lib/site-packages`: brak znanych podatności w
  zależnościach faktycznie użytych do końcowej walidacji.
- `.venv/Scripts/python.exe -m pytest -q tests/test_invoice_xml_final_review.py
  tests/test_ksef_number.py tests/test_path_param_validators.py`: **49 passed**
  po ostatniej zmianie walidatora; obejmuje wszystkie 30 nowych przypadków.
- Dodatkowy pełny przebieg globalnym Pythonem: **3732 passed, 28 skipped**.
  Rozpoczął się przed poprawką Unicode i zawierał pierwsze 24 nowe przypadki;
  nie zastępuje powyższej końcowej walidacji walidatora.
- Pełny przebieg izolowanym Pythonem:
  `.venv/Scripts/python.exe -m pytest -q --cov=ksef_client --cov-fail-under=100
  --cov-report=term-missing`: **3732 passed, 28 skipped, 61 subtests passed**,
  jeden warning dotyczący przestarzałego API Pillow w istniejącym teście QR.
  Kolekcja tego przebiegu również poprzedzała dodanie sześciu przypadków Unicode.
- Końcowy suplement po zmianie walidatora, z dopisaniem pomiaru:
  `.venv/Scripts/python.exe -m pytest -q tests/test_invoice_xml_final_review.py
  tests/test_ksef_number.py tests/test_path_param_validators.py --cov=ksef_client
  --cov-append --cov-report=term --cov-fail-under=0`: **49 passed**.
  Łącznie pokryto **20130/20144 linii (99,9305%)**; oba zmienione moduły mają 100%.
  **Brama 100% nie przeszła lokalnie na Windows.** Pozostałe 14 linii jest w
  `invoice_xml_storage.py`: ścieżki POSIX oraz odrzucanie dowiązań/plików
  specjalnych niewykonane na tym hoście. Nie obniżano progu CI ani nie dodawano
  wykluczeń pokrycia. Poniższy pełny przebieg na rzeczywistym Linuksie zamyka
  brakującą walidację progu 100% dla końcowego drzewa.
- **Końcowy pełny przebieg Linux, CPython 3.12.13, Debian/WSL x86_64:**
  `.venv/bin/python -m pytest -q --cov=ksef_client --cov-fail-under=100
  --cov-report=term-missing --cov-report=json:.coverage-review.json
  --cov-report=xml:coverage.xml`: **3752 passed, 14 skipped, 61 subtests passed**,
  **100,00% (20144/20144 linii), zero brakujących linii w każdym module**.
  Exit code 0, czas 165,97 s. Jeden istniejący warning Pillow opisany wyżej.
  Jest to jeden pełny przebieg, bez łączenia pomiarów między systemami.
- Linuksowe środowisko utworzono od zera, instalując `requirements-ci.lock`.
  Kopia źródeł pochodzi z archiwum bazowego SHA oraz końcowych zmienionych plików;
  zgodność obu poprawionych modułów i nowych testów z worktree potwierdzono
  porównaniem SHA-256. `tools/lint.py --strict` na Linuksie również: **PASS**.
- Szczegółowe lokalne artefakty: `.tmp/invoice-xml-final-linux-coverage.json`,
  `.tmp/invoice-xml-final-linux-coverage.xml`, `.tmp/.coverage-invoice-xml-linux`.
  Podsumowanie dołączone do repozytorium:
  [invoice-xml-sync-final-coverage.json](invoice-xml-sync-final-coverage.json).

Globalne środowisko ma starsze narzędzia i konflikty zależności innych aplikacji.
Nie zmieniano go; wyniki końcowe opierają się na izolowanym środowisku.

Nie uruchamiano lokalnie live KSeF ani pełnej macierzy Python 3.10–3.14.
Walidację wykonano na Windows oraz na rzeczywistym Linuksie przez WSL.
Zielone kontrole GitHub dla bazowego SHA nie stanowią walidacji lokalnej poprawki.
W chwili odczytu kontrola live TEST bazowego SHA nadal trwała. Brak znanych CVE
i pokrycie testami nie stanowią gwarancji braku wszystkich podatności.
