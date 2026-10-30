# Końcowa walidacja synchronizacji XML — 2026-10-30

Zweryfikowane drzewo kodu: `fa07cb8160bd1a92f4be907f69cbc801743a975d`,
gałąź `feat/invoice-xml-sync`, PR #115. Ten raport uzupełnia historyczne wyniki
w `invoice-xml-sync-final-review.md` i `invoice-xml-ci-recovery.md`.

## Poprawione błędy i bezpieczeństwo

- `d1537a9`: zachowanie HTTP Retry-After i licznika błędów po przerwaniu retry
  XML dla 429/502/503/504 oraz odrzucanie cyfr Unicode przed obliczeniem CRC
  numeru KSeF. Dodano 30 przypadków regresyjnych sync/async.
- Diagnostyka live ujawnia wyłącznie dozwolone etapy, liczniki i kody SDK;
  stdout/stderr procesu z tokenami i XML pozostają ukryte. Regresja rzeczywistego
  procesu sprawdza brak wycieku. Supervisor egzekwuje limity i sprząta potomków.
- Helper XML korzysta z rzeczywistych, już widocznych metadanych. Zapisuje
  kolejkę `pending`, kończy pierwszy proces, uruchamia drugi, sprawdza gotowe XML,
  hash oraz brak kolejnych claimów/pobrań przy powtórzeniu. Wysyłkę nowej faktury
  i propagację do HWM nadal sprawdza osobny wymagany scenariusz metadanych.
- Przegląd obejmował izolację kontekstów, HTTP, walidację identyfikatorów/hashów,
  publikację plików, dowiązania i pliki specjalne, migracje/transakcje SQLite,
  fencing, restart oraz anulowanie. Po opisanych poprawkach nie potwierdzono
  dodatkowej podatności wymagającej zmiany kodu. Audyt przypiętych zależności
  `requirements-ci.lock` nie wykazał znanych podatności.

## Testy i rzeczywiste pokrycie

[GitHub Python application](https://github.com/smekcio/ksef-client-python/actions/runs/41094642175):
wszystkie zadania zakończone sukcesem, w tym lint, pakiety instalacyjne oraz
macierz Python 3.10, 3.11, 3.12, 3.13 i 3.14-dev. Kontrola zgodności modeli API
również przeszła.

- GitHub, pełny test Python 3.12: **3771 passed, 14 skipped, 1 warning**,
  **20 144/20 144 linii SDK, 100,00%, zero brakujących linii**.
- Niezależny pełny test Linux/WSL Debian, Python 3.12.13, zależności
  `requirements-ci.lock`, dokładne źródła z `git archive fa07cb8`:
  **3771 passed, 14 skipped, 61 subtests passed, 1 warning**, 174,89 s,
  exit code 0. **20 144/20 144 linii SDK, 100,00%**, każdy moduł bez brakujących linii.
- Polecenie: `python -m pytest -q --cov=ksef_client --cov-fail-under=100
  --cov-report=term --cov-report=json:coverage-review.json`.
- Pomiar pochodzi z jednego pełnego przebiegu. Nie zmieniano progu ani
  konfiguracji wykluczeń pokrycia. Jest to pokrycie linii SDK.
- Windows: 48 testów helpera i końcowych regresji zaliczonych;
  `python tools/lint.py --strict` również zaliczony, łącznie z mypy.

## Live KSeF TEST

[Przebieg 41094644469](https://github.com/smekcio/ksef-client-python/actions/runs/41094644469)
na powyższym SHA zakończył się **7 passed, 1 failed**. Scenariusz restartu XML
osiągnął limit 600,68 s w pierwszej fazie. Bezpieczna diagnostyka:
`stage=metadata`, `visible_count=131`, `target_visible=true`, `observed=0`,
`pending=0`, `blocked=0`, `metadata_complete=false`, `failure=deadline`.

Odnalezienie celu już działa, ale nie został potwierdzony zapis jego metadanych
ani późniejsze pobranie XML. Stan trwały z `describe()` nie zawiera powodu
zakończenia konkretnego `run_once()`. Następny krok wymaga zachowania dozwolonych
pól raportu wykonania metadanych i numerycznej diagnostyki HTTP. Nie ma jeszcze
podstaw do uznania live E2E za naprawione; 100% pokrycia jednostkowego tego nie
zastępuje. Wszystkie osiem wymaganych scenariuszy nadal pozostaje w bramie.

## Uprawnienia środowiska

Użytkownik zezwolił na tymczasowe dopuszczenie wyłącznie
`feat/invoice-xml-sync` do środowiska `ksef-test`. Po uruchomieniu zadania wpis
tymczasowy usunięto. Odczyt polityk potwierdził ponownie wyłącznie `main`
(istniejący identyfikator `64458368`).

## Aktualizacja dla `e2309d5`

[Pełne CI](https://github.com/smekcio/ksef-client-python/actions/runs/41110932783)
na `e2309d59daa8ad9dac0e4653cf3b5c98904884c5` jest zielone: **3772 passed,
14 skipped, 1 warning**, Python 3.10–3.14, **20144/20144 linii SDK (100%)**.
Lint, mypy, modele i pakowanie również przeszły. SDK nie zmieniło się od `fa07cb8`;
zmiany dotyczą helpera live, kolejności gate i diagnostyki. Lokalna regresja
helpera, final review i gate: **81 passed**.

W pierwszej próbie [41110935026](https://github.com/smekcio/ksef-client-python/actions/runs/41110935026/attempts/1)
scenariusz XML przeszedł o 18:56:10 UTC, po rzeczywistym restarcie procesu.
Przeszło też sześć kolejnych scenariuszy. Cały job został anulowany podczas
ostatniego testu metadanych, po błędnej interpretacji opóźnionych, niepełnych
stanów kroków zwracanych przez API GitHub. Nie zaliczamy tej próby jako pełnego
sukcesu gate. Ponowienie nr 2 dotyczy tego samego SHA i dokładnie tego samego
wheela; jego wynik wymaga osobnego potwierdzenia.

## Wynik ponowienia nr 2 i poprawka helpera metadanych

[Próba 2](https://github.com/smekcio/ksef-client-python/actions/runs/41110935026/attempts/2)
na `e2309d5`: **7 passed, 1 failed**. XML przeszedł w 7,65 s. Ostatni test,
restart synchronizacji metadanych, zakończył się po 1740,10 s w drugim procesie.
Nie przypisujemy tego wyniku awarii GitHub ani nie uznajemy całego gate za zielony.

Helper metadanych czeka teraz po zamknięciu sesji na jej zakończenie i UPO,
jak istniejący scenariusz fasady. Wcześniej akceptacja faktury mogła zostać
potraktowana jako zakończenie publikacji. Normalizuje oba zapisy numeru przed
porównaniem obserwacji i odczytem SQLite. Wspólna, redagowana diagnostyka obu
helperów zachowuje fazę procesu, etap, dozwolone powody oraz numeryczne statusy
HTTP, bez XML, tokenów i identyfikatorów faktur. Regresja z prawdziwymi adapterami
sprawdza kolejność close → session.wait → UPO → discovery, oba zapisy numeru
oraz bootstrap i inkrementalną kontynuację na tej samej bazie. Wynik nowego
live wymaga ponownego sprawdzenia; przyczyna poprzedniego deadline nie jest
jeszcze potwierdzona przez dozwolone kody transportu.
