# Domknięcie lokalnego odbioru synchronizacji faktur

Data: 28 października 2026. Commit uzupełnień:
`872e52325f380f7294987e27764b0f2b4579eb57`.
Ten raport uzupełnia [przegląd krytyczny](invoice-sync-critical-review.md)
o luki wskazane podczas końcowego porównania z §17 planu.

## Zamknięte punkty

| Punkt planu | Dowód po uzupełnieniu |
| --- | --- |
| §17B: nowy proces po każdej stronie | `tests/test_invoice_sync_processes.py::test_restart_after_every_page_no_early_hwm`: cztery kombinacje sync/async i default/autocommit. Każda strona jest pobierana w osobnym interpreterze uruchamianym z `-I`. Jedynym utrwalonym stanem wznowienia jest SQLite. Zbiór wymusza offsety przy tej samej dacie oraz wiele okien 100 dni. Test porównuje dokładne zbiory dokumentów, obserwacji i outboxu, stały cycle_to, generację i kolejne rewizje. HWM jest None aż do ostatniej strony. |
| §17C: wspólny kontrakt rzeczywistych adapterów | `tests/test_invoice_sync_store_contract.py`: 116 przypadków wspólnych dla sync i async. 64 z nich wstrzykują awarię przed/po każdym z ośmiu SQL partii, w obu trybach SQLite, w tym po COMMIT przed receiptem. Kontrola obejmuje dokładny outcome, atomiczność trzech tabel i checkpointu, CAS oraz jawne odzyskanie. Pozostałe przypadki sprawdzają receipt, stale load, generację po fence, replay, izolację scope, hash, outbox i uszkodzony odczyt. |
| §17D: tabela błędów magazynu | Ten sam zestaw zawiera 40 kombinacji operation/outcome/failure_scope/raise_on_error dla obu API: load/not_started oraz commit/not_started, rolled_back, committed i unknown; scope stream/store; raise True/False. Store-wide pozostaje wyjątkiem, a zdrowa rola kończy pracę przy błędzie lokalnym. Niepotwierdzone pokrycie jest usuwane z raportu. |
| §17B: pozostały budżet po trzech pustych rolach | `tests/test_invoice_sync_failures.py::test_backfill_uses_remaining_budget_after_three_empty_roles`: sync i async, kontrolowany zegar oraz rzeczywisty magazyn. Trzy krótkie role kończą się po jednej stronie; długi backfill korzysta z dalszych kolejek i przekracza sumarycznie domyślne time_budget/4, mieszcząc się w limicie globalnym. |
| §19: obsługa completed/partial/failed w quickstarcie | [Pierwsza integracja](../invoice-sync.md#pierwsza-integracja) jawnie ustawia raise_on_error=False i obsługuje failed przed completed/partial. Wyjaśnia odpowiedzialność schedulera, obsługę 403 i wyjątki, które nadal przerywają worker. |

Adapter async w testach należy do aplikacji testowej: tworzy połączenie,
wykonuje SQL i zamyka je w jednym dedykowanym wątku. Wspólna kontrola w harnessie
potwierdza, że żadne z tych działań nie odbywa się na wątku event loop.
SDK nie otrzymało ukrytego `to_thread` ani zależności od SQLite.

## Weryfikacja

| Środowisko | Wynik pełnego zestawu |
| --- | --- |
| Linux, Python 3.10, 3.11, 3.12, 3.13, 3.14 | Po 3467 passed, 13 skipped i 61 zaliczonych podtestów. |
| Windows, Python 3.12 | 3458 passed, 22 skipped i 61 zaliczonych podtestów. |
| Dokładny zainstalowany wheel, wybrany zestaw sync/search/pagination/transport | 494 passed, zero pominięć, bez importu lokalnego src także w procesach potomnych. |

Wszystkie nowe przypadki lokalne wykonano. Pominięcia pełnego zestawu dotyczą
dotychczasowych testów live oraz przypadków platformowych/opcjonalnych.
Zestaw ma o 105 przypadków więcej niż przed domknięciem. Pokrycie instrukcji/linii
SDK na Linux i Windows wynosi 100% (18 769/18 769); nie jest to pomiar pokrycia
gałęzi. Przechodzą strict lint, Ruff, mypy (278 plików), generatory i pip check.
Zbudowano wheel i sdist oraz zweryfikowano ich manifest i sumy kontrolne.
Pełna macierz zachowuje ostrzeżenia o przyszłych usunięciach API Pillow
i `asyncio.iscoroutinefunction` (Python 3.14); nie są to niezaliczone testy.

Dokładne wyniki macierzy, pokrycie i hashe dystrybucji znajdują się w
[invoice-sync-acceptance-closure.json](invoice-sync-acceptance-closure.json).

Drzewo SDK pozostaje `e02bce19e93bba3b353a23c18e1e27c63a3f2fca`, identyczne
z drzewem poddanym poprzedniemu przeglądowi i pomiarom RSS. Ta zmiana uzupełnia
testy oraz dokumentację; nie powtarza pomiaru pamięci niezmienionego SDK.
Poprzednie trzy pary pomiarów i maksimum różnic 180 224 B zachowują swój
[opis i zakres](invoice-sync-review-validation.json).

## Brama przed wydaniem

Live A/HWM/B/restart pozostaje do rzeczywistego wykonania w CI, zgodnie
z decyzją użytkownika: „Zakończ testy lokalne; live pozostaw do bramy CI”.
Lokalne testy nie są dowodem przejścia tej bramy.

Sprawdzono konfigurację `.github/workflows/required-test-e2e.yml`, manifest
`tests/required_test_e2e.json` oraz kontroler `tools/verify_e2e_results.py`:
nowy node jest obowiązkowy, zestaw ma siedem scenariuszy, workflow kieruje
wykonanie do środowiska `ksef-test`, instaluje i weryfikuje dokładny wheel,
a kontroler odrzuca brak, skip, failure, powtórzenie i rerun scenariusza.
Worker live ma dwie osobne fazy i nadzór grup procesów na Linux.
Nie zmieniano ochrony środowiska ani sposobu udostępniania sekretów.

Wymagany przed wydaniem pozostaje zielony wynik tej bramy. Plan wymaga też
wydania minor po 0.21.0; lokalnie zbudowane artefakty 0.21.0 służą weryfikacji,
nie są nowym wydaniem. Nie wykonywano push, tworzenia PR ani publikacji.
