# Odpowiedź na bug/security review z 28 października 2026

Przeanalizowano `REVIEW_BUG_SECURITY_INVOICE-METADATA-SYNC_2026-10-28.md`
(SHA-256 `feeffb92d0a78c2426aa3a480bcb94924b0e49eb2c70abd8ed0cb6122a2316fd`),
dotyczący tipa `45eaf32`. Poprawki kodu i regresje są w commicie
`50ace739b8de9632ce9f517f5de40a688796c5d8`.

## Decyzje i wykonane poprawki

| ID | Ocena i działanie |
| --- | --- |
| A1 | Naprawione. Load, walidacja scope/cursora, zachowanie potwierdzonego checkpointu i czasu obserwacji poprzedzają końcowy check budżetu. Wolny odczyt daje partial ze starym, nadal potwierdzonym coverage. Nie przypisujemy pokrycia checkpointowi przed poprawną walidacją. Regresja na rzeczywistej SQLite, sync i async. |
| A2 | Naprawiona przenośność. Parametry 2–4 MiB mają krótkie jawne ID. Zarzut o niemożliwości historycznych wyników wymaga korekty: pytest 9.2 automatycznie skraca duże ID. Lokalna sonda Windows: domyślna strategia daje 2 passed, legacy daje 4 errors; po poprawce cały test stanu przechodzi również w legacy. Nowe dowody zawierają wersję pytest. |
| A3 | Potwierdzone ograniczenie, jawnie zaakceptowane w kontrakcie kooperatywnym. Timeout pojedynczego odczytu już był zmniejszany do control.remaining(); proponowana w review zmiana timeoutu nie usuwa powolnego odbioru nagłówków w wielu odczytach. Nie dodano pozornej poprawki ani zależności od prywatnych pól poola HTTPX/httpcore. Dokumentacja wskazuje dokładnie tę granicę oraz wymóg nadzorcy procesu przy twardym deadline. Nie twierdzimy, że SDK zapewnia łączny timeout nagłówków. |
| A4 | Naprawione przed alokacją grafu. Preflight bajtów JSON kontroluje 500 000 tokenów i 32 kontenery głębokości przed json.loads odpowiedzi metadanych. Stringi są pomijane bez ich dekodowania/kopiowania. Odpowiedzi błędów HTTP w limited mode też przechodzą kontrolę przed response.json(). Checkpoint ma preflight 100 000 tokenów przed dekoderem i dotychczasowy limit 50 000 węzłów po dekodowaniu. Limit body pozostaje 16 MiB; legalna gęsta strona 14,6 MB przechodzi. To ograniczenie struktury, nie obietnica stałego RSS całego procesu. |
| A5 | Naprawione. Non-finite float jest odrzucany; tylko rzeczywiste przekroczenie rozmiaru snapshotu staje się page_snapshot. inf/-inf/NaN w obserwacjach dają invalid_metadata, bez sugestii naprawy przez zmniejszenie strony. |
| A6 | Zachowany globalny abort, udokumentowany i przetestowany w obu API. CapacityError oznacza wyczerpanie pamięci rozliczeniowej wspólnego limitera. Nie ma uzasadnienia do traktowania go jako awarii jednej roli ani do dodania szerokiego except KsefError. |
| A7 | Naprawione. describe([None]) identyfikuje nowy scope tak samo jak run_once. |
| A8 | Naprawione. Wszystkie dziewięć wyjątków jest w exceptions.__all__; regresja porównuje publiczne klasy z eksportami. |
| A9 | Naprawiony zgłoszony scenariusz. Windows po braku/błędzie/timeout taskkill próbuje process.kill() i odbiera proces. Regresje obejmują trzy rodzaje błędu. run_phases zamienia rzeczywisty timeout fazy na TimeoutError i zachowuje typ innych przerwań. Live nadal wymaga Linux i nadzoru całej grupy; fallback Windows nie jest deklaracją równoważnej obsługi wszystkich potomków. |
| B1 | Naprawione. Callable load/commit są sprawdzane przed pracą; sync odrzuca deklarowane async metody oraz zamyka omyłkowo zwróconą coroutine. Async wymaga awaitable wyników. Pomyłka jest jawnym TypeError, niezależnie od raise_on_error, a nie failed/invalid_checkpoint. Nadal dopuszczamy zwykłą funkcję zwracającą awaitable w poprawnym trybie async. |
| B2 | Dodane fail-closed guards w czystych helperach: make_batch wiąże scope/spec z previous, begin_cycle sprawdza scope/spec checkpointu. Nie zmienia to prawidłowych publicznych przejść. |
| B3 | Poprawione typ wejścia checkpointu, unknown dla niezgodnego receipt oraz ścisły timestamp HWM przed zatwierdzeniem (date-only daje invalid_hwm). Poprawne offsety w istniejących timestampach nadal są obsługiwane; równoważność czasu jest semantyczna i nie wymaga migracji zapisanych checkpointów. |
| B4 | Poprawione. Niezmienny, mały summary checkpointu przechowuje scope i pola skalarne; ich odczyty nie parsują wielomegabajtowego kursora. Spec/active nadal zwracają niezależne kopie. Batch zna observation_count, więc liczenie records_delivered nie odtwarza całego snapshotu. Zachowano fallback dla ręcznie utworzonej partii bez cached count. |
| B5 | Zachowane celowo. Poufne original_error służy diagnostyce i może utrzymywać traceback z ramkami. Nie wycinamy niejawnie tracebacku przekazanego przez adapter. Do długiego przechowywania/telemetrii należy używać bezpiecznego to_dict() i zwalniać pełny raport; repr/JSON nadal nie ujawniają oryginalnego błędu. |
| B6 | Poprawione: opcjonalność observed_bytes, nazwa reason_code, status wdrożenia planu, siedem scenariuszy TEST. Przykład SQLite używa standardowego json.dumps zamiast prywatnego canonical_json/MAX_PAGE_BYTES; źródłem walidacji i ograniczenia strony jest gotowa partia SDK. |
| B7 | Poprawione: niezależny oczekiwany hash środowiska, konkretny typ błędu kursora, identyfikacja awarii według SQL zamiast ordinalu COMMIT==8. Tabela 40 przypadków bada propagację i izolację koordynatora; rzeczywistą klasyfikację adaptera bada osobna macierz 64 awarii SQL. Benchmark respektuje --worker --output, przekazuje --dense-page i zapisuje parametry/środowisko. Wyniki historyczne dotyczą różnych SHA i drzew SDK, nie jednego commita. Najnowszy autorytatywny pomiar jest wskazany w JSON tego przeglądu. |
| B8 | Bez zmiany globalnego kontraktu. Nie skracamy serwerowego cooldownu wspólnego budżetu, nie wyłączamy użytkownikowi proxy/CA z otoczenia i nie udajemy ochrony przed kodem, który może podmienić prywatny transport we własnym procesie. Własność transportu i konfiguracji pozostaje granicą zaufania aplikacji. |

## Dowody i granice wniosków

31 nowych regresji w `tests/test_invoice_sync_external_review.py` obejmuje
najważniejsze zmienione zachowania, strukturę JSON przed dekoderem, eksporty,
taksonomię błędów, pomyłki trybów i fallback nadzorcy. Testy z dużymi parametrami
nie są pomijane. Pełne wyniki, pokrycie linii, wersje środowiska, dokładny wheel
i nowe pomiary RSS są w
[invoice-sync-external-review-validation.json](invoice-sync-external-review-validation.json).

Wyniki dla tego commita:

- Linux/Python 3.10–3.14: po **3498 passed**, 13 skipped, 61 podtestów;
- Windows/Python 3.12: **3489 passed**, 22 skipped, 61 podtestów;
- pokrycie instrukcji/linii SDK na Linux i Windows: **18 873/18 873 (100%)**;
- dokładny zainstalowany wheel: **525 passed**, bez pominięć i bez lokalnego src;
- Windows, pełny zestaw testów stanu przy strategii ID legacy: **59 passed**;
- strict lint, Ruff, mypy (280 plików), generatory, pip check oraz wheel/sdist: zaliczone;
- trzy pary 50k/500k: maksimum różnic RSS **1 355 776 B < 32 MiB**;
- legalna gęsta strona: snapshot **14 598 251 B**, peak RSS procesu **121 520 128 B**.

Wszystkie nowe regresje lokalne wykonano. Pełne zestawy pomijają dotychczasowe
scenariusze live i przypadki platformowe/opcjonalne. Pozostaje jedno ostrzeżenie
o przyszłym usunięciu Image.getdata w istniejącym teście QR; deprecated
asyncio.iscoroutinefunction zastąpiono inspect.iscoroutinefunction.

Poprzednie raporty pozostają historycznymi pomiarami swoich commitów:
`invoice-sync-measurements.json` dotyczy `0c5e125`/drzewa `5569613`,
a `invoice-sync-review-validation.json` — `bbd64e6`/drzewa `e02bce1`.
Różne maksima RSS tych oddzielnych prób nie są sprzecznym wynikiem jednej próby.
Nie sumujemy ich ani nie wybieramy minimum jako aktualnego wyniku.

Live A/HWM/B/restart nadal pozostaje obowiązkową bramą CI przed wydaniem,
zgodnie z decyzją użytkownika. Nie uruchamiano go lokalnie i nie zastępujemy go
testami mockowanymi. Nie wykonano push, utworzenia PR ani publikacji.
