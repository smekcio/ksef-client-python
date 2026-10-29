# Synchronizacja metadanych faktur

`InvoiceSync` i `AsyncInvoiceSync` pobierają historię oraz przyrosty **metadanych**
faktur. Każda rola ma osobny checkpoint. Aplikacja zapewnia uwierzytelnionego
klienta, magazyn transakcyjny i harmonogram kolejnych uruchomień.

To jedyny bieżący opis integracji, kontraktu i weryfikacji tej funkcji.
Live TEST dla commita `2c8d113` zaliczył wszystkie siedem wymaganych scenariuszy
w [chronionej bramie CI](https://github.com/smekcio/ksef-client-python/actions/runs/40757621518).
Synchronizacja metadanych jest dostępna od 0.22.0; brama sprawdza dokładny artefakt
przed publikacją. Wyniki związane z SHA zawiera
[jeden plik dowodów](reports/invoice-sync-validation.json).

## Pierwsza integracja

```python
from ksef_client import (
    Ksef, KsefClientOptions, KsefEnvironment, RetryConfig, TokenCredentials,
)

options = KsefClientOptions(
    base_url=KsefEnvironment.TEST.value,
    retry=RetryConfig(
        max_retries=5,
        retryable_post_paths=frozenset({"/invoices/query/metadata"}),
    ),
)
with Ksef.connect(
    options=options, credentials=TokenCredentials(token),
    context_type="Nip", context_value=nip,
) as client:
    sync = client.invoices.sync(
        namespace="tenant-42", sync_key="erp-invoices",
        since="2024-01-01T00:00:00Z",
    )
    report = sync.run_once(
        application_store, time_budget=600, raise_on_error=False,
    )
    failed = [stream for stream in report.streams if stream.status == "failed"]
    if failed:
        handle_failed_streams(failed)  # alert / naprawa według stop_reason
    elif report.complete:
        handle_completed_metadata_cycle(report)
    else:
        schedule_next_run(report)  # partial: wznowienie zapisanego postępu
```

`application_store` implementuje opisany poniżej protokół. Publiczny adapter
`SQLiteInvoiceSyncStore.open(path, timeout=5)` oraz wariant
`await AsyncSQLiteInvoiceSyncStore.open(path)` są dostępne w `ksef_client`.
Domyślnie synchronizują tylko metadane (`enqueue_xml=False`). Istniejąca baza
z dawnego przykładu wymaga jawnej migracji również w tym trybie — adapter nie
zmienia schematu przy otwarciu. Zatrzymaj zapisujących workerów i wykonaj backup;
[procedura aktualizacji](invoice-xml-sync.md#aktualizacja-istniejącej-bazy)
nie wymaga włączania XML ani podawania zastępczego identyfikatora storage.
[Trwała kolejka i synchronizacja XML](invoice-xml-sync.md) opisuje włączenie pobrań.
Własne połączenie SQLite musi mieć skończony timeout, np.
`sqlite3.connect(private_database_path, timeout=5)`.

Funkcje `handle_failed_streams`, `handle_completed_metadata_cycle` i
`schedule_next_run` należą do aplikacji. Scheduler powinien uruchamiać kolejne
cykle także po sukcesie; po `failed` decyzja o ponowieniu zależy od przyczyny
(np. 403 wymaga poprawy uprawnień). `raise_on_error=False` pozwala obsłużyć
oczekiwane awarie poszczególnych strumieni w raporcie. Błąd jednej roli nie powinien
wyłączać harmonogramu pozostałych ról. Awaria całego magazynu,
błąd programistyczny, nadrzędny deadline i anulowanie nadal przerywają wywołanie;
powinien je obsłużyć nadrzędny worker aplikacji.

Fabryka nie wykonuje I/O. Domyślnie wybiera Subject1 i Subject2. Pozostałe role
włącza się przez `subject_types=("Subject1", "Subject2", "Subject3", "SubjectAuthorized")`.
Można też przekazać `queries=[InvoiceQueryFilters(...)]` zamiast `since` i ról.
Każde query musi mieć `PermanentStorage`, jawny początek ze strefą,
`to=None` i `restrict_to_permanent_storage_hwm_date=True`.
Dozwolone są 1–4 różne role, najwyżej jedno query na rolę.

Klient niskiego poziomu udostępnia tę samą fabrykę przez
`client.invoices.sync(..., context_key="Nip:...")`. Fasada pobiera context_key
z połączenia. Synchronizator nie przejmuje własności klienta.

Retry odczytowego POST jest jawne. Bez powyższej allowlisty 429/5xx zatrzymuje
strumień; kolejny `run_once` wznawia zapisany stan. SDK nie zmienia wspólnych
options i nie dodaje osobnej pętli retry. Token jest pobierany od providera przy
każdej rzeczywistej próbie HTTP. Statyczny access token sam nie zyskuje refreshu.

## Wynik i budżet pracy

`run_once(store, *, time_budget=600, max_pages_per_stream=None,
step_time_budget=None, cancellation=None, raise_on_error=True)` wykonuje najwyżej
jeden cykl każdego wybranego strumienia. Cykle aktywne są wznawiane; nowe mają
zamrożony koniec równy czasowi UTC początku uruchomienia.

Strumienie dostają kolej po jednej partii. Wspólnie korzystają z całego budżetu;
domyślny limit pojedynczego kroku to `time_budget / liczba_strumieni`.
Można go zwiększyć przez `step_time_budget`. Nie jest to skumulowany limit roli.
`max_pages_per_stream` liczy zatwierdzone strony, także puste, bez partii sterujących.

| Status strumienia | Znaczenie |
| --- | --- |
| `completed` | Cały skan zakończony, ostatnia strona i HWM zatwierdzone razem. |
| `partial` | Zapisany postęp; powód `work_limit`, `time_budget` lub `step_time_budget`. |
| `failed` | Oczekiwana awaria HTTP, paginacji, integralności, limitu lub zapisu. |

Domyślnie błędy strumieni dają `KsefSyncRunError` po obsłużeniu pozostałych ról.
Ten sam raport jest w `error.report`. `raise_on_error=False` zwraca raport z
`failed`. Awaria całego magazynu, obcy scope, błąd programistyczny, nadrzędny
deadline i anulowanie zawsze przerywają wywołanie.

`records_delivered` liczy obserwacje, również ponowne odczyty znanych faktur.
`pages_committed` liczy zatwierdzone strony. `new_streams` wskazuje nowe scope.
`to_dict()` raportu jest bezpiecznym opisem diagnostycznym; oryginalne błędy
pozostają poufnym atrybutem `original_error` wyników.
Pełny raport może przez traceback oryginalnego błędu utrzymywać ramki i dane
strony w pamięci. Do długiego przechowywania diagnostyki używaj `to_dict()`
i zwalniaj pełne obiekty raportów.
Każdy wynik JSON zawiera także własne `coverage`, nawet gdy nie ma wspólnego
pokrycia wszystkich ról. `stop_reason` błędu używa wyłącznie znanych kodów SDK;
nie kopiuje dowolnego tekstu `reasonCode` serwera ani adaptera.

Budżety są kooperatywne. Timeout HTTP ogranicza również pojedynczy odczyt
sieciowy i jest zmniejszany do pozostałego deadline'u. Nie jest to łączny timeout
fazy nagłówków: HTTPX może odebrać je w wielu odczytach. Serwer wysyłający
nagłówki małymi porcjami może więc przekroczyć budżet przed kolejnym checkiem SDK.
Anulowanie kooperatywne również czeka na powrót z takiego odczytu.
Rozpoczęty COMMIT jest odbierany do końca zgodnie z timeoutem adaptera;
async chroni go przed anulowaniem i odbiera wynik także po wielokrotnym cancel.
Twardy limit czasu wymaga nadzorcy procesu. Wymuszone zakończenie nie dowodzi rollbacku.

## HWM i pokrycie

Pośrednia strona nigdy nie podnosi `committed_hwm`. Nowy cykl zaczyna się od
poprzedniego HWM **inkluzywnie**, z zachowaniem pełnej precyzji czasu API.
Skan wieloletni korzysta z istniejącej maszyny okien do 100 dni UTC. Koniec
całego skanu jest stały; granice kolejnych żądań HTTP wynikają z okien,
obcięcia wyników i clippingu HWM.

`coverage` opisuje zamknięty przedział `[initial_from, committed_hwm]` dla filtrów
danego strumienia. Podczas następnego częściowego cyklu stare pokrycie pozostaje
ważne. `common_coverage` jest przecięciem potwierdzonych pokryć wybranych ról;
brak pokrycia, puste przecięcie lub niepotwierdzony zapis daje `None`.
Raport zawiera zaobserwowaną generację, rewizję i czas obserwacji.
Nie jest liniową migawką wszystkich checkpointów bazy.

`complete=True` oznacza ukończenie cykli do HWM serwera. HWM może być starszy
od aktualnego czasu. Pokrycie zależy od wybranych filtrów i aktualnych uprawnień.
Brak faktury w późniejszej odpowiedzi nie jest poleceniem usunięcia danych.

## Scope i zmiana konfiguracji

Klucz checkpointu to `(namespace, environment, context_key, sync_key, stream_id)`.
Środowisko jest SHA-256 pełnego efektywnego adresu API, obliczanym przez
`operations.environment_key`; `/v2` i `/api/v2` tworzą różne scope.
Context_key jest etykietą aplikacji i musi odpowiadać uwierzytelnieniu.

Stream_id jest skrótem kanonicznego query, w tym roli i początku historii.
Równoważne chwile z różnymi offsetami dają ten sam identyfikator.
Zmiana filtrów lub początku tworzy nowy backfill. Dodanie roli nie resetuje
pozostałych. Wycofanie roli nie usuwa danych. Scope można sprawdzić przed I/O
przez `sync.streams`. Stare checkpointy pozostają w magazynie aplikacji.

`page_size` (10–250, domyślnie 100) i `window_days` (1–100, domyślnie 100)
nie należą do tożsamości query. Aktywny cykl używa zapisanych wartości;
zmiana konfiguracji obowiązuje od następnego cyklu.

## Protokół magazynu i pull API

```python
class InvoiceSyncStore(Protocol):
    def load(self, scope: InvoiceSyncScope) -> InvoiceSyncCheckpoint | None: ...
    def commit(self, batch: InvoiceSyncBatch) -> InvoiceSyncCommitReceipt: ...
```

`load` czyta autorytatywny magazyn z gwarancją read-your-writes. Zwraca `None`
wyłącznie dla brakującego wiersza. Musi porównać pełny scope wiersza z JSON.

Jedna transakcja `commit` sprawdza generację i oczekiwaną rewizję przez CAS,
kontroluje hash dokumentów, zapisuje wszystkie obserwacje strony oraz następny
checkpoint i `last_commit_id`. Brak dopasowania CAS jest konfliktem.
Dokument ma klucz `(namespace, environment, context_key, ksef_number)`;
obserwacja zawiera dodatkowo sync_key i stream_id. Sprzeczny hash wycofuje całą
stronę, również między różnymi zadaniami. Pozostałe metadane aktualizują widok
konkretnego strumienia.

Receipt to dokładnie `(scope, generation_id, revision, commit_id)` nowego stanu.
`batch.confirm(receipt)` sprawdza receipt i zwraca checkpoint w pamięci.
Nie zastępuje transakcji. Po niepewnym COMMIT nie wolno bezwarunkowo powtarzać
zapisu. Adapter kończy/ogradza stare zadania i połączenie; następne uruchomienie
zaczyna od `load`, a kolejny CAS bezpiecznie rozstrzyga konkurencję.

```python
from datetime import datetime, timezone

cycle_to = datetime.now(timezone.utc).isoformat()
stream = sync.streams[0]
checkpoint = store.load(stream.scope)
if checkpoint is None or checkpoint.phase == "idle":
    batch = stream.begin_cycle(checkpoint, until=cycle_to)
    checkpoint = batch.confirm(store.commit(batch))
while True:
    batch = stream.next_batch(checkpoint)
    if batch is None:
        break
    checkpoint = batch.confirm(store.commit(batch))
```

To jeden skończony cykl. `next_batch(None)` jest błędem.
`sync.describe(checkpoints)` oblicza raport bez I/O.
Partie utrwalają głęboki snapshot; zmiana zwróconych modeli/list nie zmienia partii.

Async: użyj `AsyncKsef`, `AsyncInvoiceSyncStore` i `await sync.run_once(store)`.
Fabryka, begin_cycle, confirm i operacje administracyjne pozostają zwykłymi
metodami. `next_batch`, load i commit są awaitowalne. Adapter aplikacji musi
korzystać z async DB lub jawnie zarządzać własnym workerem z timeoutem;
nie wykonuj sqlite3 na pętli zdarzeń.
Pomylenie trybu magazynu daje `TypeError` z nazwą oczekiwanego trybu; nie jest
błędem strumienia maskowanym przez `raise_on_error=False`.

## Jawny limit transportu

`BaseHttpClient.request(..., max_bytes=None)` i odpowiednik async pozostawiają
zwykły odbiór bez zmian. Dodatnia liczba całkowita ogranicza rzeczywiste bajty
odpowiedzi na każdej próbie. Bool, zero, wartości ujemne i float są odrzucane
przed I/O. `request_json_limited(..., max_bytes=N)` jest skrótem tej samej ścieżki
wymagającym limitu; nie uruchamia osobnej pętli HTTP.

Ścieżka synchronizacji metadanych korzysta z limitu 16 MiB. Dotychczasowe metody
`search_invoice_metadata(...).pages()` i `search_invoice_metadata_range(...).pages()`
nie włączają tego limitu. Argument przechodzi jawnie przez retry,
próbę HTTP, odświeżenie po 401 i odbiór odpowiedzi. Nie jest przechowywany
w ContextVar i nie przechodzi na zagnieżdżone żądania auth ani inne taski/wątki.
Każde z nich otrzymuje własny limit lub domyślne None.

Adres limited request jest zamrożony przed auth/admission i pozostaje ten sam
podczas retry oraz ponowienia po refreshu. Oryginalna ścieżka nadal decyduje
o allowliście POST i walidacji presigned URL. Odbiór wymusza identity encoding,
odrzuca 3xx, sprawdza Content-Length oraz faktyczne porcje, a następnie zamyka
odpowiedź również przy wyjątku/anulowaniu. Nagłówki 429 aktualizują wspólny
cooldown przed ewentualnym błędem body. Zabezpieczenia presigned URL i usuwanie
Authorization przy skip_auth pozostają aktywne.

## Limity, błędy i odzyskanie

Limity wynoszą: HTTP body i kanoniczna strona 16 MiB, checkpoint 4 MiB,
kursor 2 MiB, query 128 KiB, głębokość checkpointu 16 i 50 000 węzłów.
Przed dekodowaniem odpowiedzi metadanych kontrolowane są także głębokość
32 kontenerów i budżet 500 000 tokenów struktury (klucze, wartości i kontenery).
Kontrola pomija zawartość stringów bez tworzenia ich kopii. Przekroczenie
oznacza niepoprawną odpowiedź, bez zatwierdzenia strony. Nie jest to limit RSS
całego procesu; tekst, modele i snapshot mogą współistnieć w pamięci.
Przekroczenie body/snapshotu/nowego checkpointu daje `KsefSyncLimitError`
z `limit_stage`, `limit_bytes` i `observed_bytes`, jeżeli rozmiar został ustalony
(pole może być None). Nie jest ponawiane. Niefinitywne kwoty, także wynik
przepełnienia `1e999`, dają `invalid_metadata`; zmniejszenie strony ich nie naprawi.
Runtime limit kursora zachowuje `KsefIncompletePaginationError` z przyczyną
`cursor_size_limit`. Strona nie zostaje zatwierdzona.

Odrzucone przekierowanie lub kompresja odpowiedzi daje `KsefSyncError` z `reason_code`
`response_redirect` albo `response_encoding`, a nie błąd rozmiaru. Popraw adres
lub konfigurację pośrednika; zmniejszenie strony nie naprawia tej sytuacji.
Początek historii późniejszy od bieżącej granicy cyklu daje błąd tylko danego
strumienia (`cycle_end_before_start`), bez zmiany jego HWM.

`KsefSyncStoreError` opisuje `operation=load/commit`,
`commit_outcome=not_started/rolled_back/committed/unknown` i
`failure_scope=stream/store`. `store` zawsze przerywa koordynator.
Niezgodny receipt daje `commit_outcome="unknown"`: dopiero ponowny load/CAS
rozstrzyga, czy partia została utrwalona.
`KsefRateLimitCapacityError` również przerywa całe wywołanie, niezależnie od
`raise_on_error`: oznacza wyczerpanie pamięci rozliczeniowej wspólnego limitera,
nie błąd pojedynczej roli. Należy poprawić konfigurację/obciążenie budżetu.
Obcy wyjątek adaptera jest poufnym `original_error`, bez ujawniania jego łańcucha.
Przykład SQLite odrzuca obcą transakcję również przy `load`. Po przerwaniu
rozpoczętej transakcji przez `KeyboardInterrupt` lub `SystemExit` sprząta ją
przed propagacją przerwania; po błędzie sprzątania zamyka połączenie.

Operacje administracyjne tworzą puste partie do zatwierdzenia przez ten sam CAS:

| Przyczyna | Operacja |
| --- | --- |
| Zły kursor przy poprawnej kopercie | `restart_active(cp, reason="cursor_invalid")` |
| Zmiana biblioteki | `restart_active(cp, reason="library_upgrade")` |
| Za duże body/strona | `restart_active(cp, reason="page_size_limit", page_size=10)` |
| Limit kursora/checkpointu | `restart_active(cp, reason="checkpoint_limit")`, bez gwarancji naprawy |
| Usunięta przyczyna chwilowej niekompletności | `restart_active(cp, reason="transient_pagination_retry")` |
| Zmiana uprawnień | `restart_backfill(cp, until=cycle_to, reason="permissions_changed")` |
| Świadomy pełny replay | `restart_backfill(cp, until=cycle_to, reason="operator_replay")` |
| Spójny restore bazy | zatrzymanie starych workerów, `fence_after_restore(cp, reason="backup_restored")`, nowe workery |

Restart_active zachowuje HWM i cycle_to, odrzuca kursor i zwiększa rewizję.
Restart_backfill zaczyna od niezmiennego initial_from i zmienia generację;
stare pokrycie jest unieważnione. Fence zmienia generację z zachowaniem postępu.
Uszkodzona koperta nie staje się brakującym checkpointem. Nie edytuj ręcznie HWM.

Rekord większy od limitu lub nierozwiązywalna identyczna granica dat wymaga
zweryfikowanego podziału filtrów albo innego źródła. Sam restart nie naprawia
takiej niekompletności. Częściowy replay ostatnich miesięcy wymaga nowego
strumienia z innym initial_from lub osobnego range search; nie odnawia pokrycia
starego strumienia.

Backup musi obejmować dokumenty, obserwacje, checkpointy i outbox razem.
SDK sam nie wykrywa rollbacku bazy. Dane trwałe zawierają poufne filtry i kursory:
chroń bazę, pliki WAL/SHM i backupy, nie loguj JSON checkpointów.

Synchronizacja metadanych nie pobiera XML i nie potwierdza zaksięgowania.
Opcjonalny outbox przykładu SQLite ma stabilny klucz dokument/rodzaj/wariant,
niezależny od generacji. Worker XML ma własne hashe i statusy.
Automatyczny eksport, XML, harmonogram i rekonsyliacja są osobnymi etapami.

## Decyzje implementacyjne

- Jeden koordynator steruje przejściami, a osobne drivery wykonują sync/async I/O.
  Pozwala to zachować identyczną kolejność load, odczytu strony i COMMIT.
- Istniejący kursor wyszukiwania zachowuje semantykę i format v1. Kompaktowy
  kursor oznaczałby odrębny kontrakt; nie usuwa też potrzeby limitowania metadanych.
- Checkpoint ma niezmienny snapshot i mały cache pól skalarnych. Spec/active
  zwracają niezależne kopie; observation_count nie parsuje strony dla licznika.
- Generacja i rewizja służą CAS/fence. commit_id rozróżnia konkretne propozycje
  partii: dwaj workerzy mogą przygotować różne partie z tą samą następną rewizją.
- common_coverage realizuje wymagane przecięcie potwierdzonych zakresów ról.
  Opóźniony, lecz zweryfikowany load zachowuje wcześniejsze pokrycie w partial.
- Twardy deadline nagłówków wymaga nadzorcy procesu. Serwerowy cooldown wspólnego
  limitera, proxy/CA i własność transportu pozostają częścią konfiguracji aplikacji.

## Weryfikacja i odtwarzanie wyników

Poniższe komendy wykonuj z katalogu repozytorium, w przygotowanym virtualenv
zgodnym z requirements-dev.txt. Pełna macierz obejmuje Python 3.10–3.14 na Linux
oraz Python 3.12 na Windows. Bieżące liczby, wersje narzędzi, sumy artefaktów
oraz surowe pary RSS są wyłącznie w [pliku dowodów](reports/invoice-sync-validation.json).
Zmiany dokumentacji po zapisanym code_commit nie zmieniają badanego SDK.

`requirements-dev.txt` określa dolne granice wersji, więc nowa instalacja nie
odtwarza dokładnego środowiska zapisanej macierzy lokalnej. Przed porównaniem
wyników zachowaj wersję Pythona i `python -m pip freeze`. Chronione runnery
live/release na Linux/Python 3.12 instalują przypięte zależności z
`requirements-ci.lock`. Subtests są częścią pytest od 9.0 i nie wymagają
osobnego pakietu `pytest-subtests`.

```bash
python tools/lint.py --strict
python tools/generate_async_facade.py --check
python -m pytest -q --cov=ksef_client --cov-fail-under=100 --cov-report=term-missing
```

To próg pokrycia instrukcji/linii, nie gałęzi. Lokalne pominięcia live lub
przypadków platformowych nie zaliczają scenariuszy TEST. Regresje obejmują:

| Granica | Dowód |
| --- | --- |
| Trwałość | Rzeczywista SQLite, sync/async, default/autocommit; awarie przed/po każdym SQL, w tym utrata receiptu po COMMIT; CAS, hash, fence i idempotentny outbox. |
| Restart | Nowy interpreter z -I po każdej stronie; dokładne zbiory dokumentów i obserwacji, stały cycle_to oraz HWM tylko na końcu. |
| Transport | Jawny limit na obu entry pointach, retry/401/refresh, nested auth, współbieżność, kompresja/3xx, 429 z błędem body, wolne porcje i cleanup async. |
| Dane niezaufane | Limity body/snapshotu/kursora, preflight JSON przed dekoderem, mutacje checkpointu, niezgodna tożsamość źródła i poufne oryginalne wyjątki. |
| Koordynacja | Zdrowa rola postępuje przy awarii innej; długi backfill korzysta z czasu po trzech pustych rolach; globalny i krokowy budżet mają odrębne przyczyny. |

Testy mają krótkie jawne ID dla parametrów wielomegabajtowych, niezależnie od
strategii automatycznych identyfikatorów pytest na Windows.

### Dokładny wheel

Zbuduj artefakty ze wskazanego pełnego SHA (FULL_COMMIT_SHA poniżej jest miejscem
na rzeczywistą wartość z git rev-parse HEAD):

```bash
python -m pip install build
python -m build --outdir .tmp/invoice-sync-dist
python tools/release_artifacts.py record .tmp/invoice-sync-dist --sha FULL_COMMIT_SHA
python tools/release_artifacts.py verify .tmp/invoice-sync-dist --sha FULL_COMMIT_SHA
```

W osobnym virtualenv z zależnościami testowymi zainstaluj ten wheel przez pip
z --force-reinstall --no-deps. Ustaw KSEF_TEST_INSTALLED=1 i KSEF_TEST_WHEEL na
absolutną ścieżkę do pliku. Następnie wykonaj poniższy wybór testów (jawne ścieżki
zamiast globu powłoki, aby ta sama komenda działała również w PowerShell):

```bash
python -m pytest -q tests/test_bounded_http.py tests/test_invoice_sync.py tests/test_invoice_sync_state.py tests/test_invoice_sync_failures.py tests/test_invoice_sync_contract.py tests/test_invoice_sync_processes.py tests/test_invoice_sync_review.py tests/test_invoice_sync_external_review.py tests/test_invoice_sync_store_contract.py tests/test_invoice_sync_transport.py tests/test_invoice_search.py tests/test_invoice_range_search.py tests/test_invoice_range_review.py tests/test_pagination.py
python tools/release_artifacts.py verify-installed .tmp/invoice-sync-dist --sha FULL_COMMIT_SHA
```

Conftest i procesy restartu weryfikują import z zainstalowanego wheela oraz jego
bajty, zamiast importu lokalnego src. Wymagana jest nieedytowalna instalacja.

### Pamięć

Referencyjny pomiar wymaga Linux/Python 3.12. Każdy worker jest nowym procesem:

```bash
python tools/benchmark_invoice_sync.py --pairs 3 --output .tmp/invoice-sync-rss.json
python tools/benchmark_invoice_sync.py --worker 10000 --boundary 10000 --output .tmp/invoice-sync-boundary.json
python tools/benchmark_invoice_sync.py --worker 250 --boundary 250 --dense-page --output .tmp/invoice-sync-dense.json
```

Próg dotyczy maksimum z trzech różnic max(0, peak_RSS_500k - peak_RSS_50k):
32 MiB. Nie jest limitem całkowitego RSS gęstej strony. --output działa także
z --worker i tworzy brakujące katalogi nadrzędne. Osobne uruchomienia i różne SHA
mogą dawać różne wyniki; aktualnym punktem odniesienia są pary w jedynym pliku
dowodów, wraz z parametrami i SHA.

### Obowiązkowa brama live

Scenariusz A/HWM/B/restart wykonuje workflow required-test-e2e.yml w środowisku
ksef-test, na dokładnym wheelu. Jeden node nadzoruje dwa procesy fazowe na Linux,
z łącznym watchdogiem 1800 s. Manifest i kontroler wymagają siedmiu scenariuszy,
bez skip, rerun ani powtórnego wysłania faktury jako obejścia niepowodzenia.
Run [40757621518](https://github.com/smekcio/ksef-client-python/actions/runs/40757621518)
dla commita `2c8d1138bf3bf52fbeef4457181ccd6123943175` zakończył się wynikiem
**7 passed, 0 skipped, 0 failures, 0 errors**, w jednej próbie, na zweryfikowanym
wheelu. Zestaw obejmował A/HWM/B/restart. Tymczasowy wyjątek środowiska `ksef-test`
dla gałęzi PR został po runie usunięty; środowisko ponownie dopuszcza tylko `main`.
Kolejne wydanie nadal przechodzi tę samą bramę na swoim dokładnym artefakcie.

## Historia

Dawny plan i kolejne raporty zostały skonsolidowane w ten dokument. Szczegółową
historię wymagań, ustaleń i wcześniejszych prób zachowuje Git, np.
`git show 379af4b:docs/plans/invoice-sync.md` oraz
`git show 379af4b:docs/reports/invoice-sync-external-review-response.md`.
Nie utrzymujemy ich jako równoległych aktualnych specyfikacji i raportów.
