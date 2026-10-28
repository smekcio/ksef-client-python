# Plan implementacji InvoiceSync

Status: projekt do implementacji; opisane API nie jest jeszcze dostępne.

Data: 27 października 2026. Baza: **0.21.0**, commit
`1db4dbe486bcd7ab75973dc6c321e50785a1ed18`. Gałąź: `feat/invoice-sync-plan`.
Rewizja planu: 3, po finalnym review własnym i raporcie S-1–S-11.
Zmiany i commity tej gałęzi pozostają wyłącznie lokalne, zgodnie z decyzją użytkownika.
Model niezależnych strumieni pozostaje; niniejsza rewizja domyka kontrakt transportu,
budżetowania, błędów, odzyskania i kryteriów odbioru.

## 1. Cel, gwarancje i zakres

`InvoiceSync` / `AsyncInvoiceSync` synchronizują **metadane faktur**: pierwsze
pobranie historii i kolejne przyrosty od zatwierdzonego HWM. Aplikacja dostarcza
uwierzytelnionego klienta, magazyn, transakcje i harmonogram. SDK koordynuje
odczyt, walidację, postęp oraz wznowienie.

Gwarancje obowiązują przy poprawnym adapterze magazynu i w zakresie stabilnego
kontraktu KSeF oraz aktualnych uprawnień:

- restart i awaria zapisu nie przesuwają checkpointu poza utrwalone dane;
- dane, obserwacje roli i następny checkpoint są zatwierdzane atomowo;
- odczyt może się powtórzyć; trwały zapis jest idempotentny;
- brak możliwości potwierdzenia kompletności daje jawny błąd danego strumienia;
- awaria jednej roli nie blokuje postępu pozostałych, jeśli współdzielony
  transport, magazyn i budżet czasu nadal pozwalają na pracę;
- SDK nie deklaruje exactly-once dla HTTP ani skutków w innych systemach.

Pierwszy etap obejmuje wszystkie cztery role, wyszukiwanie wieloletnie,
checkpointy per strumień, sync/async, bezpieczną obsługę COMMIT, przykład SQLite,
procedury odzyskania i weryfikację na zainstalowanym wheelu.

Pobranie metadanych nie oznacza pobrania XML, zakończenia zadania outboxu ani
zaksięgowania. Dokumentacja i README muszą mówić o synchronizacji metadanych.
Automatyczny eksport, XML, wybór `metadata / export / auto`, harmonogram, ORM,
rozproszony limiter, PDF i OpenTelemetry pozostają osobnymi etapami. Nie dodajemy
pustych opcji obiecujących te funkcje. Zachowujemy API 0.21.0, Python >=3.10
oraz brak nowych zależności podstawowych.

## 2. Rozstrzygnięcia wszystkich dziesięciu punktów review

| Punkt | Podjęta decyzja | Gdzie doprecyzowano |
| --- | --- | --- |
| 1. Niezależne strumienie | Checkpoint i cykl per rola + filtry; round-robin, globalny budżet i limit pojedynczego kroku. | §4, §7, §8 |
| 2. Integracja z SDK | Etap 0: tożsamość wyszukiwania, walidacja kursora bez I/O, pełne obserwacje i dokładna allowlista czystych fabryk w generatorze. | §5, §18 |
| 3. Retry | Jawna konfiguracja przez aplikację; mechanizm istnieje, ale domyślna allowlista POST jest pusta. | §10 |
| 4. Token | Brak przechwytywania tokena przez sync; provider pobiera go przy każdym rzeczywistym żądaniu. | §10 |
| 5. HWM i pokrycie | `to=cycle_to` dla całego skanu; żądania okien wyznacza maszyna paginacji. Inkluzywne granice i przedziały pokrycia. | §6, §8 |
| 6. COMMIT i błędy | CAS, receipt, kontrolowany wynik niepewny, ochrona rozpoczętego commita w async i jednoznaczny model limitu czasu. | §9, §11 |
| 7. Deduplikacja | Wszystkie obserwacje przed odrzuceniem duplikatów; jawna tabela pól, atomowa kontrola hashy również między zadaniami. | §5, §12 |
| 8. Tożsamość magazynu | Jeden złożony scope używany w protokole, SQLite, receipt i checkpointach. | §4, §9, §14 |
| 9. Mocniejsze testy | A -> HWM -> B -> restart; awarie, zdrowe/chore role, konflikty, precyzja i graniczne rozmiary. | §17 |
| 10. Produkt i odzyskanie | Metadane, osobny outbox XML, jawne operacje ponownego odczytu i ogrodzenia po backupie; bez ręcznej edycji HWM. | §1, §15, §19 |

### Decyzje po finalnym raporcie S-1–S-11

| Uwaga | Rozstrzygnięcie projektowe |
| --- | --- |
| S-1 | Rozdzielamy 0a (kontrakty wyszukiwania) i 0b (ograniczony odbiór HTTP). 0b ma własny odbiór i security review przed produkcyjnym pull oraz koordynatorem. |
| S-2 | Standardowe options są frozen. Sprawdzamy środowisko przed krokiem i wiążemy wywołanie z konkretnym celem; nie dokładamy martwego guarda do każdej iteracji retry. |
| S-3 | `environment_key(options.normalized_base_url())`, hex bez prefiksu, pełna ścieżka. Kursor v1 zachowuje `sha256:`; origin służy wyłącznie limitom API. |
| S-4 | Globalny budżet jest współdzielony przez gotowe strumienie, a round-robin i limit kroku ograniczają monopolizację. Brak skumulowanych sztywnych udziałów per rola. |
| S-5 | 32 MiB oznacza różnicę peak RSS między dwoma rozmiarami zbioru, nie całkowity limit RAM. Zachowujemy limity 16 MiB body/snapshot i podajemy oba absolutne pomiary. |
| S-6 | Przekroczenia limitów mają nazwany błąd, fazę, status failed oraz jawny plan odzyskania; bez zaliczania strony i bez automatycznego retry. |
| S-7 | Tabela typ/kod/przyczyna; commit_outcome i failure_scope są osobnymi atrybutami błędu magazynu. Agregacja błędów jest jawna. |
| S-8 | Tabela przyczyn i napraw. Restart może odrzucić błędny kursor przy poprawnej kopercie, ale nie leczy każdej niekompletności. |
| S-9 | Częściowy replay w istniejącym strumieniu jest poza v1; nowy scope/one-shot range search nie podnosi pokrycia starego strumienia. |
| S-10 | Budżety SDK są kooperatywne. Twardy watchdog testu nadzoruje procesy; przerwanie może pozostawić niepewny wynik DB, rozstrzygany przez load/CAS. |
| S-11 | Kompletny przykład cycle_to, jawne pola strony i poziomy dokumentacji: run_once na start, pull i administracja dla zaawansowanych. |

Dodatkowo poprawiamy rozróżnienie scan bounds / wire bounds, walidację pustych
lub powtórzonych strumieni, raport przy konflikcie generacji oraz redakcję całego
łańcucha wyjątków. Są to ustalenia końcowego review, a nie nowe funkcje produktu.

## 3. Oparcie o istniejący SDK i źródła

| Element | Wykorzystanie |
| --- | --- |
| [`invoice_range_search.py`](../../src/ksef_client/invoice_range_search.py) | Ta sama maszyna okien i kursorów; addytywne wejścia opisane w etapie 0. |
| [`invoice_search.py`](../../src/ksef_client/invoice_search.py) | Walidacja zakresu, obcięcia, kolejności i precyzji czasu; bez kopiowania algorytmu paginacji. |
| [`clients/invoices.py`](../../src/ksef_client/clients/invoices.py) | Fabryki, wspólna normalizacja query i transport. |
| [`facade.py`](../../src/ksef_client/facade.py), [`async_facade.py`](../../src/ksef_client/async_facade.py) | Wygodne tworzenie synchronizacji z kontekstem połączenia. |
| [`request_control.py`](../../src/ksef_client/request_control.py), [`rate_limiting.py`](../../src/ksef_client/rate_limiting.py) | Deadline, anulowanie i istniejący budżet HTTP. |
| [`retry.py`](../../src/ksef_client/retry.py), [`token_manager.py`](../../src/ksef_client/token_manager.py) | Retry opt-in i odświeżanie tokena per żądanie. |
| [`exceptions.py`](../../src/ksef_client/exceptions.py) | Istniejąca taksonomia i addytywne kody synchronizacji. |
| [`invoice_checkpoint_sqlite.py`](../examples/invoice_checkpoint_sqlite.py) | Wzorzec transakcji; dotychczasowy przykład pozostaje działający. |
| [`streaming_export.py`](../../src/ksef_client/streaming_export.py) | Podstawa późniejszego backendu eksportowego, poza tym etapem. |

Model odczytu ograniczonego HWM wynika z
[dokumentacji MF o HWM](https://github.com/CIRFMF/ksef-api/blob/ce3670ea042de380039de4c5849fd6455811b292/pobieranie-faktur/hwm.md).
Dopuszcza opóźnienie najświeższych dokumentów. Wznowienie zachowuje wspólną,
inkluzywną granicę. Dla synchronizacji dokumentów MF opisuje
[przyrostowy eksport](https://github.com/CIRFMF/ksef-api/blob/ce3670ea042de380039de4c5849fd6455811b292/pobieranie-faktur/przyrostowe-pobieranie-faktur.md);
nasz etap metadanych nie zastępuje jego kontraktu.

Kontrakt query i limitów: [snapshot SDK](../../specs/ksef-openapi.snapshot.json)
i [OpenAPI TEST](https://api-test.ksef.mf.gov.pl/docs/v2/openapi.json).
27.10.2026 TEST wskazywał API 2.9.0 i 100 dni UTC, zgodnie z SDK.
Przed kodowaniem ponownie sprawdzamy zgodność, bez kopiowania limitów ze starszych
stron opisowych i bez tworzenia drugiego limitera HTTP.

## 4. Strumienie, scope i zmiany konfiguracji

Jednostką poprawności jest `InvoiceSyncStream`: jedna rola, jeden niezmienny
zestaw filtrów i początek historii. `InvoiceSync` jest koordynatorem wybranego
zbioru strumieni. Nie ma globalnego kursora, HWM, cyklu ani rewizji blokującej role.

`InvoiceSyncScope` zawiera dokładnie:

| Pole | Znaczenie |
| --- | --- |
| `namespace` | Jawna przestrzeń aplikacji/tenanta; wymagana, do 256 znaków. |
| `environment` | `environment_key(api_base_url)`: 64 znaki hex bez prefiksu, z efektywnego pełnego adresu API. |
| `context_key` | Kontekst aplikacyjny zgodny z uwierzytelnieniem; do 4096 znaków. |
| `sync_key` | Nazwa zadania w tej przestrzeni; do 256 znaków. |
| `stream_id` | SHA-256 kanonicznej specyfikacji jednego strumienia. |

Jedyną funkcją tożsamości środowiska synchronizacji jest istniejące
`operations.environment_key(options.normalized_base_url())`. Publiczne identity
wyszukiwania używa tego samego hex; prywatny zapis kursora v1 nadal ma `sha256:`.
Warstwa sync nie porównuje tych dwóch reprezentacji tekstowo i nie zmienia v1.
`canonical_rate_limit_environment()` nadal grupuje po origin dla kwot HTTP;
nie stosujemy jej do kluczy dokumentów lub checkpointów.

`/v2` i `/api/v2` są domyślnie różnymi scope środowiska. Wspólny origin nie
udowadnia tożsamości danych; pod innymi ścieżkami może działać inny backend.
Nie ma automatycznej migracji aliasów. Potwierdzoną migrację adresu kontroluje
aplikacja z weryfikacją danych. Zmienia się część environment w scope, nie sam
stream_id wyliczany wyłącznie ze specyfikacji query.

Specyfikacja strumienia zawiera rolę, wszystkie filtry z początkowym `from_`,
`PermanentStorage`, ograniczenie HWM i wersję semantyki synchronizacji.
Konfiguracyjne `to` musi być `None`; faktyczny koniec wstawia rozpoczęty cykl.
Nie zawiera tokena, numeru generacji, bieżącego HWM ani identyfikatora cyklu.
Nie sortujemy list filtrów bez potwierdzenia, że ich kolejność jest nieistotna.

Kanoniczny spec to `{semantics_version: 1, query: ...}`. Query powstaje przez
wspólną normalizację i serializację typed model z pominięciem pól None;
daty początku są sprowadzane do UTC z zachowaniem pełnego ułamka. SHA-256
liczymy z JSON: sort_keys=True, separators=(",", ":"), ensure_ascii=True,
allow_nan=False. Równe chwile z różnymi offsetami dają ten sam początek i scope.

`page_size` i `window_days` są parametrami wykonania, nie tożsamością strumienia.
Aktywny cykl zachowuje ich zapisane wartości. Nowe wartości obowiązują od nowego
cyklu; nie reinterpretują istniejącego kursora. Wariant `queries` dopuszcza
najwyżej cztery query, po jednym na rolę. Równoległa koordynacja kilku query
tej samej roli wymaga osobnych obiektów. Osobne sync_key są zalecane dla
niezależnie zarządzanych zadań, ale nie są warunkiem izolacji: zapewnia ją
pełny scope ze stream_id. Zmiana początku lub filtrów pod tym samym sync_key
jest dozwolona i wybiera nowy strumień; nie migruje starego checkpointu.

Dodanie `Subject3` tworzy tylko nowy strumień; identyfikatory Subject1/2 zostają
te same. Zmiana filtrów albo początku historii tworzy nowy `stream_id` i nowy
backfill. Stary checkpoint pozostaje dostępny, ale nie jest wybierany ani usuwany
automatycznie. Raport wskazuje nowo utworzone strumienie. Fabryka udostępnia ich
scope przed wykonaniem, więc aplikacja może zatwierdzić zmianę konfiguracji.
Zmiana kolejności ról niczego nie resetuje. Rotacja tokena nie zmienia scope.

Środowisko i kontekst nigdy nie są odczytywane z checkpointu jako konfiguracja
HTTP. Scope jest najpierw wyznaczany z połączenia, potem porównywany z magazynem.
`context_key` nie zastępuje autoryzacji. Wycofanie roli z konfiguracji nie usuwa
jej dokumentów ani obserwacji. Czyszczenie starych strumieni jest operacją aplikacji.

## 5. Etap 0a/0b: kontrakty wyszukiwania i ograniczony transport

### 0a. Czyste kontrakty i adapter wyszukiwania

Do obu `InvoiceMetadataRangeSearch` dodajemy identity i walidację bez I/O oraz
kontrakt pełnej strony obserwacji. Dotychczasowe page/pages/items i odczyt
kursorów v1 zachowują zachowanie. Nie tworzymy drugiej maszyny paginacji.

| Wejście | Dokładny kontrakt |
| --- | --- |
| `identity` | Read-only `InvoiceMetadataSearchIdentity`: environment hex, kontekst, fingerprint znormalizowanego query i parametry wykonania; dane poufne poza repr. |
| `validate_cursor(cursor)` | Zwykła metoda także w async, bez HTTP; zgodność, format i rozmiar są sprawdzane przez obecną maszynę. Zwraca None albo istniejący błąd kursora. |
| `observation_page(cursor=None)` | Jedna strona tej samej maszyny; pełne obserwacje przed deduplikacją, kursor i HWM. W async jest awaitowalna. Publiczne uruchomienie wymaga ukończenia 0b. |

`InvoiceMetadataObservationPage` ma dokładnie pola `observations`
(krotka InvoiceMetadata), `next_cursor` (str albo None) oraz
`permanent_storage_hwm_date` (str albo None). Sync wymaga poprawnego HWM;
nullable pozostaje dla publicznego użycia strony z innymi typami dat.
Nie jest to zamiennik dotychczasowego InvoiceMetadataPage. Walidacja zakresu,
dat i kolejności obejmuje również wiersze odrzucone przez starą deduplikację.

Normalizacja query, identity i walidacja używają jednego wewnętrznego helpera.
Moduł sync nie parsuje prywatnego kursora. 0a można testować z wstrzykniętym
fetcherem bez nowej ścieżki sieciowej; nie udostępniamy produkcyjnego fallbacku
observation_page do nieograniczonego odbioru starego transportu. W 0a deklarujemy
DTO/kontrakt obserwacji na adapterze testowym; właściwą metodę sieciową włącza 0b,
bez publicznego stuba obiecującego działającą synchronizację.

Standardowy `KsefClientOptions` jest frozen. Nowe `api_base_url` jest read-only
widokiem dokładnie tej konfiguracji, z której transport buduje URL. Źródło
zapamiętuje identity przy konstrukcji i sprawdza ją przed każdym krokiem HTTP.
Nie testujemy zwykłego przypisania options.base_url jako dozwolonej mutacji:
ma ono nadal zgłaszać FrozenInstanceError. Zmianę środowiska między krokami
symulujemy jawnym testowym adapterem. Własny transport ma utrzymać stały cel
przez całe pojedyncze wywołanie i jego retry albo odmówić wykonania.
Nie zmieniamy wymagań starych endpointów i nie wprowadzamy globalnego zamrażania
transportów. Nie ma nowego guarda w każdej iteracji standardowej pętli retry.

Generator otrzymuje dokładną allowlistę czystych wywołań obejmującą
`self.owner.api.invoices.sync`, mapowanie InvoiceSync -> AsyncInvoiceSync
oraz potrzebny import. Fabryka pozostaje def bez await. Nieznane I/O nadal
wywołuje błąd; nie wyłączamy kontroli wszystkich self.owner.api.*.

### 0b. Osobny podetap transportu z własnym odbiorem

Ograniczenie w czasie odbioru wymaga zmiany punktu pobierania body: obecne
httpx.Client.request() buforuje całość. Jest to jawny refaktor części http.py,
a nie kosmetyczny wrapper. 0b stanowi osobny reviewowalny commit/PR z pełnymi
regresjami HTTP, retry, token managera, rate budgets i security review.
Może powstawać obok modelu stanu, ale musi być ukończony przed produkcyjnym
trybem pull, koordynatorem i live E2E. Nigdzie nie omijamy go po cichu.

Decyzja implementacyjna: wydzielamy prywatny hook odbioru body wywoływany przez
istniejące `_request_once`. Domyślny hook zachowuje buforowaną ścieżkę 0.21.0.
Nowe `request_json_limited()` ustawia prywatną, task/thread-local politykę
odbioru w ContextVar i wywołuje istniejące `self.request()`. Polityka ma zakres
jednego wywołania i jest resetowana w finally; nie mutuje options ani klienta.
Nie dokładamy nowego argumentu do nadpisanych `_request_once` ani drugiej pętli retry.

Polityka jest przypisana do konkretnego publicznego wywołania i transportu,
nie do całego drzewa jego podwywołań. Wejście request() zużywa jednorazowy
marker wrappera i tworzy własną ramkę odbioru; zwykłe zagnieżdżone request()
zaczyna od polityki domyślnej i po wyjściu przywraca ramkę rodzica. Samo
odczytywanie jednego dziedziczonego ContextVar w hooku byłoby błędem:
refresh tokena i callback nie mogą odziedziczyć docelowego URL lub odbiornika
zapytania metadanych. Jawnie zagnieżdżone request_json_limited ma własną ramkę.
Testy obejmują nested auth, równoległe taski i brak wycieku polityki po wyjątku.

Dzięki temu nadal działają nadpisania TokenRefreshingHttpClient i jego wariantu
async: proaktywny provider, jednorazowe odświeżenie po 401 i osobne admission
każdej rzeczywistej próby. 401 po udanym refreshu nie tworzy nieskończonej pętli.
Standardowy odczyt innych endpointów nie przechodzi do trybu limited.

`request_json_limited(method, path, *, max_bytes, ...) -> HttpResponse` przyjmuje
te same parametry żądania co request plus dodatni max_bytes. Zwraca ograniczone
bajty i nagłówki w istniejącym typie; JSON dekoduje adapter metadanych, nie
transport. W async metoda jest awaitowalna. Hook limited używa stream/iter_raw
(aiter_raw), nie akumuluje całego body przed sprawdzeniem limitu i zawsze zamyka
odpowiedź przy sukcesie, błędzie, limicie i anulowaniu.

Wspólny callback odbioru nagłówków wykonuje rozliczenie 429/Retry-After i obsługę
system warning dokładnie raz. Dla limited działa przed odczytem body, więc
przekroczenie limitu lub zerwany odczyt nie usuwa cooldownu. Dla starej ścieżki
kolejność i zachowanie pozostają zgodne z 0.21.0. Statusy, parsowanie błędów
i redakcja korzystają z dotychczasowych helperów. Nowy KsefResponseLimitError
nie dziedziczy po KsefHttpError: jest deterministycznym błędem ograniczonego
odbioru, więc nie trafia do retry ani reaktywnego refreshu. Sync mapuje go
na KsefSyncLimitError; semantyka zwykłego, mieszczącego się w limicie 401/429
pozostaje bez zmian.

Accept-Encoding: identity już istnieje w SDK. Limited wymusza jego skuteczną
wartość po scaleniu nagłówków i odrzuca inną kompresję odpowiedzi. Ma lokalne
follow_redirects=False niezależnie od opcji starego klienta; wszystkie 3xx są
odrzucane. Cel jest rozwiązywany z konfiguracji źródła i stałej ścieżki metadanych
raz na wywołanie. Własny adapter musi zachować ten cel również podczas retry.
Nie uznajemy samego guarda base_url za ochronę przed przekierowaniem.

Sprawdzamy Content-Length i rzeczywiste bajty, limit domyślny 16 MiB. Nieufny
lub błędny nagłówek nie wyłącza limitu faktycznie odebranego body. Przed i po
porcjach sieciowych kontrolujemy request_control; HTTP read timeout ogranicza
bezczynność, nie cały transfer. Odbiór nie czeka na pełny duży chunk. Przekroczenie
terminu może obejmować jeden ograniczony odczyt; to limit kooperatywny.

Decoder nowej ścieżki metadanych odrzuca nie-JSON, duplikaty kluczy i NaN/Infinity,
sprawdza strukturę listy oraz liczbę wierszy <= żądany page_size przed tworzeniem
modeli. Współdzieli dotychczasową walidację metadanych; nie zmienia globalnie
HttpResponse.json() ani parserów innych endpointów.

Odbiór 0b obejmuje lokalny HTTP z wolnymi porcjami, przekroczonym rozmiarem,
kompresją, 3xx, 401 -> refresh -> 200, 401 -> refresh -> 401, 429/cooldown przy
błędzie body, równoległe limited i zwykłe żądania oraz pełną dotychczasową
macierz transportu. Nowa metoda i własne adaptery mają identyczny kontrakt.

## 6. API użytkowe i jawny tryb pull

Wszystkie poniższe przykłady opisują przyszłe API.

```python
from ksef_client import (
    Ksef, KsefClientOptions, KsefEnvironment, RetryConfig, TokenCredentials,
)
from ksef_client import models as m

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
        subject_types=(
            m.InvoiceQuerySubjectType.SUBJECT1,
            m.InvoiceQuerySubjectType.SUBJECT2,
        ),
    )
    report = sync.run_once(
        application_store, time_budget=600, max_pages_per_stream=1000,
    )
```

`sync()` jest fabryką bez I/O. Domyślne role wariantu `since` to Subject1/2.
Inne role są jawne, a 403 nie oznacza ich pominięcia. Wariant zaawansowany
przyjmuje `queries: Sequence[m.InvoiceQueryFilters]` zamiast `since` i ról.
Są to rozłączne warianty konstrukcji, z typed-only requestami.
Po normalizacji wymagamy 1–4 unikalnych strumieni. Puste subject_types/queries,
powtórzone role (również enum + równoważny tekst wire), niedozwolone typy
kolekcji i sprzeczne warianty argumentów są odrzucane przed I/O. Namespace,
sync_key i context_key muszą być niepuste i nie mogą zawierać znaków sterujących.
Nie ma kompletności all([]) ani dzielenia czasu przez zero.
Znaczniki wejściowe wymagają pełnej daty/czasu i jawnej strefy Z/offsetu;
nie zgadujemy strefy dla nowego API synchronizacji.

`KsefClient.invoices.sync()` i `AsyncKsefClient.invoices.sync()` wymagają ponadto
jawnego `context_key`. Fasada bierze go z połączenia. W async fabryka nadal nie
wymaga `await`, natomiast `run_once` i odczyt strony wymagają `await` oraz async store.
Obiekt nie jest właścicielem klienta i nie zamyka jego transportu.

Koordynator ma `streams`, niemutowalną krotkę uchwytów z ich scope. Każdy uchwyt
udostępnia pull API:

- `begin_cycle(checkpoint, *, until)` -> pusta partia rozpoczynająca cykl;
  `checkpoint=None` jest dozwolone tylko tutaj, przy inicjalizacji;
- `next_batch(checkpoint)` -> jedna partia danych; dla stanu idle zwraca `None`;
  `None` jako argument jest błędem, nie skrótem rozpoczęcia cyklu;
- obie metody są bez zapisu i nie mutują wejścia; tylko `next_batch` aktywnego
  cyklu wykonuje HTTP; `begin_cycle` jest zwykłą metodą również w async;
- `batch.confirm(receipt)` waliduje potwierdzenie i zwraca następny checkpoint
  w pamięci. Nie wykonuje zapisu ani nie zastępuje transakcji.

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

To jeden skończony cykl, nie daemon. `until` jest świadomą, zamrożoną granicą
żądania, nie dowodem kompletności. Tryb pull raportuje postęp przez checkpointy,
a `sync.describe(checkpoints)` oblicza opis pokrycia z dostarczonych stanów bez I/O.
Nie powstaje drugi algorytm raportowania. Harmonogram kolejnego cyklu zapewnia
aplikacja. Nie wiążemy modelu z `.wait()` serwerowej operacji KSeF.

## 7. Koordynacja i wykorzystanie całego budżetu

`run_once(store, *, time_budget=600, max_pages_per_stream=None,
step_time_budget=None, cancellation=None, raise_on_error=True)`:

1. Odczytuje i waliduje wybrany zbiór 1–4 scope. Wszystkie poprawnie odczytane
   stany i kursory są sprawdzane przed pierwszym HTTP; błędny strumień otrzymuje
   wynik failed, a naruszenie izolacji tenanta lub awaria całego magazynu przerywa całość.
2. Każdy poprawny strumień wznawia najwyżej jeden aktywny cykl albo tworzy jeden
   nowy. Nowe cykle dostają czas UTC początku wywołania jako scan_to; aktywne
   zachowują wcześniejszy cycle_to. Granice poszczególnych requestów ustala §8.
3. Wykonuje round-robin, po jednym przejściu lub stronie na strumień. Nie ma
   prefetchu ani więcej niż jednej niezatwierdzonej partii. Pierwsza runda daje
   każdemu gotowemu strumieniowi kolej przed powrotem do poprzedniego.
4. Istnieje jeden globalny monotoniczny deadline wywołania. Osobny limit kroku
   ogranicza pojedyncze load/HTTP+COMMIT lub przejście sterujące, nie skumulowaną
   pracę roli. Przy step_time_budget=None wynosi time_budget / początkowe N;
   jawna dodatnia wartość pozwala obsłużyć kosztowny pojedynczy odczyt.
   Faktyczny deadline kroku jest minimum tego limitu, globalnego pozostałego
   czasu i nadrzędnego request_control. COMMIT po rozpoczęciu pozostaje chroniony.
5. Zakończony lub błędny strumień wypada z kolejki; gotowe strumienie wykorzystują
   pozostały globalny czas w kolejnych rundach. Nie mają limitu time_budget/N
   na całą pracę. Gdy trzy role skończą w sekundę, jedna może wykorzystać niemal
   cały pozostały budżet, z zachowaniem limitu każdego pojedynczego kroku.
6. Wygaśnięcie limitu kroku przed zapisaniem strony daje partial z przyczyną
   step_time_budget i zatrzymuje ten strumień do następnego run_once. Nie
   ponawiamy ukrycie przerwanego HTTP ani commita w tym samym wywołaniu.
   Jeżeli jeden legalny request stale wymaga więcej czasu niż limit kroku,
   aplikacja jawnie zwiększa step_time_budget; sam round-robin nie rozwiązuje
   arbitralnie długiego I/O. Własny globalny limit daje partial/time_budget.
7. Błąd HTTP, integralności, niekompletności lub CAS zatrzymuje tylko dotknięty
   strumień, jeżeli adapter nadal jest bezpieczny. Pozostałe dostają kolej.
   Nie zmieniamy filtrów, nie ogłaszamy sukcesu błędnej roli i nie uruchamiamy
   drugiego cyklu strumienia zakończonego w tym wywołaniu.
8. max_pages_per_stream liczy zatwierdzone strony, również puste, bez partii
   sterujących. Osiągnięcie limitu daje partial/work_limit. Po wykonaniu kolejki
   powstaje raport: domyślnie błędy strumieni dają KsefSyncRunError(report),
   a raise_on_error=False zwraca ten sam raport z failed. Limity pracy same
   nie są błędem. Globalne/fatalne wyjątki opisuje §11.

Budżet time_budget oraz opcjonalny step_time_budget są dodatnimi skończonymi
liczbami, bez bool. Limit stron jest None albo dodatnim int, bez bool;
raise_on_error jest bool. Zegar czasu pracy nie jest zapisywany w checkpoincie.
Nie ma osobnego limitera częstotliwości requestów: admission/retry pozostają w HTTP.

Czas jest współdzielony, ale liczba stron i stany pozostają niezależne.
Szczególne przypadki testowe: trzy puste role + duży backfill, trwałe 403 jednej
roli, round-robin przy wielu aktywnych rolach i pojedynczy request przekraczający
limit kroku. Limit pojedynczego kroku, kooperatywny transport i skończone timeouty
DB są warunkami postępu; nie obiecujemy działania przy niekooperującym adapterze.

Nie zmieniamy publicznego RequestControl tylko dla identyfikacji limitów.
Koordynator przechowuje lokalnie pochodzenie deadline'u; przy równości pierwszeństwo
ma ograniczenie nadrzędne, potem globalne, potem krok. Reguły wyjątków są w §11.

## 8. HWM, pokrycie i raport

Dla strumienia przechowujemy `committed_hwm` oraz aktywny opis odczytu z kursorem.
`cursor=None` w aktywnym cyklu oznacza pierwszą stronę, nie koniec historii.
HWM odpowiedzi pośredniej jest kandydatem, a nie zatwierdzonym punktem.
Dopóki cały range search nie zakończył się, zapis strony zmienia tylko kursor.
Po ostatniej stronie dane i nowy HWM są zatwierdzane w jednej transakcji.

Rozdzielamy dwa poziomy granic. `active.from_` i `active.cycle_to` opisują
**cały skan**. Z nich budujemy jedno query przekazane do fabryki range search:

```python
from dataclasses import replace

scan_query = replace(
    template,
    date_range=replace(
        template.date_range, from_=active.from_, to=active.cycle_to,
    ),
)
```

Tylko to wejściowe query ma to=cycle_to. Maszyna range search wyznacza następnie
wire_from/wire_to poszczególnych okien do 100 dni, ich clipping do HWM i zawężenia
po obcięciu wyników. Nie nadpisujemy tych dat przed wysłaniem. Na przykład skan
2024-01-01 -> 2026-01-01 ma pierwsze okno kończące się 2024-04-10, a nie 2026-01-01.

Po restarcie niezmienne pozostają scan bounds, konfiguracja i kursor. Test
transportu sprawdza, że request mieści się w skanie, odpowiada aktualnemu oknu,
respektuje HWM i zachowuje inkluzywną ciągłość; nie wymaga równości wszystkich
wire bounds z granicami całego skanu. Domyślne page size=100 i window_days=100
są utrwalone w aktywnym cyklu. Konfiguracyjne to=None nie trafia do fabryki skanu.

Kandydat granicy pochodzi z
`InvoiceMetadataObservationPage.permanent_storage_hwm_date`, zwróconego przez
maszynę całego zakresu. Nie jest to najwyższa data faktury ani arbitralne to
ostatniego wysłanego okna. HWM zatwierdzamy tylko po next_cursor=None.

Nowy cykl zaczyna się od committed HWM inkluzywnie albo od początku historii,
gdy jeszcze go nie ma. Nie dodajemy mikrosekundy. Precyzja API, w tym siedem
cyfr ułamka i porównanie offsetów, musi zostać zachowana; nie zaokrąglamy granicy
w górę. Publiczne `parse_api_datetime()` nie zmienia kontraktu 0.21.0.

`InvoiceSyncCoverage` jest przedziałem domkniętym `[initial_from, committed_hwm]`
z tożsamością zakresu filtrów. Przed pierwszym pełnym odczytem wynosi `None`.
Pusta końcowa strona może zatwierdzić HWM, ale nigdy bez poprawnej odpowiedzi HWM.
Stary HWM zostaje ważny podczas kolejnego częściowego cyklu. Nie wolno ustawić
nowego HWM wcześniej niż zapis danych ostatniej strony.

Raport zawiera:

- `streams`: wynik każdego wybranego scope, status completed/partial/failed,
  pokrycie, powód zatrzymania, zatwierdzone strony/rekordy i bezpieczny kod błędu;
- `complete`: każdy wybrany strumień ukończył swój cykl w tym wywołaniu;
- `observed_generation`, `observed_revision` i moment odczytu/potwierdzenia
  stanu dla każdego wyniku; opis dotyczy tych obserwacji, nie liniowej migawki
  całej bazy i nie gwarantuje niezmienności stanu po zwrocie raportu;
- `common_coverage`: przecięcie pokryć wszystkich wybranych strumieni,
  czyli `[max(początków), min(HWM)]`, jeżeli wszyscy mają pokrycie i przedział
  nie jest pusty i pokrycie każdego jest potwierdzone w tym wywołaniu;
  w przeciwnym razie None. Konflikt generacji/rewizji, niepewny COMMIT lub
  niespójny receipt unieważniają cached coverage w raporcie, bez dopisywania
  starego HWM do wspólnej kompletności. Kolejny run zaczyna od nowego load;
- identyfikatory nowych strumieni oraz przyczyny normalnego ograniczenia pracy;
- oryginalne błędy jako poufne atrybuty poza repr/bezpieczną serializacją.

Usuwamy niezaimplementowane `complete_through` jako samą datę. Pokrycie dotyczy
wyłącznie wybranych filtrów i aktualnej widoczności danych. Nie jest migawką
wszystkich faktur KSeF ani gwarancją stałości uprawnień. `complete=True` nie
znaczy, że dotarliśmy do bieżącego czasu: HWM mógł przyciąć cykl wcześniej.
Brak przesunięcia poprawnego HWM jest normalny; SDK nie czeka aktywnie na nowy HWM.

`records_delivered` obejmuje powtórne obserwacje. Nie nazywamy go liczbą nowych
faktur, ponieważ SDK nie zna wyniku trwałej deduplikacji magazynu.

## 9. Kontrakt magazynu, CAS i potwierdzenie zapisu

```python
class InvoiceSyncStore(Protocol):
    def load(self, scope: InvoiceSyncScope) -> InvoiceSyncCheckpoint | None: ...
    def commit(self, batch: InvoiceSyncBatch) -> InvoiceSyncCommitReceipt: ...


class AsyncInvoiceSyncStore(Protocol):
    async def load(self, scope: InvoiceSyncScope) -> InvoiceSyncCheckpoint | None: ...
    async def commit(self, batch: InvoiceSyncBatch) -> InvoiceSyncCommitReceipt: ...
```

`load` odczytuje ten sam autorytatywny magazyn, do którego trafia `commit`:
primary/read-your-writes, bez niezadeklarowanej opóźnionej repliki i cache.
Nie może zwrócić `None` zamiast błędu odczytu. Żądany scope musi być porównany
z wierszem i treścią JSON. SQLite i inne adaptery używają pełnego klucza scope.

Jedna transakcja `commit(batch)` wykonuje:

1. Walidację scope, specyfikacji, generacji i oczekiwanej rewizji.
2. CAS: nieobecny wiersz dla inicjalizacji albo dokładnie wskazana generacja
   i rewizja; zero dopasowań jest konfliktem, nie zgodą na reset.
3. Atomową kontrolę i zapis tożsamości dokumentów, wszystkich obserwacji strony
   oraz opcjonalnych zadań outboxu.
4. Zapis kompletnego następnego checkpointu, rewizji i identyfikatora commita.
5. COMMIT, a następnie zwrot `InvoiceSyncCommitReceipt`.

CAS, dokumenty, obserwacje i checkpoint mają wspólną granicę transakcyjną.
Żaden błąd nie pozostawia samej rezerwacji rewizji. Receiptem jest dokładnie
`(scope, generation_id, revision, commit_id)` nowego stanu. `batch.confirm()`
sprawdza ich zgodność przed przyjęciem checkpointu w RAM. Niezgodny receipt
jest błędem adaptera; SDK nie pobiera kolejnej strony tego strumienia.
Receipt jest kontraktem adaptera, nie kryptograficznym dowodem trwałości.

Rewizja rośnie o jeden dla danego strumienia, także przy partii sterującej.
Początkowy zapis tworzy rewizję 1 i losową generację. Każda partia zawiera
oczekiwaną generację/rewizję albo ich brak tylko przy inicjalizacji.
Zalecany jest jeden worker na scope; CAS chroni również dwa procesy.
Lease/advisory lock aplikacji jest opcjonalną optymalizacją ruchu, nie podstawą poprawności.

`commit_id` jest losowym UUID partii, zapisanym jako `last_commit_id`.
Zastępuje deterministyczny `batch_id` z poprzedniej wersji planu. Ułatwia
powiązanie receipt z partią; nie stanowi podpisu, klucza deduplikacji faktur
ani dowodu wyniku dawnego commita. Ponownie przygotowana strona może dostać
inny identyfikator. Poprawność wynika z transakcji, scope i CAS.

Po niepewnym COMMIT SDK nie ponawia automatycznie `commit` i nie ufa kandydatowi
z RAM. Adapter musi zamknąć/ogrodzić stare połączenie i zakończyć własne zadania;
strumień zostaje zatrzymany. Następne wykonanie zaczyna od `load` z primary.
Jeżeli stara transakcja nadal rozstrzyga się na serwerze, sam odczyt nie jest
dowodem jej porażki: kolejny CAS musi bezpiecznie poczekać lub zgłosić konflikt.
Nie wolno bezwarunkowo wykonać zapisu na podstawie starej rewizji.

Po konflikcie inny strumień może pracować, ale przegrany nie nadpisuje nowszego
stanu. Po błędzie całej bazy albo nieuprzątniętej transakcji nie kontynuujemy
na tym samym niebezpiecznym adapterze. Testy kontraktu nie zastępują jego
rzeczywistej gwarancji atomiczności i trwałości.

## 10. Retry i odświeżanie tokena

`RetryConfig.retryable_post_paths` jest domyślnie pusty; `options.retry=None`
całkowicie wyłącza retry. Nie twierdzimy, że POST metadanych ponawia się sam.
Rekomendowany przykład jawnie włącza `/invoices/query/metadata` z ograniczoną
liczbą prób i Retry-After. Synchronizacja respektuje podane ustawienia,
nie mutuje wspólnych options i nie dodaje drugiej pętli retry.

Bez tej konfiguracji 429/5xx są błędem strumienia, checkpoint się nie przesuwa,
a kolejne wywołanie może go wznowić. Z retry każda rzeczywista próba korzysta
z tego samego budżetu HTTP oraz pozostałego limitu kroku i całego wywołania. Brak czasu
nie powoduje ponowienia całego cyklu ani nowych zadań w tle.

Fabryka synchronizacji nie przyjmuje osobnego `access_token`. Nowy adapter
range search przekazuje `access_token=None`, aby manager klienta rozwiązał
token przy każdej faktycznej próbie. Nie odczytuje tokena przy konstrukcji,
nie zapisuje go w partial i nie umieszcza w scope ani checkpoincie.

Samodzielny klient z tokenem statycznym nadal działa, ale sam token nie zyskuje
auto-refreshu: po wygaśnięciu błąd 401 zatrzymuje strumień. Dokumentacja zaleca
`Ksef`/`AsyncKsef` albo istniejącego `AuthenticatedClient` dla backfillu.
Testy muszą oddzielić statyczny token od token providera, obejmując refresh
po długim Retry-After oraz w sync/async. Osobna regresja obejmuje ważny według
zegara token odrzucony 401: pojedynczy refresh i ponowienie limited request;
drugi 401 kończy tę próbę bez następnego odświeżania.

## 11. Czas, anulowanie i hierarchia błędów

### Budżet kooperatywny i limit zewnętrzny

Time budget i step_time_budget są limitami rozpoczynania/dalszego wykonywania
pracy SDK. Nie są gwarancją wall-clock. Odbiór sieci może zakończyć się po jednym
trwającym odczycie, a rozpoczęty COMMIT ma zostać odebrany. Zwykły nadrzędny
request_control i asyncio.wait_for też nie gwarantują natychmiastowego powrotu
przy koniecznym cleanup. Twarde zakończenie wymaga nadzorcy procesu/joba;
może zostawić niepewny wynik DB, który rozstrzyga następny load/CAS.
Nie dodajemy konkurencyjnego KsefSyncTimeoutError.

| Zdarzenie | Zachowanie |
| --- | --- |
| Własny globalny limit upłynął | Partial/time_budget dla niedokończonych strumieni po odebraniu rozpoczętego commita. |
| Własny limit kroku upłynął | Partial/step_time_budget tylko tego strumienia; pozostałe dostają kolej. |
| Nadrzędny deadline, także równy własnemu | Dotychczasowy KsefRateLimitWaitTimeout przerywa całe wywołanie. |
| Timeout sieci przed upływem limitów | Dotychczasowy KsefHttpError jest błędem strumienia. |
| Kooperatywne cancellation | KsefRequestCancelledError po sprzątaniu. |
| Anulowanie asyncio | Oryginalny asyncio.CancelledError; nie jest błędem bazy ani partial. |
| Fatalna awaria adaptera / naruszenie izolacji | Natychmiastowe przerwanie całego wywołania, niezależnie od raise_on_error. |

Koordynator porównuje źródło deadline'u, nie sam typ wyjątku. Nie zamienia
każdego KsefRateLimitWaitTimeout/TimeoutError w partial. Ograniczenie nadrzędne
ma pierwszeństwo przed globalnym i krokiem. Przed commitem sprawdzamy te reguły.

Po rozpoczęciu zapisu sync czeka na adapter z jego własnym skończonym timeoutem.
Async tworzy jedno zadanie, zachowuje silną referencję i osłania je przez
asyncio.shield. Anulowanie, także powtórne, jest zapamiętywane; SDK odbiera wynik
lub wyjątek zadania i czeka na sprzątanie, potem propaguje anulowanie. Udany
COMMIT pozostaje udany mimo anulowania. Nieznany wynik wymaga nowego load/CAS.
Nie uruchamiamy następnej strony lub commita po anulowaniu. Nie ma ukrytego
to_thread(sync_store), a adapter bez skończonych timeoutów nie spełnia kontraktu.

### Typy, kody i rozróżnienia

Wszystkie wymienione wyjątki synchronizacji, w tym KsefInvalidSyncCheckpointError,
dziedziczą po KsefSyncError, który dziedziczy po KsefError. Baza nie dziedziczy
po ValueError. KsefResponseLimitError ma osobną bazę opisaną poniżej.
Nowe ErrorCode dopisujemy na końcu enuma.

| Typ | Przyczyna i granica | ErrorCode / wyjście CLI |
| --- | --- | --- |
| KsefSyncError | Pozostała znana awaria orkiestracji z bezpiecznym reason_code, np. invalid_metadata; nie worek na błędy programistyczne. | SYNC_ERROR / API_ERROR |
| KsefInvalidSyncCheckpointError | Zła struktura, wersja, tożsamość lub niezmienniki trwałego stanu. Nie oznacza legalnego stanu w złej fazie. | INVALID_SYNC_CHECKPOINT / VALIDATION_ERROR |
| KsefSyncStateError | Poprawny checkpoint użyty w niedozwolonej operacji, np. begin_cycle dla active. | SYNC_STATE_ERROR / VALIDATION_ERROR |
| KsefSyncConflictError | CAS nie dopasował generacji/rewizji; nie nadpisujemy nowszego stanu. | SYNC_CONFLICT / API_ERROR |
| KsefSyncDataConflictError | Sprzeczne kanoniczne hashe tego samego dokumentu. Nie używamy do limitu bajtów ani błędu SQL. | SYNC_DATA_CONFLICT / API_ERROR |
| KsefSyncLimitError | Przekroczony limit body, kanonicznej strony lub wygenerowanego checkpointu; atrybut limit_stage. | SYNC_LIMIT_EXCEEDED / API_ERROR |
| KsefSyncStoreError | Awaria load/commit adaptera; wynik zapisu i zasięg awarii są osobnymi atrybutami poniżej. | SYNC_STORE_ERROR / IO_ERROR |
| KsefSyncRunError | Agregat oczekiwanych błędów strumieni po obsłużeniu pozostałych; zawiera report. | SYNC_RUN_FAILED / API_ERROR |
| KsefResponseLimitError | Błąd nowego limited HTTP przed wejściem do modelu sync; bez retry i bez dziedziczenia po KsefHttpError. | RESPONSE_LIMIT_EXCEEDED / API_ERROR |

KsefResponseLimitError dziedziczy bezpośrednio po KsefError. Bounded source
mapuje go na KsefSyncLimitError(limit_stage="response_body") przy wejściu
synchronizacji. Parser źródła nie musi rozumieć store ani checkpointu.
Dotychczasowe błędy HTTP/paginacji w pull pozostają rozpoznawalne. Nieznany
status, nie-JSON lub brak wymaganego hasha nie są konfliktem DB ani pustą stroną.
Błędne argumenty fabryki/parametry to ValueError/TypeError przed I/O.

KsefSyncStoreError ma jawne pola:

- operation: load albo commit;
- commit_outcome: not_started, rolled_back, committed albo unknown;
- failure_scope: stream albo store.

Dla load wynik to not_started. Committed oznacza, że adapter wie o zatwierdzeniu,
ale nie dostarczył poprawnego receipt; SDK nadal zatrzymuje strumień i wymaga
ponownego odczytu. Unknown nie staje się rolled_back po utracie połączenia.
Failure_scope=store zawsze przerywa koordynator. Dwa atrybuty nie są kodowane
w trzech konkurencyjnych ErrorCode: CLI ma jedną kategorię IO_ERROR, aplikacja
odczytuje strukturę. Dozwolone kombinacje i niemożliwe wartości mają testy.

Raise_on_error=False zmienia wyłącznie agregację oczekiwanych błędów strumieni:
zwraca report z failed zamiast KsefSyncRunError. Gdy True, ten sam report jest
w error.report, bez dodatkowej wartości zwrotnej. Cancellation, nadrzędny deadline,
awaria store-wide, naruszenie izolacji i błędy programistyczne nie są maskowane.

Oczekiwane awarie silnika są łapane po jawnej liście typów. Normalizacja obcych
wyjątków odbywa się tylko na wąskiej granicy adaptera, z bezpiecznym komunikatem;
nie stosujemy except Exception wokół całego silnika jako zamiany błędów na failed.
Surowy wyjątek adaptera jest poufnym atrybutem, a wrapper jest podnoszony from None.
Testy redakcji obejmują str, repr, bezpieczne to_dict i pełny traceback.format_exception,
łącznie z przyczynami i kontekstem. DSN/payload nie mogą wyciec przez łańcuch błędów.

### Przekroczenia limitów

KsefSyncLimitError ma limit_stage (response_body/page_snapshot/checkpoint),
limit_bytes i obserwowany rozmiar, gdy jest znany. Status to failed, nie partial;
nie zatwierdzamy strony, HWM ani kandydata następnego kursora. Powtórzenie tej
samej strony nie jest automatyczną naprawą. Żadna z tych klas nie uruchamia retry.

Limit generowanego kursora zgłaszany przez range search zachowuje istniejący
KsefIncompletePaginationError(reason_code="cursor_size_limit"). Daje failed
bez commita strony; nie mapujemy go po tekście komunikatu ani nie parsujemy
kursora ponownie w sync. Limit checkpoint dotyczy nowej koperty, którą udało
się przygotować z poprawnym kursorem, ale której nie można zapisać w granicach.

Za duży JSON checkpointu już odczytywanego z magazynu jest natomiast
KsefInvalidSyncCheckpointError(reason_code="checkpoint_size_limit") przed HTTP.
Za duży query przy konstrukcji jest ValueError. Nie tworzymy martwego scope.
Odzyskanie aktywnej strony przez mniejszy page_size i sytuacje bez takiej
możliwości rozstrzyga tabela w §15. Limity nie są automatycznie podnoszone.

## 12. Deduplikacja i podział danych dokumentu/roli

Koordynator używa `observation_page()`, nie zredukowanego `page.items`.
W istniejącym SDK reprodukcja dwóch wierszy o tym samym numerze i różnych
hashach kończyła się jednym rekordem bez błędu. Nowy kontrakt ma zachować
obydwa przed kontrolą integralności. Stare publiczne page() nie zmienia zachowania.

| Dane | Właściciel i reguła |
| --- | --- |
| Namespace, środowisko, kontekst, numer KSeF | Klucz trwałego dokumentu; role i zadania nie tworzą drugiego dokumentu w tym scope. |
| `invoice_hash` | Kanoniczny SHA-256 dokumentu; wymagany i walidowany dla sync. Niezgodność nie jest last-write-wins. |
| Rola, stream_id, powiązanie z dokumentem | Obserwacja konkretnego strumienia; zachowana nawet przy fakturze znanej z innej roli. |
| Daty issue/invoicing/acquisition/permanent storage | Pełne metadane obserwacji; permanent storage dodatkowo podlega walidacji zakresu i kolejności. |
| Numer faktury, kwoty, waluta, typ i form code | Metadane obserwacji, bez automatycznego scalania w globalny dokument. |
| Seller, buyer, authorized_subject, third_subjects | Widok obserwacji uprawnień danej roli. Nie nadpisuje obserwacji innych strumieni. |
| Invoicing mode, self-invoicing, attachment, hash_of_corrected_invoice | Pozostałe znane pola metadanych obserwacji; ten sam sposób serializacji co model SDK. |

Minimalny wiersz dokumentu zawiera klucz i invoice hash; pełny model pozostaje
w obserwacjach. Wymagana jest spójność numeru, poprawny hash 32-bajtowy i poprawna
data permanent storage przed przygotowaniem commita. Nie wystarcza samo
istnienie opcjonalnego pola w ręcznie pisanym `InvoiceMetadata`.

W obrębie strony sprzeczne hashe tego samego numeru dają błąd przed zapisem.
Zgodne obserwacje można zapisać przez idempotentny upsert; nie przechowujemy
historii wszystkich kopii w pamięci. Zmiana niekluczowych metadanych aktualizuje
wyłącznie widok danego strumienia, w kolejności zatwierdzonych obserwacji.

Między stronami, restartami, rolami i różnymi `sync_key` każda obserwacja
przechodzi atomową kontrolę hashy dokumentu w magazynie. CAS checkpointu jednego
zadania nie chroni współdzielonego dokumentu przed innym zadaniem. Adapter
wstawia dokument warunkowo i porównuje istniejący hash pod właściwą ochroną
transakcji/unikalności; nie wykonuje osobnego niezabezpieczonego select-then-update.
Konflikt wycofuje stronę i jej checkpoint. Test obejmuje dwa równoległe zadania.

Brak faktury w późniejszym wyniku nie jest poleceniem usunięcia dokumentu ani
obserwacji. Zmiana widoczności/uprawnień wymaga procedury z §15.

## 13. Model checkpointu, przejścia i niezmienniki

Jeden `InvoiceSyncCheckpoint` dotyczy dokładnie jednego scope. Nie ma listy
pending_roles, duplikowanego statusu roli ani globalnego cycle_completed.

```json
{
  "kind": "invoice-sync-stream",
  "version": 1,
  "scope": {
    "namespace": "tenant-42",
    "environment": "af1a268b339f8d65837d13893c289bd13d582fde5c5c4f375c8eb6a7480f58a2",
    "context_key": "Nip:5265877635",
    "sync_key": "erp-invoices",
    "stream_id": "1f28405985272d5fce65820d0c029c24f3a16df08de007517a4d7b3842038038"
  },
  "spec": {
    "semantics_version": 1,
    "query": {
      "subjectType": "Subject1",
      "dateRange": {
        "dateType": "PermanentStorage",
        "from": "2024-01-01T00:00:00Z",
        "restrictToPermanentStorageHwmDate": true
      }
    }
  },
  "generation_id": "11111111-1111-4111-8111-111111111111",
  "revision": 1,
  "committed_hwm": null,
  "phase": "active",
  "active": {
    "cycle_id": "22222222-2222-4222-8222-222222222222",
    "from": "2024-01-01T00:00:00Z",
    "cycle_to": "2026-10-27T19:00:00Z",
    "page_size": 100,
    "window_days": 100,
    "cursor": null
  },
  "last_commit_id": "33333333-3333-4333-8333-333333333333"
}
```

Przykład ma pełny kształt i zgodne skróty środowiska/spec; staje się fixture
schematu v1. Stan brakujący oznacza brak wiersza, a nie checkpoint o fazie
uninitialized. Zestawy kluczy koperty, scope, spec i active są ścisłe;
idle ma active=null, bez pól cyklu przechowywanych w innym miejscu.

| Stan wejścia | Operacja | Wynik zatwierdzony atomowo |
| --- | --- | --- |
| Brak wiersza | begin_cycle(None, until) | Active, generation UUID, revision 1, HWM None, cursor None. |
| Idle z HWM | begin_cycle(checkpoint, until) | Active od HWM inkluzywnie, nowy cycle_id, rewizja +1. |
| Active, kursor dowolny | next_batch, jest następny kursor | Dane + nowy kursor, HWM bez zmian, rewizja +1. |
| Active, ostatnia strona | next_batch | Dane + zatwierdzony HWM, phase idle, active None, rewizja +1. |
| Idle | next_batch | None, bez HTTP i bez zmiany stanu. |
| Active | begin_cycle | KsefSyncStateError; nie porzuca aktywnego odczytu. |
| Dowolny poprawny zapisany | Operacja administracyjna z §15 | Kontrolowane przejście CAS, nigdy ręczna edycja HWM. |

Niezmienniki walidowane przed HTTP i przed przyjęciem następnego stanu:

1. Scope i spec odpowiadają wybranemu strumieniowi; stream_id jest zgodny
   z kanonicznym hashem spec. Generacja/rewizja są zgodne z oczekiwaniem partii.
2. `phase=active` wtedy i tylko wtedy, gdy active jest obiektem. Idle wymaga
   committed HWM i `active=None`; nie ma idle z nieukończoną historią.
3. Active.from jest równe committed HWM albo initial_from przy HWM None.
   Active.cycle_to nie jest wcześniejsze od from; daty zachowują pełną precyzję.
4. Query całego skanu różni się od spec wyłącznie zapisanymi datami. `dateType`,
   rola, filtry, ograniczenie HWM i Asc są stałe. Jego to jest active.cycle_to;
   daty requestów wewnętrznych należą do maszyny okien/HWM, zgodnie z §8.
5. Cursor pasuje do tak zbudowanego query oraz zapisanych parametrów wykonania,
   co sprawdza validate_cursor bez HTTP. Nie wolno przyjmować kursora innego
   strumienia albo innej granicy jako pozornie zgodnego tekstu.
6. Strona pośrednia nie podnosi committed HWM. Ostatnia strona ma poprawny HWM
   pomiędzy active.from a cycle_to i nie niższy od poprzednio zatwierdzonego.
7. Zwykłe przejście ma tę samą generację, rewizję dokładnie +1 i poprawny commit_id.
   Tylko określone operacje administracyjne mogą zmienić generację/cofnąć postęp.
8. Żaden stan ani receipt nie ma ukrytych pól zmieniających adres HTTP, poświadczenia
   lub wybraną rolę. Nie akceptujemy nieznanych kluczy schematu v1.

## 14. Bezpieczny snapshot i przykład SQLite

Checkpoint, scope i batch są logicznie głęboko niemutowalne. Sam frozen=True
oraz krotka modeli nie wystarczają, ponieważ modele mają listy i zagnieżdżone obiekty.
Partia utrwala prywatny kanoniczny snapshot JSON danych i następnego stanu
jako bytes. Właściwości udostępniające modele/słowniki zwracają świeże kopie;
mutacja third_subjects przez adapter nie zmienia checkpointu ani partii.
Nie obliczamy identyfikatora commita z mutowalnego grafu obiektów.

Granice: 4 MiB zakodowanego checkpointu na strumień, kursor do istniejących
2 MiB, kanoniczny query do 128 KiB, timestamp do 128 znaków, rewizja
1..2^63-1, maksymalnie cztery strumienie koordynatora. Dane strony mają limit
16 MiB kanonicznego snapshotu przed jego kopiowaniem. Nowa ścieżka HTTP z §5
ogranicza również body przed parsowaniem do 16 MiB. Kanonikalizacja może
zwiększyć rozmiar względem body; wtedy strona jest jawnie odrzucana.
Limit body nie oznacza limitu 16 MiB całego procesu: parser i modele mają
narzut. Stare ścieżki transportu i pamięć aplikacji zachowują własny kontrakt.

`from_json` sprawdza rozmiar przed parsowaniem. `from_dict` wykonuje ograniczone
przejście po węzłach/głębokości przed pełną serializacją i kopią. Ustalamy
maksymalną głębokość 16 i 50 000 węzłów checkpointu; sam cursor jest tekstem.
Sprawdzamy limit również po kanonikalizacji. Odrzucamy duplikaty kluczy JSON,
NaN/Infinity, bool jako licznik, obce role, złe UUID, regresje i sprzeczne fazy.
Format v1 jest wersjonowany; kolejne wydanie czyta go albo zapewnia migrację.

Nie zapisujemy tokenów, kluczy, podpisanych URL-i ani pełnego zbioru numerów
KSeF w checkpoincie. Filtry, kontekst i kursory pozostają poufne. Repr,
bezpieczne to_dict błędów/raportu i logi nie pokazują danych dokumentów.
Jawne to_json checkpointu jest formatem trwałym aplikacji, nie diagnostyką.
SHA-256 scope nie jest szyfrowaniem lub uwierzytelnieniem. Stan z niezaufanego
klienta wymaga ochrony aplikacji; nie rozszerzamy OperationState.KINDS.

Nowy `docs/examples/invoice_sync_sqlite.py` pokazuje standardową bibliotekę:

| Tabela | Klucz i zawartość |
| --- | --- |
| sync_checkpoints | PK(namespace, environment, context_key, sync_key, stream_id); generation, revision, spec hash, JSON, last_commit_id. |
| invoices | PK(namespace, environment, context_key, ksef_number); kanoniczny invoice hash. |
| invoice_observations | Pełny scope strumienia + numer KSeF; FK do dokumentu i pełne metadane widoku. |
| outbox, opcjonalnie w aplikacji | Unikalny klucz dokumentu + rodzaj zadania/wariant; bez powiązania idempotencji z rewizją lub generacją. |

SQL jest parametryzowany. `BEGIN IMMEDIATE`, CAS, kontrola hasha dokumentu,
upsert obserwacji i checkpoint mają jeden COMMIT/ROLLBACK. Odrzucamy obcą
aktywną transakcję. Nie trzymamy transakcji przez HTTP. Sprawdzamy default
sqlite3 i autocommit na wspierających go wersjach Pythona oraz dwa procesy
z innymi sync_key zapisujące ten sam dokument.

Baza, katalog, WAL/SHM i backupy są prywatne. Nie przechowujemy w nich tokena,
nie logujemy JSON i nie kasujemy bazy po błędzie. Przykład nie staje się
produkcyjnym magazynem w pakiecie. Dla async podajemy natywny protokół i przykład
integracji z adapterem aplikacji; nie wywołujemy sqlite3 na event loop.
Współdzielone testy kontraktu można uruchomić dla innych adapterów, bez zależności
ORM ani serwera PostgreSQL wymaganych przez podstawowy SDK.

## 15. Procedury odzyskania, częściowy replay i granica XML

Operacje administracyjne są metodami uchwytu, tworzą puste partie do atomowego
commit przez ten sam store i nie wykonują HTTP. Nie uruchamiają się same.
Wymagają jawnego kodu reason zamiast swobodnego tekstu z sekretami.

| Operacja | Dokładne działanie |
| --- | --- |
| restart_active(checkpoint, *, reason, page_size=None, window_days=None) | Active: porzuca tylko kursor, zachowuje committed HWM i cycle_to; odtwarza skan od HWM albo initial_from. Rewizja +1, ta sama generacja. |
| restart_backfill(checkpoint, *, until, reason) | Nowa generacja, HWM None, aktywny skan od initial_from, rewizja +1. Dokumenty i obserwacje zostają; stare pokrycie nie jest utrzymywane jako aktualne. |
| fence_after_restore(checkpoint, *, reason) | Nowa generacja i rewizja +1 po spójnym backupie; zachowane HWM oraz kursor. Nie odtwarza danych utraconych po dacie backupu. |

Walidacja jest dwustopniowa: codec sprawdza bezpieczną kopertę, scope/spec,
generację, rewizję, daty, fazę i ograniczony tekst kursora. Semantykę kursora
sprawdza validate_cursor przed zwykłym HTTP. Restart_active celowo nie wymaga
semantycznej poprawności starego kursora, bo go odrzuca; musi jednak ufać
poprawnej kopercie i committed HWM. Nie naprawia złej tożsamości ani uszkodzonego HWM.
Za duży lub nieczytelny JSON nie jest omijany przez helper.

| Przyczyna | Działanie i ograniczenie |
| --- | --- |
| 429/5xx lub chwilowy błąd odczytu | Najpierw zwykłe wznowienie z tym samym checkpointem i retry klienta; nie resetujemy automatycznie cyklu. |
| Kursor semantycznie uszkodzony/odrzucony po aktualizacji, poprawna koperta | Restart_active(reason="cursor_invalid" albo "library_upgrade"); czyta ponownie bez przesuwania HWM. |
| Body lub snapshot strony przekroczył limit | Failed; restart_active(reason="page_size_limit", page_size=mniejszy), z poprawnym minimum API 10. Dotychczasowy kursor nie może być użyty z nowym page_size. |
| Pojedynczy rekord lub strona przy minimum nadal przekracza limit | Brak automatycznej naprawy: jawna zmiana źródła/filtrów albo wersji/konfiguracji o udokumentowanych nowych granicach. Nie pomijamy rekordu. |
| Runtime limit kursora/checkpointu | Zachować ostatni poprawny stan; restart_active(reason="checkpoint_limit") może pomóc po zmianie parametrów lub biblioteki, ale nie jest gwarancją naprawy. |
| transient empty_pages/inconsistent_response | Zwykłe wznowienie; świadomy restart_active(reason="transient_pagination_retry") dopiero po usunięciu przyczyny. Klasa niekompletności nie zawsze jest deterministyczna. |
| Ponad limit rekordów na identycznej granicy, brak postępu | Restart ani backfill tej samej spec nie rozwiązują tego samodzielnie. Potrzebny zweryfikowany podział filtrów lub przyszły backend; eksport też nie jest uniwersalnym obejściem. |
| Zmiana uprawnień/widoczności | Restart_backfill(reason="permissions_changed"); nie wyciągamy wniosku o usunięciu z samego braku wyniku. |
| Spójny restore bazy | Zatrzymać stare workery, fence_after_restore(reason="backup_restored"), dopiero potem uruchomić nowe. |
| Nieczytelna koperta lub sprzeczny scope/HWM | Błąd, bez udawania load=None. Odtworzyć spójny backup albo utworzyć świadomie nowy scope i backfill z zaufanej konfiguracji. |

Reason jest skończonym enumem kodów wskazanych w tabeli plus operator_replay.
Operacje sprawdzają zgodność kodu z rodzajem przejścia. Nie używamy ogólnego
pagination_recovery jako obietnicy naprawy każdej niekompletności.
Brak wiersza dopuszcza begin_cycle(None, until=...), lecz istniejący uszkodzony
wiersz nie jest brakiem: inicjalizacja nie omija CAS i niczego nie kasuje.
Nie ma set_hwm ani wskazówki ręcznej edycji JSON.

### Częściowy ponowny odczyt

V1 restart_backfill zawsze zaczyna od niezmiennego initial_from. Nie dodajemy
argumentu from_ do tej metody: częściowy replay przy niezmiennym strumieniu
wymagałby zdefiniowania pokrycia wielu przedziałów i ich generacji.
Jest to jawnie odłożone rozszerzenie, nie ukryta semantyka istniejącego helpera.

Ponowny odczyt ostatnich sześciu miesięcy można wykonać jako nowy strumień
z innym initial_from (nowy stream_id, niekoniecznie nowy sync_key) lub jako
skończony range search z istniejącym przykładem transakcyjnym. W jednym
koordynatorze nadal jest najwyżej jedno query na rolę. Dokumenty są deduplikowane,
ale obserwacje nowego scope są osobne. Taki replay nie podnosi pokrycia ani
nie odnawia deklaracji starego strumienia dla całej historii. Po zmianie
uprawnień, która może dotyczyć starszych danych, trzeba unieważnić stare
pokrycie przez pełny restart_backfill albo świadomie nie deklarować go jako aktualnego.

### Backup i XML

Backup obejmuje dokumenty, obserwacje, checkpointy i outbox w jednej kopii.
SDK sam nie wykrywa rollbacku magazynu; generacja ogradza opóźnione partie po
udokumentowanej procedurze. Działania zewnętrzne wykonane po dacie backupu
nadal wymagają własnych kluczy idempotencji. Pełna rekonsyliacja i usuwanie
historycznych widoków są osobnym procesem aplikacji.

XML może mieć zadanie outboxu zapisane razem z metadanymi, o stabilnym kluczu
dokument/rodzaj/wersja. Worker XML ma własny hash i status. Nie wiążemy jego
idempotencji z generacją lub commit_id. HWM metadanych nie oznacza XML-ready;
przyszły tryb pełnych dokumentów otrzyma własny kontrakt pokrycia.

## 16. Pliki i publiczne typy

| Plik | Odpowiedzialność |
| --- | --- |
| src/ksef_client/invoice_sync_state.py | Scope, checkpoint, snapshot, czyste przejścia i procedury administracyjne. |
| src/ksef_client/invoice_sync.py | Uchwyty strumieni, koordynatory sync/async, store protocols i report. |
| src/ksef_client/invoice_range_search.py, invoice_search.py | Identity, validate_cursor, observation_page; te same istniejące maszyny. |
| src/ksef_client/clients/invoices.py, http.py, token_manager.py | Fabryki/normalizacja oraz jawny refaktor hooku odbioru w 0b; regresje nadpisań auth i istniejącego transportu. |
| src/ksef_client/facade.py, tools/generate_async_facade.py | Fabryka i dokładna obsługa wywołań bez I/O. |
| src/ksef_client/async_facade.py | Wygenerowany adapter. |
| src/ksef_client/__init__.py, exceptions.py, cli/exit_codes.py | Eksport typów, taksonomia i mapowanie błędów. |
| docs/invoice-sync.md i przykłady | Instrukcja użytkowa po implementacji, niezależna od niniejszego planu. |

Publiczne typy: InvoiceSync/AsyncInvoiceSync, InvoiceSyncStream/AsyncInvoiceSyncStream,
InvoiceSyncScope, InvoiceSyncCheckpoint, InvoiceSyncBatch, InvoiceSyncCommitReceipt,
InvoiceSyncCoverage, InvoiceSyncReport, InvoiceSyncStreamResult oraz oba store protocols.
Addytywne typy wyszukiwania: InvoiceMetadataSearchIdentity i InvoiceMetadataObservationPage.
Nie generujemy ich z OpenAPI. Czysty moduł stanu nie importuje HTTP, SQL, fasady
ani asyncio. Wewnętrzny helper precyzyjnego porównania dat jest współdzielony
z wyszukiwaniem; nie zmieniamy publicznego parsera datetime.

## 17. Testy i mierzalne kryteria odbioru

### A. Etap 0 i zgodność z 0.21.0

- Stare page/pages/items zachowują wyniki i kursor v1; observation_page zwraca
  pełne wiersze. Reprodukcja dwóch hashy jednego numeru jest regresją obowiązkową.
- Identity i validate_cursor nie wykonują HTTP; sprawdzamy niezgodny kontekst,
  filtry, scan_to, page size i parametry okna, także na innym strumieniu.
- Environment fixture porównuje scope hex z helperem operations i zachowuje
  prefiks kursora v1. /v2 oraz /api/v2 to odrębne scope; kwoty origin mogą być wspólne.
- Standardowe frozen options odrzucają przypisanie base_url. Zmienny testowy
  adapter wykazuje zmianę identity między krokami przed HTTP; niezmienny cel
  pojedynczego limited request i brak przekierowań są testowane osobno.
- Generator tworzy fabrykę bez await, ma potrzebny import i mapping; nieznane
  wywołanie I/O nadal odrzuca. Test semantyczny i generator --check.
- Odbiór 0b: Content-Length, body limit, kompresja, 3xx i wolne porcje.
  Dodatkowo 401/refresh, 429 z uszkodzonym lub za dużym body (cooldown zachowany),
  nested auth oraz równoległe zwykłe/limited requesty. Nie dziedziczą wzajemnie
  polityki odbioru, celu ani ograniczeń; reset następuje także po wyjątku.
- Nowy sync nie wymaga dodatkowego tokena; test konsumenta używa publicznych importów.

### B. Bezpieczeństwo danych, postęp i strumienie

- Deterministyczny zbiór wieloletni, okna, obcięcia, identyczne daty, puste strony,
  pełna precyzja 7 cyfr i różne offsety. Porównanie dokładnych zbiorów, nie liczników.
- Restart nowego procesu po każdej stronie; HWM strony pośredniej nigdy nie
  trafia do committed HWM. Empty-final i brak HWM mają odrębne przypadki.
- Role z różnymi początkami, puste/rozłączne przecięcie pokrycia, aktywny cykl
  ze starym HWM. To=cycle_to jest sprawdzane na wejściu fabryki skanu;
  transport ma poprawne zmienne wire bounds po restarcie i po HWM clipping.
- Puste queries/role oraz powtórzone role po normalizacji są odrzucane przed I/O.
  Raport ma dokładnie jeden wynik na scope, bez all([]) jako sukcesu.
- Trwałe 403 jednej roli: inna rola odbiera fakturę A, potem B w kolejnych
  wywołaniach. Długi backfill nie blokuje zdrowej roli z krótką historią.
- Round-robin, globalny czas i limit pojedynczego kroku; zdrowe role dostają
  kolej, a jeden duży backfill wykorzystuje czas po trzech pustych rolach.
  Zwiększenie step_time_budget umożliwia jawnie droższy odczyt, bez hidden retry.
- Dodanie roli nie resetuje pozostałych; zmiana query tworzy nowy scope;
  wycofanie roli nie usuwa danych, rotacja tokena nie zmienia scope.
- Sprzeczne hashe na jednej stronie, między stronami, po restarcie i między
  równoległymi zadaniami. Zgodne duplikaty zachowują obserwacje wszystkich ról.
- Mutacja zagnieżdżonych list modeli po utworzeniu partii nie zmienia jej snapshotu.

### C. Trwałość i adapter magazynu

- Rzeczywista SQLite, awaria po każdym SQL, na COMMIT i po COMMIT przed receiptem;
  baza zawiera dane i checkpoint razem albo żadne. Również default/autocommit.
- Dwa procesy konkurują o scope; inne namespace, środowisko i kontekst są odizolowane.
- Dwa sync_key zapisują ten sam dokument: konflikt hasha nie jest nadpisaniem.
- Niepoprawny receipt, stale read, błąd load zamiast None oraz nieznany wynik
  zakończenia. Nie ma bezwarunkowego ponowienia zapisu.
- Restart_active odrzuca uszkodzony kursor tylko przy poprawnej kopercie;
  nieczytelny checkpoint nie staje się None. Klasy limitów i każda ścieżka
  odzyskania mają test bez przesunięcia granicy. Partial replay nowego scope
  nie podnosi pokrycia starego strumienia.
- restart_active/backfill/fence działają przez CAS. Odtworzona baza odrzuca
  partię starej generacji; test nie obiecuje automatycznego wykrywania backup rollback.
- CAS konflikt z równoległym restart_backfill unieważnia cached coverage
  i common_coverage w wyniku; raport pokazuje obserwowaną generację/rewizję.
- Outbox ma stabilną idempotencję dokumentu po replay i zmianie generacji.
- Wspólny zestaw testów kontraktu dla sync/async adapterów, nie tylko liberalny fake.

### D. Retry, token i async

- Bez allowlisty POST błąd nie jest ponawiany; z allowlistą retry respektuje
  Retry-After, liczbę prób i pozostały czas. Nie mutujemy konfiguracji klienta.
- Odświeżenie tokena w środku backfillu i po długim retry; None dociera do
  transportu, provider pracuje per próba. Statyczny token ma oddzielny test 401.
- Te same przejścia i pokrycie w sync/async. Brak sqlite3 na event loop.
- Anulowanie przed commitem, podczas niego, wielokrotne anulowanie i timeout
  sterownika: zadanie commita jest zawsze odebrane, brak kolejnego HTTP/zapisu.
- Limit globalny/kroku -> odrębne powody partial; nadrzędny deadline i cancellation
  zachowują typy. Test równego deadline'u daje pierwszeństwo ograniczeniu nadrzędnemu.
- Store outcome/failure_scope i raise_on_error True/False mają pełną tabelę testów;
  store-wide błąd nie zamienia się w wynik przy False. Pełne tracebacki nie zawierają
  markerów DSN/tokenów z cause/context. Błąd sieci nie jest limitem rozmiaru.

### E. Limity i wydajność

- Maksymalny legalny kursor 2 MiB, checkpoint 4 MiB i query 128 KiB; granice
  przed i po kanonikalizacji, rozrost Unicode i za głęboka struktura.
  Runtime cursor_size_limit zachowuje typ błędu paginacji i zatrzymuje zapis;
  zbyt duża nowa koperta ma odrębny KsefSyncLimitError(limit_stage="checkpoint").
- Repr, raporty i błędy nie ujawniają kursorów, modeli faktur, tokenów, DSN ani payloadu.
- Jeden odczyt strony -> najwyżej jedno żądanie metadanych bez retry i jeden
  commit danych; brak HTTP per faktura i brak transakcji trzymanej przez HTTP.
- Porównanie peak RSS dla 50 tys. i 500 tys. rekordów przy identycznej stronie,
  imporcie, danych wiersza, cache SQLite i konfiguracji. Każdy wariant jest świeżym
  izolowanym procesem. Warunek to max(0, peak_RSS_500k - peak_RSS_50k) <= 32 MiB,
  nie peak_RSS <= 32 MiB. Zachowujemy limity 16 MiB body i snapshotu; narzut parsera,
  modeli oraz kopii powoduje większy absolutny peak i jest jawnie raportowany.
  Generator i odbiorca nie materializują całego zbioru w RAM.
- Pomiar referencyjny: Linux/Python 3.12, resource.getrusage(RUSAGE_SELF).ru_maxrss
  z przeliczeniem KiB na bajty, trzy pary procesów i maksimum różnic par. Odczyt
  obejmuje proces z httpx, modelami i SQLite; tracemalloc jest tylko diagnostyką
  alokacji Pythona. Raport zawiera oba absolutne peaki, różnicę i środowisko.
  Benchmark nie jest mnożony przez całą macierz Pythona. Maksymalna legalna strona
  ma oddzielny stress test, bez arbitralnego limitu 32/64 MiB całego procesu.
- Raport pomiarów zawiera rozmiar checkpointu, czas serializacji/commita i p50/p95
  kroku przy największej granicy deduplikacji. Czas nadrobienia historii uwzględnia
  rzeczywisty limit HTTP; nie obiecujemy przepustowości niezależnej od KSeF.

### F. Live E2E na dokładnym wheelu

Jeden zatwierdzony node pytest jest nadzorcą dwóch kolejnych procesów fazowych.
To jedna próba scenariusza, bez ponownego wykonania po niepowodzeniu.
Proces bootstrap kończy się, zanim proces incremental odtworzy stan z tej
samej SQLite. Nie przekazujemy tokenów/kluczy w argumentach; dane fixture są
w środowisku, a konfiguracja testu i baza w prywatnym tmp_path.

1. Bootstrap wysyła unikalną A w TEST, jawnie Subject1. Initial_from to UTC
   sprzed wysyłki o 5 minut, zachowane dla obu procesów. Nie zakładamy pustej bazy KSeF.
2. Czeka na A pod HWM: polling co 60 s, miękki limit 600 s i ograniczone retry.
3. Wykonuje run_once do SQLite, sprawdza A i H1 z
   InvoiceMetadataObservationPage.permanent_storage_hwm_date, po zatwierdzeniu
   pełnego skanu. H1 pochodzi z checkpointu, nie z daty ostatniej faktury.
4. Po zakończeniu bootstrap nowy proces incremental odczytuje checkpoint,
   wysyła B i potwierdza permanentStorageDate(B) > H1, następnie czeka na B pod HWM
   z takim samym miękkim limitem 600 s.
5. Drugi run_once zaczyna skan od H1 inkluzywnie. Wrapper potwierdza granice
   wejścia skanu oraz poprawne okna/HWM requestów; nie wymaga stałego to na każdym HTTP.
6. B jest w bazie, A nie ma drugiego dokumentu, a nowy HWM wynika z ukończonego
   skanu. Trzeci pusty cykl nie zastępuje dowodu przyrostu B.

Jeżeli run_once zwróci partial z limitem pracy, faza może kontynuować wyłącznie
od zapisanej aktywnej pozycji w ramach wspólnego miękkiego deadline. Nie wysyła
ponownie A/B i kończy odczyt po ukończeniu tego cyklu, bez rozpoczynania następnego.
Failed albo niepewny COMMIT nie uruchamiają automatycznie nowej próby fazy.

Każdy proces przed i po pracy jawnie weryfikuje installed-wheel mode, ścieżkę
importu i bajty SDK względem dokładnego KSEF_TEST_WHEEL. Testy/helper pochodzą
z zaufanego checkoutu workflow; worker nie korzysta z lokalnego src ani editable
install. JUnit reprezentuje jeden nadrzędny scenariusz z manifestu, a fazy są
krokami restartu, nie rerunem testu. Artefakt zawiera wyłącznie bezpieczne dowody.

Miękki deadline logiki wynosi 1740 s łącznie; każde run_once ma time_budget=120 s.
Twardy watchdog rodzica ma 1800 s od startu pierwszej fazy, wspólne dla obu.
W CI Ubuntu każdy proces fazowy ma własną sesję/grupę. Po limicie rodzic
zatrzymuje grupę, czeka najwyżej 10 s na zakończenie, następnie wymusza jej
zakończenie i odbiera procesy/wyjście. Wyjście jest ograniczone i sanitowane,
bez nieograniczonego capture_output w RAM ani wypisywania środowiska.
Test jest failed nawet jeśli dane zostały zapisane. Wymuszone zabicie nie oznacza
rollbacku: ewentualny następny odczyt
musi respektować load/CAS. Job CI pozostaje dodatkowym ostatnim limitem.

Testy watchdogu używają procesów z kontrolowanym zawieszeniem i potwierdzają
brak osieroconych dzieci. Mechanizm narzędzia testowego dla CI Linux nie jest
nową funkcją SDK ani obietnicą przerywania dowolnego kodu aplikacji w 1800 s.
Ręczny runner na innym OS musi mieć równoważny nadzór procesów; nie udaje twardego
limitu przez sam request_control/asyncio.wait_for.

Nie ma skip/xfail/rerun scenariusza. Brak uprawnień innych ról nie osłabia testu:
fixture wybiera Subject1, pozostałe role i wymuszone awarie są deterministyczne.
Nowy node i helpery trafiają do manifestu/kontrolera oraz testów release gate.
Nie zmieniamy zaufanego pochodzenia testów i nie osłabiamy ochrony środowisk.
Nowy wyjątek gałęzi wymaga osobnego upoważnienia, wcześniejszy był jednorazowy.
Pełny odbiór: 100% pokrycia, lint/mypy, generatory/OpenAPI, Python 3.10–3.13
+ dodatkowa 3.14, wheel/sdist, CLI packaging, installed-wheel regressions oraz
bug/security review z naprawą potwierdzonych ustaleń.

## 18. Kolejność implementacji i bramki zależności

| Etap | Zakres | Warunek zakończenia |
| --- | --- | --- |
| 0a | Identity, validate_cursor, kontrakt obserwacji, generator i format środowiska | Czysta walidacja bez HTTP, zgodne kursory v1, wynik pełnych obserwacji na fetcherze testowym, semantyczny test generatora. |
| 0b | Hook body w istniejącym HTTP, ramki ContextVar, bounded stream i adapter observation_page | Własny odbiór/security review; pełne stare testy HTTP/auth/retry/budget, 401 reactive refresh, 429 przy błędzie body, 3xx i izolacja nested/concurrent requestów. |
| 1 | Scope, snapshot, stan per strumień i przejścia | Niezmienniki, limity, kanonikalizacja oraz schema v1 bez I/O. Może powstawać równolegle z 0b. |
| 2 | Pull i receipt/CAS, SQLite | Wymaga 0a+0b+1: dwuletnia historia oraz restart/awarie przy każdej granicy zapisu. Bez fallbacku sieciowego do starego odbioru. |
| 3 | Koordynacja i report | Wymaga 2: zdrowe role postępują, wolny backfill wykorzystuje pozostały budżet, poprawne pokrycie i klasyfikacja błędów. |
| 4 | Async i fasada | Pełne zależności 0b: zgodne przejścia, shield/drain, wielokrotne anulowanie, refresh i limit JSON. |
| 5 | Procedury odzyskania, dokumentacja, pomiary | Powiązanie przyczyn z helperami, brak ręcznej edycji HWM, RSS delta i przykłady. |
| 6 | Dokładny wheel, supervised A/H1/B/restart i końcowe review | Watchdog i brama TEST rzeczywiście wykonane; ustalenia naprawione, dowody związane z SHA. |

0b jest osobną jednostką review/PR, a nie uboczną częścią koordynatora. Może
powstawać równolegle z 1, lecz jest zależnością produkcyjnego pull w 2 oraz 3/4.
0a bez 0b nie publikuje obietnicy ograniczonego odbioru ani synchronizacji.
Jeżeli integracja 0b nie przejdzie regresji/security review, nie omijamy jej
przez nową pętlę retry lub nieograniczony fetch; funkcja czeka na domknięcie bramki.

Etapy są lokalnymi reviewowalnymi commitami. PR lub wysyłka na zdalne repo
wymaga nowego polecenia użytkownika; aktualna gałąź pozostaje lokalna.
Nie wydajemy synchronizacji przed odbiorem transakcji, izolacji, restartu i transportu.
Docelowo nowe API wymaga wydania minor po 0.21.0.

## 19. Dokumentacja, pakowanie i dalsze rozszerzenia

- README po implementacji promuje synchronizację metadanych i linkuje
  docs/invoice-sync.md; obecny plan nie jest reklamą istniejącej funkcji.
- Główny przewodnik pokazuje wyłącznie connect -> sync -> run_once, jawne retry,
  provider tokena i kontrolę complete/partial/failed. Nie wymaga znajomości
  wszystkich publicznych typów do pierwszej integracji.
- Osobne sekcje zaawansowane: scope wielu tenantów, pull/receipt, adapter store,
  limity i administracyjne procedury odzyskania. Publiczność typu nie oznacza,
  że musi być prezentowany w każdym quickstarcie.
- Nowe API przykładów jest jawnie oddzielone od przykładów działających na 0.21.0.
- Plan pozostaje w sdist zgodnie z istniejącą zasadą kompletności źródeł
  `recursive-include docs *.md *.py`. To świadoma decyzja, nie błąd bezpieczeństwa;
  nie zmieniamy MANIFEST.in tylko po to, aby ukryć dokument projektowy.
- Strategia eksportowa wykorzysta streaming export i osobny poufny stan operacji;
  kontynuacja obciętej paczki nie może być mylona z zatwierdzonym HWM.
- Automatyczny dobór backendu, rekonsyliacja widoczności, XML i obserwowalność
  będą osobnymi zmianami z własnym kontraktem pokrycia oraz migracji aktywnego stanu.

Przed rozpoczęciem kodowania powyższe decyzje są rozstrzygnięte: jednostką
poprawności jest strumień, magazyn zapewnia transakcję i CAS, a koordynator
nie zamienia częściowego powodzenia w pełny sukces. Zmiana tych kontraktów
wymaga aktualizacji planu i odpowiadających mu kryteriów testów.
