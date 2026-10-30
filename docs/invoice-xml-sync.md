# Synchronizacja metadanych i XML

SDK pobiera metadane faktur z KSeF i zapisuje ich oryginalne pliki XML w lokalnym
archiwum. Zapamiętuje postęp w SQLite. Po restarcie uruchamiasz ten sam kod
z tą samą bazą i katalogiem — zadania nie przepadają, a gotowe pliki nie są
pobierane ponownie.

| Potrzeba | Wybierz |
| --- | --- |
| Przyrostowe archiwum metadanych i XML | `client.invoices.sync_documents(...)` |
| Tylko metadane | `client.invoices.sync(...)` |
| Jednorazowe pobranie znanego numeru KSeF | `client.invoices.download(ksef_number)` |
| Paczka eksportu na dysk | `client.exports.start(filters).download_to(...)` |

## Pierwsze uruchomienie

Przykłady odpowiadają bieżącemu kodowi repozytorium. Zainstaluj checkout przez
`pip install -e .`. Ustaw zmienne środowiskowe **`KSEF_NIP`** i **`KSEF_TOKEN`**
dla środowiska TEST. Nie wpisuj tokena do źródeł ani do logów.
Synchronizacja korzysta z uprawnienia do odczytu faktur.

Kompletny skrypt z logowaniem i obsługą wyniku:
[invoice_sync_documents.py](examples/invoice_sync_documents.py).
Uruchom go z katalogu repozytorium:

```bash
python docs/examples/invoice_sync_documents.py
```

Skrypt tworzy `private/invoices.db` (metadane, postęp i zadania) oraz
`private/xml/` (XML i identyfikator magazynu). Własnego adaptera nie musisz pisać.
Poniższy pełny przykład wykonuje jeden cykl dla sprzedawcy i nabywcy:

```python
import os
from ksef_client import (
    Ksef, KsefClientOptions, KsefEnvironment, TokenCredentials, RetryConfig,
    FileInvoiceXmlStore, SQLiteInvoiceSyncStore,
)

options = KsefClientOptions(
    base_url=KsefEnvironment.TEST.value,
    retry=RetryConfig(retryable_post_paths=frozenset({"/invoices/query/metadata"})),
)
with Ksef.connect(
    options=options, context_type="Nip", context_value=os.environ["KSEF_NIP"],
    credentials=TokenCredentials(os.environ["KSEF_TOKEN"]),
) as client:
    with FileInvoiceXmlStore("private/xml") as storage, SQLiteInvoiceSyncStore.open(
        "private/invoices.db", enqueue_xml=True, xml_storage_id=storage.storage_id,
    ) as store:
        sync = client.invoices.sync_documents(
            namespace="firma", sync_key="erp", since="2024-01-01T00:00:00Z",
        )
        report = sync.run_once(store, storage, time_budget=600, raise_on_error=False)
        print(report.to_dict())
```

### Które ustawienia zachować przy ponowieniu?

| Ustawienie | Znaczenie |
| --- | --- |
| `since` | Początek historii. W kolejnych cyklach SDK samo korzysta z zapisanego postępu. |
| `namespace` | Twoja etykieta aplikacji lub firmy. |
| `sync_key` | Stała nazwa zadania, np. `erp`. |
| Ścieżka bazy i katalog XML | Zachowaj te same przy każdym uruchomieniu. |

Nie zmieniaj etykiet ani początku historii w celu wznowienia: zmiana konfiguracji
może utworzyć nowy strumień odczytu. Duży pierwszy odczyt może wymagać wielu
uruchomień — częściowy wynik po osiągnięciu budżetu jest normalny.

### Co zrobić z wynikiem?

| Wynik | Działanie aplikacji |
| --- | --- |
| `report.complete` | Wszystkie odkryte XML są gotowe do potwierdzonej granicy KSeF; zaplanuj kolejny cykl. |
| `report.xml.blocked > 0` lub strumień metadanych ma `failed` | Sprawdź kod błędu i usuń przyczynę. Nie resetuj zadań automatycznie. |
| `report.xml.stop_reason == "authentication"` | Przywróć możliwość logowania przed ponowieniem. |
| Pozostałe wyniki częściowe | Uruchom ponownie; `report.xml.next_attempt_at` wskazuje najbliższe zaplanowane ponowienie. |

`complete` odnosi się do granicy trwałego zapisu serwera (HWM), która może być
starsza od aktualnego czasu. Nie oznacza, że przyszłe uruchomienia są zbędne.
Niewykorzystany czas fazy metadanych przechodzi na pobieranie XML. Jeżeli
sprawdzanie magazynu zużyje cały budżet, nowy cykl metadanych nie zostanie rozpoczęty.

`metadata_time_budget=300` ogranicza fazę metadanych. XML wykorzystuje pozostały
czas całego przebiegu. Domyślnie worker przejmuje najwyżej 100 dokumentów,
pojedynczo. Harmonogram kolejnych uruchomień zapewnia aplikacja, także po sukcesie.
`raise_on_error=False` zwraca oczekiwane błędy dokumentów w raporcie; awarie
magazynu, błędy programistyczne, nadrzędny deadline i anulowanie nadal przerywają
wywołanie. `KsefXmlRunError.report` zawiera wynik danego przebiegu: `InvoiceDocumentReport`
przy wspólnym cyklu albo `InvoiceXmlReport` przy osobnym workerze. W obu przypadkach
`exc.xml_report` (także `exc.report.xml`) udostępnia raport XML. Wyjątek dziedziczy
po `KsefSyncRunError`.

Osobne wywołania to `sync.metadata.run_once(store)` i
`sync.xml.run_once(store, storage)`. Dla istniejącego `InvoiceSync`:
`worker = client.invoices.xml_sync(metadata_sync)`. Kontekst, środowisko i wybór
strumieni pozostają związane z metadanymi. Worker nie pobiera innych zadań bazy.

Retry HTTP pozostaje ustawieniem klienta; dla zapytań metadanych wymaga jawnego
dodania `/invoices/query/metadata` do allowlisty POST. Kolejka nie modyfikuje
konfiguracji transportu. Każda próba GET korzysta z istniejącego refreshu tokena,
budżetu grupy `invoiceDownload` i ograniczonego odbioru odpowiedzi.

## Odczyt z lokalnego archiwum

Nazwy plików są techniczne; nie trzeba ich samodzielnie interpretować. Odczytuj
XML przez magazyn, który ponownie sprawdzi hash. Wewnątrz tych samych bloków
`with`, po `run_once`, możesz przetworzyć pierwszą stronę gotowych dokumentów:

```python
from ksef_client import InvoiceXmlKey

scope = sync.xml.scopes[0]
for item in store.list_xml(sync.xml.scopes, limit=100):
    if item["status"] == "ready":
        key = InvoiceXmlKey(
            scope.namespace, scope.environment, scope.context_key, item["ksef_number"],
        )
        xml_bytes = storage.read(key, item["expected_hash"])
        print(item["ksef_number"], len(xml_bytes))
```

Dalsze strony pobieraj przez `after=ostatni_numer_z_poprzedniej_strony`.
Przy zwiększeniu limitu pobierania XML ustaw też odpowiedni `max_bytes` przy
odczycie cache. Parametr działa tak samo dla `storage.read(...)` i
`await storage.read(...)`. To odczyt lokalny, bez ponownego żądania do KSeF.

## Async

Użyj `AsyncKsef` oraz adapterów async. Poniższa funkcja przyjmuje już połączonego
klienta; uruchom ją wewnątrz jego kontekstu, zanim zamkniesz połączenie.

```python
from ksef_client import AsyncKsef, AsyncFileInvoiceXmlStore, AsyncSQLiteInvoiceSyncStore

async def synchronize(client: AsyncKsef):
    async with await AsyncFileInvoiceXmlStore.open("private/xml") as storage:
        async with await AsyncSQLiteInvoiceSyncStore.open(
            "private/invoices.db", enqueue_xml=True, xml_storage_id=storage.storage_id,
        ) as store:
            sync = client.invoices.sync_documents(
                namespace="firma", sync_key="erp", since="2024-01-01T00:00:00Z",
            )
            return await sync.run_once(store, storage, raise_on_error=False)
```

Adapter SQLite ma własne połączenie w jednym dedykowanym wątku. Operacje
plikowe również są wykonywane poza pętlą zdarzeń. Rozpoczęte zapisy są odbierane
do końca także po wielokrotnym anulowaniu. Wariant sync z `open()` jest
właścicielem połączenia; konstruktor przyjmujący `sqlite3.Connection` pozostawia
jego zamknięcie aplikacji. Połączenia muszą być bez aktywnej transakcji.
Jeżeli rollback zawiedzie, adapter zamyka niewiarygodne połączenie i zgłasza
błąd całego magazynu. Otwórz nowy adapter i odczytaj utrwalony stan; nie traktuj
tego przypadku jak zwykłej utraty dzierżawy ani nie powtarzaj zapisu w ciemno.

## Stany i współbieżność

Stany dokumentu: `pending`, `leased`, `retry_wait`, `blocked`, `ready`.
Tożsamość to namespace, środowisko, kontekst, numer KSeF i wariant XML v1;
rola, sync_key i generacja nie tworzą dodatkowych kopii pobrania.

Każdy proces używa własnego adaptera i połączenia, tego samego lokalnego pliku
bazy i katalogu XML. SQLite na sieciowym systemie plików nie jest wspierane.
Domyślna dzierżawa trwa 120 s, budżet dokumentu 60 s. Ustawienia workera
przekazuje się przez `xml_options` fabryki `sync_documents` albo bezpośrednio
do `xml_sync`:

```python
worker = client.invoices.xml_sync(
    metadata_sync, max_xml_bytes=16 * 1024 * 1024,
    lease_seconds=120, document_time_budget=60, max_failures=12,
)
```

Wygasłą dzierżawę można przejąć. Losowy token, rosnący fencing i epoka bazy
uniemożliwiają zatwierdzenie wyniku staremu właścicielowi. Dzierżawa musi
przekraczać budżet dokumentu o minimum 30 s. Budżety są kooperatywne:
nie przerywają rozpoczętego wywołania systemu plików ani COMMIT. Powtórzony
GET po awarii jest dopuszczalny; publikacja zweryfikowanego obiektu jest idempotentna.

KSeF 21165 i HTTP 429 planują ponowienie bez trwałego wyczerpania prób.
Pełne `Retry-After` jest dolną granicą terminu, także dla wielogodzinnych przerw.
Błędy sieci i 500/502/503/504 po 12 kolejnych nieudanych cyklach przechodzą
do `blocked`. Backoff zaczyna się od 5 s i rośnie do godziny, z jitterem ±20%.
Nieprzedstawialny liczbowo `Retry-After` blokuje dokument z kodem
`invalid_retry_after` — wymaga sprawdzenia odpowiedzi serwera lub proxy.
401 po refreshu zatrzymuje przebieg; 403, 21164, błędy integralności i limitu
rozmiaru blokują dokument. Brak miejsca lub awaria magazynu przerywają worker,
pozostawiając zadanie do przejęcia po wygaśnięciu dzierżawy.

## Integralność i przechowywanie

Limit 16 MiB jest limitem bezpieczeństwa klienta, a nie deklaracją limitu KSeF.
Jest konfigurowalny. Pamięć workera zależy od rozmiaru pojedynczego dokumentu,
nie od długości kolejki. Dane są weryfikowane względem metadanych i opcjonalnego
nagłówka `x-ms-meta-hash`. Nie są dekodowane ani ponownie serializowane.
`ready` nie oznacza walidacji XSD, poprawności podatkowej ani zaksięgowania.

Katalog ma trwały `storage_id`; niezgodność z bazą zatrzymuje pobieranie przed
HTTP. Obiekty mają niejawne deterministyczne nazwy. Plik tymczasowy jest
publikowany atomowo, bez nadpisywania istniejącej niezgodnej zawartości.
Po awarii między publikacją a COMMIT kolejny worker weryfikuje istniejący plik
i kończy zadanie bez HTTP. Potwierdzanie publikacji po restarcie procesu jest
gwarantowane; odporność na awarię zasilania zależy także od systemu plików i sprzętu.

Chronić cały katalog przed niezaufanymi zapisującymi procesami. Zabezpieczenia
ścieżek nie zastępują uprawnień systemowych. Na Windows adapter utrzymuje uchwyty
katalogów do zamknięcia, aby blokować ich podmianę. Trzeba zamykać magazyn kontekstem.

Protokoły `InvoiceXmlStorage` / `AsyncInvoiceXmlStorage` oraz
`InvoiceDocumentStore` / `AsyncInvoiceDocumentStore` pozwalają dostarczyć własne
backendy. `put_verified` musi zwrócić `InvoiceXmlReceipt` dopiero po trwałej,
idempotentnej publikacji. `finish_xml` wymaga ważnej dzierżawy i receiptu;
własny adapter ma egzekwować te same gwarancje transakcyjne i fencing.

## Historia, migracja i odzyskiwanie

Dla metadanych zapisanych przed włączeniem kolejki wywołać:

```python
progress = store.backfill_xml(sync.xml.scopes, batch_size=500, time_budget=60)
```

Checkpoint backfillu jest trwały. Powtarzać do `progress.complete`.
Operacja nie cofa HWM metadanych ani nie resetuje istniejących stanów XML.
Nowe strumienie zapisujące zadania atomowo mają historię kolejki kompletną od początku.

Migracja starego przykładu jest jawna. Zatrzymać starych zapisujących workerów,
wykonać backup i na bezczynnym połączeniu wywołać
`SQLiteInvoiceSyncStore.migrate_legacy_example(connection, xml_storage_id=...)`.
Adapter rozpoznaje pełny znany schemat, nie tylko nazwy tabel. Zachowuje stary
outbox. Następnie otworzyć publiczny adapter i przeprowadzić backfill wybranych
strumieni; import zadań ma checkpoint i nie oznacza dokumentów jako `ready`.

Przed odtworzeniem backupu zatrzymaj wszystkie procesy korzystające z bazy
i katalogu XML. Po odtworzeniu, przed uruchomieniem workerów, wywołaj
`store.fence_workers()` i przejdź stronicowane `verify_ready(scopes, storage, after=..., limit=100)`.
Backup powinien obejmować bazę i dokumenty; pliki WAL/SHM również są poufne.
Brakujący XML wraca do `pending`, uszkodzony do `blocked`. Pliki nie są
automatycznie kasowane. Po usunięciu przyczyny blokady:
`store.retry_blocked(scopes, reason="opis decyzji operatora", limit=100)`.
Powód operatora jest walidowany, ale jego tekst nie jest kopiowany do diagnostyki.

`storage.cleanup_staging()` usuwa ograniczoną liczbę starych plików tymczasowych,
domyślnie starszych niż doba. Wykonuj tę operację w oknie serwisowym, po
zatrzymaniu publikujących workerów. Nie usuwa opublikowanych dokumentów.
Po zamknięciu magazynu operacje na nim są odrzucane; zamknięcie czeka na
trwające operacje tej samej instancji.

## Raport

`report.metadata_complete`, `report.xml_ready_for_observed` i `report.complete`
opisują różne gwarancje. Całość jest ukończona tylko przy ukończonym cyklu
metadanych, gotowych XML i ukończonym backfillu.

Liczniki obejmują unikalne dokumenty wybranych strumieni: `observed`,
`not_enqueued`, `pending`, `leased`, `retry_wait`, `blocked`, `ready`.
Raport pokazuje też pobrania, odzyskane pliki, bajty, przejęcia, błędy i najbliższy
termin ponowienia. `list_xml(scopes, after=..., limit=100)` zwraca szczegóły
w ograniczonych stronach; zawierają prywatne identyfikatory dokumentów.

Checkpoint (punkt wznowienia) i zadanie pobrania są zapisywane w tej samej
transakcji. Plik otrzymuje stan `ready` dopiero po sprawdzeniu SHA-256, publikacji
i zapisaniu potwierdzenia w bazie.

Checkpointy i liczniki są odczytywane w jednej transakcji. Jeżeli między fazami
inny koordynator zmieni checkpoint, `metadata_changed=True` uniemożliwia
przedstawienie nieaktualnego wyniku jako kompletnego.
Gotowość oznacza ostatnią potwierdzoną publikację: zewnętrzne usunięcie pliku
wykrywa odczyt z weryfikacją lub `verify_ready`, nie sam licznik bazy.


## Diagnostyka i kontrakty adapterów

`report.xml.reason_counts` to ograniczona liczba par `(kod, liczba dokumentów)`
z ostatnimi znanymi przyczynami, np. `(("forbidden", 2),)`. Raport nie kopiuje
odpowiedzi serwera. Przyczyny konkretnych dokumentów znajdziesz w paginowanym
`store.list_xml(sync.xml.scopes, limit=100)`: pola `ksef_number`, `status`,
`last_reason`, `attempts`, `failures`, `next_attempt_at`. Następną stronę pobierz
przez `after=ostatni_ksef_number`. `last_reason` jest ostatnim stanem diagnostyki,
nie historią zdarzeń. `retry_blocked(..., reason="permissions_fixed")` wymaga
najpierw usunięcia przyczyny błędu. Nie resetuj blokad w pętli.

Wadliwy numer KSeF ma kod `invalid_ksef_number`. Nieczytelny pojedynczy obiekt
ma `stored_object_unreadable`, a plik specjalny/dowiązanie `unsafe_storage_file`.
Te dokumenty przechodzą do `blocked`; worker obsługuje pozostałe zadania.
Błędy I/O całego dysku, brak miejsca i awarie SQLite nadal przerywają wywołanie,
także przy `raise_on_error=False`. Ten parametr kontroluje błędy dokumentów,
a nie dostępność infrastruktury.

HTTP 408/409/425 i 500/502/503/504/507/520/522/524 są ponawiane z limitem
`max_failures`. 403, 21164 i pozostałe trwałe błędy żądania blokują dokument.
`Retry-After` jest zachowywany także dla 21165 i przejściowych błędów HTTP,
a nie tylko 429. Kod `invalid_retry_after` dotyczy terminu przekraczającego
zakres reprezentacji czasu; zwykły niepoprawny tekst nagłówka podlega parserowi
transportu i nie oznacza automatycznie tej blokady.

`stop_reason` przyjmuje `time_budget`, `work_limit`, `lease_lost`,
`authentication` albo `None`. Utrata dzierżawy kończy bieżący worker. `None`
może oznaczać brak zadań gotowych teraz: sprawdź `pending`, `leased`,
`retry_wait` i `next_attempt_at`, zanim zaplanujesz kolejny cykl.
Czasy diagnostyczne `observed_at` są ISO-8601 UTC; `next_attempt_at` to sekundy
Unix (float), nadające się do porównania z `time.time()`.

Własny `describe_xml` musi zwrócić w jednej migawce również wymagane pole
`checkpoints`: po jednej pozycji na scope, w kolejności argumentu `scopes`.
`None` oznacza brak checkpointu tego strumienia. Worker sprawdza kontrakt przed
pierwszym claimem. Nie wolno zastąpić migawki niezależnymi odczytami checkpointów.
`InvoiceXmlKey.environment` jest fingerprintem środowiska z
`sync.xml.scopes[0].environment`, nie napisem `"TEST"`. Klucze normalizują poprawne
numery KSeF z dodatkowym myślnikiem do postaci 35-znakowej; publiczny adapter
robi to także przy zapisie obserwacji.

## Aktualizacja istniejącej bazy

Nowy publiczny adapter **nie aktualizuje istniejącego schematu przy otwieraniu**.
Zatrzymaj wszystkie procesy zapisujące, wykonaj backup i otwórz osobne bezczynne
połączenie. Dla schematu dawnego przykładu metadanych:

```python
import sqlite3
from contextlib import closing
from ksef_client import SQLiteInvoiceSyncStore

with closing(sqlite3.connect("private/invoices.db", timeout=5)) as connection:
    SQLiteInvoiceSyncStore.migrate_legacy_example(connection)
```

Ta migracja nie wymaga katalogu XML. Późniejsze otwarcie z `enqueue_xml=True`
i `xml_storage_id=storage.storage_id` wiąże bazę z archiwum; wykonaj potem
backfill. Możesz też podać właściwy identyfikator od razu podczas migracji.
Dodatkowe tabele aplikacji są zachowywane (poza zastrzeżonymi nazwami XML),
ale tabele adaptera muszą mieć pełny
rozpoznany schemat. Połączenie obsługuje domyślne wiersze tuple lub `sqlite3.Row`;
własne fabryki słownikowe wymagają osobnego połączenia dla aplikacji.

Bazy XML utworzone wcześniejszym kodem tej gałęzi mają wersję 1. Przed otwarciem
aktualnym adapterem wykonaj offline `SQLiteInvoiceSyncStore.migrate_schema(connection)`.
Wersja 2 dodaje indeksowane sondy wyboru zadań zamiast materializowania całej
historii obserwacji przy każdym claimie. Obie migracje scalają poprawne alternatywne postacie numeru KSeF;
konflikt hashy wycofuje transakcję. Obiekt opublikowany pod dawną tożsamością
nie jest usuwany ani automatycznie uznawany za nowy plik gotowy — pozostaje
obowiązek pobrania i weryfikacji. Nie stosuj zastępczego `storage_id`.
Zmiana powiązania na dowolny inny katalog nie jest wspierana: przeniesienie
archiwum wymaga zachowania jego `.storage-id` i sprawdzenia plików po restore.

## Warunki operacyjne

`max_xml_bytes` ogranicza także dokument odzyskiwany z istniejącego obiektu.
Obniżenie limitu może dać `response_size_limit` i `blocked`, choć bajty mają
poprawny hash. Po zwiększeniu limitu ponowienie jest jawne. `inspect` haszuje
strumieniowo, w stałej pamięci, sprawdzając deadline między fragmentami;
nie przerywa już rozpoczętego wywołania systemowego odczytu.

`cleanup_staging(max_entries=...)` ogranicza liczbę kandydatów `.tmp-*`, nie
liczbę opublikowanych XML pominiętych podczas skanu. Katalog może wymagać pełnego
przejścia; sprzątanie wykonuj w oknie serwisowym z zatrzymanymi publikującymi
workerami. Gotowe dokumenty nie są automatycznie usuwane ani szyfrowane.
Polityka retencji danych, backupów i ewentualne VACUUM należą do aplikacji.

Zegar systemowy hosta musi być poprawnie synchronizowany. Trwałe terminy
kolejki używają czasu Unix, budżety czasu — zegara monotonicznego. Ręczna zmiana
czasu/restore VM może opóźnić przejęcie wygasłych zadań; po zatrzymaniu starych
workerów i korekcie czasu użyj kontrolowanego odzyskiwania. Sam report nie
wykonuje audytu wszystkich plików, zgodnie z opisem `verify_ready`.

Magazyn wymaga lokalnego systemu plików obsługującego bezpieczną publikację
(hardlinki i fsync na POSIX, uchwyty i rename bez nadpisywania na Windows).
FAT, udział sieciowy, OneDrive i katalogi z junction/reparse points nie są
obsługiwanym sposobem współdzielenia archiwum. `.storage-id` jest plikiem
wewnętrznym: nie edytuj go ani nie zmieniaj zakończeń linii. Na Windows uchwyty
obejmują także przodków katalogu, aby uniemożliwić podmianę ścieżki. Zamykaj
storage blokiem `with`; finalizer zwalnia porzucone uchwyty tylko pomocniczo.
