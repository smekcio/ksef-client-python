# Synchronizacja metadanych i XML

`InvoiceDocumentSync` łączy istniejący `InvoiceSync` z trwałą kolejką pobrań XML.
Checkpoint i zadanie są zapisywane razem. XML staje się `ready` dopiero po
weryfikacji SHA-256, trwałej publikacji pliku i zatwierdzeniu receiptu w bazie.
HWM potwierdza metadane i utworzenie zadań, niezależnie od dostępności XML.

## Pierwszy przebieg

```python
from ksef_client import FileInvoiceXmlStore, SQLiteInvoiceSyncStore

# client: uwierzytelniony Ksef; te same fabryki udostępnia client.api.invoices.
with FileInvoiceXmlStore("./private/xml") as storage:
    with SQLiteInvoiceSyncStore.open(
        "./private/invoices.db", enqueue_xml=True, xml_storage_id=storage.storage_id,
    ) as store:
        sync = client.invoices.sync_documents(
            namespace="firma", sync_key="erp", since="2024-01-01T00:00:00Z",
        )
        report = sync.run_once(store, storage, time_budget=600, raise_on_error=False)
        print(report.to_dict())
```

`metadata_time_budget=300` ogranicza fazę metadanych. XML wykorzystuje pozostały
czas całego przebiegu. Domyślnie worker przejmuje najwyżej 100 dokumentów,
pojedynczo. Harmonogram kolejnych uruchomień zapewnia aplikacja, także po sukcesie.
`raise_on_error=False` zwraca oczekiwane błędy dokumentów w raporcie; awarie
magazynu, błędy programistyczne, nadrzędny deadline i anulowanie nadal przerywają
wywołanie. `KsefXmlRunError.report` zawiera raport przy domyślnym trybie wyjątków.

Osobne wywołania to `sync.metadata.run_once(store)` i
`sync.xml.run_once(store, storage)`. Dla istniejącego `InvoiceSync`:
`worker = client.invoices.xml_sync(metadata_sync)`. Kontekst, środowisko i wybór
strumieni pozostają związane z metadanymi. Worker nie pobiera innych zadań bazy.

Retry HTTP pozostaje ustawieniem klienta; dla zapytań metadanych wymaga jawnego
dodania `/invoices/query/metadata` do allowlisty POST. Kolejka nie modyfikuje
konfiguracji transportu. Każda próba GET korzysta z istniejącego refreshu tokena,
budżetu grupy `invoiceDownload` i ograniczonego odbioru odpowiedzi.

## Async

```python
from ksef_client import AsyncFileInvoiceXmlStore, AsyncSQLiteInvoiceSyncStore

async with await AsyncFileInvoiceXmlStore.open("./private/xml") as storage:
    async with await AsyncSQLiteInvoiceSyncStore.open(
        "./private/invoices.db", enqueue_xml=True, xml_storage_id=storage.storage_id,
    ) as store:
        sync = client.invoices.sync_documents(
            namespace="firma", sync_key="erp", since="2024-01-01T00:00:00Z",
        )  # client: AsyncKsef
        report = await sync.run_once(store, storage, raise_on_error=False)
```

Adapter SQLite ma własne połączenie w jednym dedykowanym wątku. Operacje
plikowe również są wykonywane poza pętlą zdarzeń. Rozpoczęte zapisy są odbierane
do końca także po wielokrotnym anulowaniu. Wariant sync z `open()` jest
właścicielem połączenia; konstruktor przyjmujący `sqlite3.Connection` pozostawia
jego zamknięcie aplikacji. Połączenia muszą być bez aktywnej transakcji.

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
progress = store.backfill_xml(worker.scopes, batch_size=500, time_budget=60)
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

Po odtworzeniu backupu zatrzymać stare procesy, wywołać `store.fence_workers()`
i przejść stronicowane `verify_ready(scopes, storage, after=..., limit=100)`.
Backup powinien obejmować bazę i dokumenty; pliki WAL/SHM również są poufne.
Brakujący XML wraca do `pending`, uszkodzony do `blocked`. Pliki nie są
automatycznie kasowane. Po usunięciu przyczyny blokady:
`store.retry_blocked(scopes, reason="opis decyzji operatora", limit=100)`.
Powód operatora jest walidowany, ale jego tekst nie jest kopiowany do diagnostyki.

`storage.cleanup_staging()` usuwa ograniczoną liczbę starych plików tymczasowych,
domyślnie starszych niż doba. Nie usuwa opublikowanych dokumentów.

## Raport

`report.metadata_complete`, `report.xml_ready_for_observed` i `report.complete`
opisują różne gwarancje. Całość jest ukończona tylko przy ukończonym cyklu
metadanych, gotowych XML i ukończonym backfillu.

Liczniki obejmują unikalne dokumenty wybranych strumieni: `observed`,
`not_enqueued`, `pending`, `leased`, `retry_wait`, `blocked`, `ready`.
Raport pokazuje też pobrania, odzyskane pliki, bajty, przejęcia, błędy i najbliższy
termin ponowienia. `list_xml(scopes, after=..., limit=100)` zwraca szczegóły
w ograniczonych stronach; zawierają prywatne identyfikatory dokumentów.

Checkpointy i liczniki są odczytywane w jednej transakcji. Jeżeli między fazami
inny koordynator zmieni checkpoint, `metadata_changed=True` uniemożliwia
przedstawienie nieaktualnego wyniku jako kompletnego.
Gotowość oznacza ostatnią potwierdzoną publikację: zewnętrzne usunięcie pliku
wykrywa odczyt z weryfikacją lub `verify_ready`, nie sam licznik bazy.
