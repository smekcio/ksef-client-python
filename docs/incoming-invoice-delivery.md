# Dostarczanie faktur zakupowych ze zweryfikowanego archiwum

`SQLiteInvoiceSyncStore` i `AsyncSQLiteInvoiceSyncStore` dostarczają dokumenty
do skryptu lub aplikacji w kolejnych próbach. Użyj tej samej bazy SQLite oraz
tego samego magazynu XML, które obsługują archiwum. Wybierz zakres `Subject2`
z synchronizacji dokumentów lub eksportu. Można pobierać także dokumenty
z istniejącego archiwum.

```python
# archive_scope to sync.xml.scopes[0] dla synchronizacji Subject2 albo
# sync.scope dla archiwum eksportowego Subject2.
delivery = store.claim_invoice_delivery(
    archive_scope, storage, consumer="purchase-import", lease_seconds=300,
)
if delivery is not None:
    try:
        save_once(delivery.event_id, delivery.metadata, delivery.xml)
    except RecoverableImportError:
        store.retry_invoice_delivery(delivery, delay_seconds=30)
    else:
        store.acknowledge_invoice_delivery(delivery)
```

`save_once` oznacza operację aplikacji, która w jednej transakcji zapisuje
dokument i unikatowy `event_id`. Zwraca sukces także dla już zapisanego ID.
Jeśli aplikacja zakończy pracę po swoim zapisie, a przed potwierdzeniem w SDK,
następna próba przyniesie ten sam identyfikator. Aplikacja może potwierdzić ją
bez ponownego zapisu dokumentu.

Nazwę odbiorcy utrzymuj między uruchomieniami. Wiele workerów o tej samej nazwie
dzieli stan dostarczenia. Różne nazwy odbiorców mają osobne potwierdzenia.
W ramach tej samej przestrzeni nazw, środowiska i kontekstu dokument widziany
kilka razy, także przez synchronizację metadanych i eksport paczek, zachowuje
to samo ID. Każde potwierdzenie dotyczy konkretnej próby. Gdy próba wygaśnie,
kolejny worker może podjąć dokument, a spóźnione potwierdzenie zgłosi
`KsefInvoiceDeliveryLeaseLostError` z `ksef_client.invoice_delivery`.
Wybierz czas rezerwacji większy od typowego czasu przetwarzania dokumentu.
Odbiornik nadal potrzebuje deduplikacji przy przekroczeniu tego czasu.

Odczyt porównuje skrót oryginalnego XML z archiwum przed zwróceniem zdarzenia
i sprawdza typy pól zapisanych metadanych. Synchronizacja i import paczki
sprawdzają te same typy przed zapisem. Jeśli poprzednia wersja SDK zapisała
wartość po konwersji typu, ustalenie wartości źródłowej wymaga ponownego
odczytu z KSeF. Błąd
weryfikacji lub odczytu nie dostarcza dokumentu. Rezerwacja wygasa samodzielnie,
a ponowna próba ustępuje starszym dostępnym dokumentom. Przy brakujących plikach
uruchom `verify_ready`, aby kolejne pobranie XML mogło je uzupełnić.
Uszkodzoną zawartość możesz odzyskać z kopii spójnej z bazą.
`None` oznacza brak dostępnej faktury w tej chwili. Wersja async używa tych
samych nazw z `await`. Worker odbiorcy może działać bez logowania do KSeF.

Baza zawiera stan prób i potwierdzeń. Archiwum odtwarzaj razem z magazynem
XML i zatrzymaj workery przed przywracaniem kopii. Po odzyskaniu bazy istniejące
`fence_workers()` wycofuje rezerwacje pochodzące ze starego stanu.
Identyfikator dostarczenia służy do deduplikacji. Dokumenty i metadane chroń jak
pozostałą zawartość archiwum.
