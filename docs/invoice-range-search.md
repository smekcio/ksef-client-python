# Pobieranie historii faktur z jednym checkpointem

`search_invoice_metadata_range()` przyjmuje okres obejmujący wiele lat i dzieli
go na okna po maksymalnie 100 dni kalendarzowych UTC. Każde okno korzysta z pełnej
paginacji, obsługi obcięcia wyników i deduplikacji granic. Dostępne są kierunki
`Asc` i `Desc` oraz typy dat `PermanentStorage`, `Invoicing` i `Issue`.

```python
from ksef_client import models as m

filters = m.InvoiceQueryFilters(
    subject_type=m.InvoiceQuerySubjectType.SUBJECT1,
    date_range=m.InvoiceQueryDateRange(
        date_type=m.InvoiceQueryDateType.PERMANENTSTORAGE,
        from_="2024-01-01T00:00:00Z",
        to="2026-01-01T00:00:00Z",
        restrict_to_permanent_storage_hwm_date=True,
    ),
)
search = client.invoices.search_invoice_metadata_range(
    filters, context_key="Nip:5265877635", window_days=100, page_size=100,
)
page = search.page(cursor=saved_cursor)  # None przy pierwszym uruchomieniu
```

Obiekt jest leniwy. `page()` wykonuje jedno zapytanie metadanych, `pages()`
iteruje po stronach wszystkich okien, a `items()` i zwykła iteracja zwracają
faktury. Po pustej stronie może istnieć kolejny kursor, także do następnego okna.
`window_days` musi być liczbą całkowitą od 1 do 100. Zakres bez daty końcowej
otrzymuje ją raz przy pierwszym odczycie; wznowienie zachowuje zapisaną granicę.

## Zapis i wznowienie

W jednej transakcji utrwal `page.items` oraz `page.next_cursor`. Kursor obejmuje
cały przebieg: zamrożoną datę końcową, numer okna, stan jego paginacji, HWM
i identyfikatory z granicy deduplikacji. Aplikacja dostarcza magazyn danych;
SDK nie otwiera własnej bazy ani nie uruchamia harmonogramu synchronizacji.

Po restarcie ponownie utwórz klienta i wyszukiwanie z tymi samymi filtrami,
kontekstem, środowiskiem, kierunkiem, rozmiarem strony i długością okna.
Przekaż zapisany kursor do `page()`, `pages()` lub `items()`. `next_cursor=None`
oznacza koniec; osobny znacznik ukończenia odróżnia go od pierwszego uruchomienia.
Przykład [SQLite](examples/invoice_checkpoint_sqlite.py) obsługuje wieloletnie zakresy.

Kursor ma osobny format `invoice-metadata-range`, wersja 1. Jest JSON-em w
Base64URL, ma limit 2 MiB i jest walidowany przed HTTP. Nie jest szyfrowany ani
uwierzytelniony: zawiera prywatne filtry i identyfikatory, nie zapisuj go w logach
i nie traktuj go jako zaufanego wejścia użytkownika. Nie zawiera tokenów ani kluczy.
Kursor pojedynczego zapytania i kursor zakresu nie są zamienne.

## Kompletność i HWM

Do stabilnego odczytu stosuj `PermanentStorage` i
`restrict_to_permanent_storage_hwm_date=True`. Dopiero ukończenie całego
przebiegu potwierdza kompletność do zwróconego `page.permanent_storage_hwm_date`.
W `Asc` HWM może rosnąć przy kolejnych oknach; w `Desc` zachowana jest początkowa
górna granica. Jeśli serwer ograniczy okno `Asc` do wcześniejszego HWM, SDK kończy
na potwierdzonej granicy i nie przeskakuje do kolejnego zaplanowanego zakresu.
W `Desc` kontynuuje odczyt starszych okien.

Granice okien są inkluzywne. Nakładające się faktury są deduplikowane po numerze
KSeF, także przy pustej końcowej stronie okna. Daty `Issue` mają precyzję dnia;
znaczniki czasu zachowują precyzję API również poniżej mikrosekundy.
`Issue`, `Invoicing` oraz brak ograniczenia HWM nie zapewniają migawki danych.

`KsefIncompletePaginationError.last_cursor` odtwarza stronę całego zakresu, przy
której nie udało się potwierdzić kompletności. Nie zapisuj takiego przebiegu jako
ukończonego. Przekroczenie rozmiaru kolejnego kursora również zachowuje punkt
powtórzenia. SDK nie uruchamia eksportu automatycznie.

## Async

```python
search = async_client.invoices.search_invoice_metadata_range(
    filters, context_key="Nip:5265877635", window_days=100,
)
async for page in search.pages(cursor=saved_cursor):
    await application_store.commit_page(page.items, page.next_cursor)
```

Zasady transakcji i checkpointów są takie same. Skutki uboczne w zewnętrznych
systemach wymagają idempotencji po stronie aplikacji.

Przykład SQLite przechowuje ukończony przebieg ustalonego zakresu; nie planuje
kolejnej synchronizacji na podstawie HWM. Używaj osobnej bazy dla każdego
środowiska KSeF, ponieważ kluczem faktury w tym przykładzie jest numer KSeF.
