# Niezawodne pobieranie metadanych i wznowienie po restarcie

Nowe `search_invoice_metadata()` jest zalecaną ścieżką pobierania kompletnego
zbioru metadanych. Dotychczasowe `iter_invoice_metadata*` zachowują swój kontrakt:
kończą się ostrzeżeniem po obcięciu wyników i nie obsługują trwałych kursorów.

```python
search = client.invoices.search_invoice_metadata(
    filters, context_key="Nip:5265877635", page_size=100, sort_order="Asc",
)
page = search.page()                # pierwsze HTTP następuje tutaj
save_items_and_cursor_atomically(page.items, page.next_cursor)

# W nowym procesie: klient i wyszukiwanie z tym samym kontekstem i filtrami.
page = search.page(cursor=saved_cursor)

for page in search.pages():
    process(page.items)
for invoice in search:
    process(invoice)
```

`pages(cursor=...)` oraz `items(cursor=...)` wznawiają kolekcję. Każda nowa
iteracja bez kursora zaczyna się od pierwszej strony. Wersja async:

```python
search = async_client.invoices.search_invoice_metadata(filters, context_key="Nip:5265877635")
page = await search.page(saved_cursor)
async for page in search.pages(cursor=saved_cursor):
    await save_items_and_cursor_atomically(page.items, page.next_cursor)
async for invoice in search:
    await process(invoice)
```

## Kompletność i ograniczenia

Kursor wskazuje następne żądanie. `next_cursor=None` oznacza potwierdzony koniec;
nie zapisuj go jako ukończenia, zanim nie utrwalisz elementów strony. Strona może
być pusta po deduplikacji i nadal mieć następny kursor.

SDK kontynuuje po `isTruncated` od ostatniej daty, z granicą inkluzywną i offsetem
zero. Duplikaty na nakładającej się granicy usuwa po numerze KSeF. Nie przesuwa daty
o mikrosekundę. Przechowuje identyfikatory aktualnej granicy, a nie całego zbioru.
Zakres pojedynczego wyszukiwania nadal wynosi maksymalnie 100 dni UTC. Domyślny
rozmiar strony to 100, dopuszczalne 10–250; kierunki: `Asc` i `Desc`.

Dla stabilnego zbioru używaj `PermanentStorage`, `Asc` i
`restrict_to_permanent_storage_hwm_date=True`. SDK zachowuje pierwszy zwrócony HWM
i ogranicza dalsze żądania do tej granicy. Wynik potwierdza kompletność do HWM,
który może być wcześniejszy od żądanej daty końcowej; HWM jest dostępny jako
`page.permanent_storage_hwm_date`, także na ostatniej stronie.
Zakończony przebieg nie oznacza, że KSeF zakończył przetwarzanie nowszych dokumentów.
`Issue`, `Invoicing` i zapytania bez ograniczenia HWM dotyczą zmieniającego się
zbioru: paginacja nie tworzy migawki serwera i nie gwarantuje stabilnych offsetów.

`KsefIncompletePaginationError` oznacza, że SDK nie może potwierdzić kompletności.
`reason_code` podaje bezpieczną przyczynę; `last_cursor` odtwarza problematyczne
żądanie. Nie zapisuj takiego przebiegu jako ukończonego. Powody obejmują brak numeru
KSeF lub daty, niespójne sortowanie/HWM, trzy puste lub powtarzające się strony,
limit bez obcięcia i obcięcie, które nie przesunęło granicy. Jeżeli ponad limit
rekordów ma tę samą datę, zawężenie po dacie może nie wystarczyć: trzeba zmienić
filtry lub osobno użyć eksportu. SDK nie uruchamia eksportu automatycznie.

## Prywatność i trwałość kursora

Kursor v1 to JSON w Base64URL, bez szyfrowania i podpisu. Zawiera filtry, kontekst,
środowisko, efektywne granice, HWM i stan deduplikacji. Nie zawiera tokenów ani
kluczy. Nie umieszczaj go w logach, URL-ach ani niezaufanym wejściu użytkownika.
Limit wynosi 2 MiB zakodowanego tekstu. Walidacja odbywa się przed HTTP i odrzuca
niezgodność wersji, struktury, środowiska, filtrów, kontekstu, rozmiaru strony
lub sortowania przez `KsefInvalidPaginationCursorError`.

`context_key` jest deklaracją aplikacji, a nie uwierzytelnieniem: aplikacja musi
powiązać go z właściwym kontem i tokenem. Nie modyfikuj kursora. Kolejne wydania SDK
muszą czytać v1 lub udostępnić udokumentowaną migrację.

## Transakcyjny checkpoint

[Przykład SQLite](examples/invoice_checkpoint_sqlite.py) zapisuje faktury i następny
kursor w jednej transakcji. Klucz unikalny obejmuje identyfikator przebiegu i numer
KSeF. Osobne `completed` odróżnia koniec od braku checkpointu. Jeden worker obsługuje
jeden przebieg. Baza zawiera prywatne dane faktur; przechowuj ją z odpowiednią ochroną.

Po awarii przed commit strona jest przetwarzana ponownie; po commit następuje
kontynuacja od kolejnej strony. To idempotentny zapis w bazie, a nie gwarancja
„exactly once” dla e-maili, webhooków i innych efektów poza tą transakcją.

## Diagnostyka i sekrety

`repr()` modeli ukrywa tokeny, podpisane URL-e, poufne nagłówki i payloady.
`ksef_client.redact_sensitive(value)` przygotowuje zredagowane struktury do
jawnego logowania. Nie wywołuje `repr()` nieznanych obiektów i ogranicza głębokość.
Nie wykrywa dowolnych sekretów w swobodnym tekście i nie jest formatem zapisu stanu.

`to_dict()`/`to_json()` zachowują format transportowy oraz dane potrzebne do
wznowienia, w tym sekrety. Nie należy ich logować. Zmiana diagnostyki nie zmienia
kontraktu serializacji dotychczasowych integracji.
