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
Nakładanie może obejmować wiele stron: rosnący offset i różne zestawy identyfikatorów
nie oznaczają braku postępu. `hasMore=false` kończy odczyt zgodnie z kontraktem MF,
także przy `isTruncated=true`. Samo osiągnięcie limitu nie dowodzi istnienia dalszych danych.
Zakres pojedynczego wyszukiwania nadal wynosi maksymalnie 100 dni UTC. Domyślny
rozmiar strony to 100, dopuszczalne 10–250; kierunki: `Asc` i `Desc`.

Dla stabilnego zbioru używaj `PermanentStorage`, `Asc` i
`restrict_to_permanent_storage_hwm_date=True`. SDK zachowuje pierwszy zwrócony HWM
i ogranicza dalsze żądania do tej granicy. Wynik potwierdza kompletność do HWM,
który może być wcześniejszy od żądanej daty końcowej; HWM jest dostępny jako
`page.permanent_storage_hwm_date`, także na ostatniej stronie.
Zakończony przebieg nie oznacza, że KSeF zakończył przetwarzanie nowszych dokumentów.
Brak poprawnego HWM, również na pustej stronie, powoduje jawny błąd niekompletności
w trybie wymagającym HWM. SDK nie potwierdza wtedy stabilności nieznanej granicy.
W kierunku `Desc` HWM kolejnego zawężonego zapytania może odpowiadać jego niższej
granicy `to`; początkowa granica kompletności pozostaje w stanie kursora.
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
skrót środowiska, efektywne granice, HWM i stan deduplikacji. Odczyt starszego
kursora v1 z jawnym URL-em środowiska pozostaje obsługiwany; następny kursor
przechowuje już SHA-256 URL-a zamiast potencjalnych poświadczeń w jego treści. Nie zawiera tokenów ani
kluczy. Nie umieszczaj go w logach, URL-ach ani niezaufanym wejściu użytkownika.
Limit wynosi 2 MiB zakodowanego tekstu. Walidacja odbywa się przed HTTP i odrzuca
niezgodność wersji, struktury, środowiska, filtrów, kontekstu, rozmiaru strony
lub sortowania przez `KsefInvalidPaginationCursorError`.

`context_key` jest deklaracją aplikacji, a nie uwierzytelnieniem: aplikacja musi
powiązać go z właściwym kontem i tokenem. Nie modyfikuj kursora. Kolejne wydania SDK
muszą czytać v1 lub udostępnić udokumentowaną migrację.

## Transakcyjny checkpoint

[Przykład SQLite](examples/invoice_checkpoint_sqlite.py) zapisuje faktury i następny
kursor w jednej transakcji. Klucz unikalny faktury to numer
KSeF; checkpoint jest przypisany do identyfikatora przebiegu. Osobne `completed` odróżnia koniec od braku checkpointu. Jeden worker obsługuje
jeden przebieg. Baza zawiera prywatne dane faktur; przechowuj ją z odpowiednią ochroną.

Po awarii przed commit strona jest przetwarzana ponownie; po commit następuje
kontynuacja od kolejnej strony. To idempotentny zapis w bazie, a nie gwarancja
„exactly once” dla e-maili, webhooków i innych efektów poza tą transakcją.

## Diagnostyka i sekrety

`repr()` modeli ukrywa tokeny, podpisane URL-e, poufne nagłówki i payloady.
`ksef_client.redact_sensitive(value)` przygotowuje zredagowane struktury do
jawnego logowania. Nie wywołuje `repr()` nieznanych obiektów i ogranicza głębokość, szerokość, liczbę węzłów
oraz długość tekstu. Podklasy typów prostych nie są przekazywane do formatterów.
Nie wykrywa dowolnych sekretów w swobodnym tekście i nie jest formatem zapisu stanu.

`to_dict()`/`to_json()` zachowują format transportowy oraz dane potrzebne do
wznowienia, w tym sekrety. Nie należy ich logować. Zmiana diagnostyki nie zmienia
kontraktu serializacji dotychczasowych integracji.

## Publikacja potwierdzona rzeczywistym TEST

Workflow publikacji przyjmuje wyłącznie istniejący tag wersji zgodny z
`pyproject.toml`. Buduje wheel i sdist, zapisuje commit oraz sumy SHA-256 w
`release-manifest.json`, a następnie instaluje dokładnie ten wheel w bramie E2E.
PyPI otrzymuje te same pliki po ponownej kontroli sum; manifest nie jest wysyłany
jako dystrybucja. Ręczne uruchomienie wymaga podania taga i przechodzi te same kontrole.

Po utworzeniu wydania Release Please automatycznie uruchamia publikację przez
`workflow_dispatch` z gałęzi `main`, przekazując tag nowego wydania. Publikację można
też uruchomić ręcznie z tym samym tagiem. Tag musi wskazywać commit należący do historii `main`.
Narzędzia weryfikujące, manifest i testy pochodzą z commita zaufanego workflow,
a nie z wydawanego taga. Kod budowania działa w osobnym jobie bez sekretów TEST.
Job posiadający OIDC pobiera tylko zweryfikowane artefakty i uruchamia przypiętą
akcję publikacji, bez checkoutu i wykonywania kodu repozytorium.

Przed użyciem administrator musi skonfigurować środowiska `ksef-test`, `ksef-demo`
i `pypi` z regułami dopuszczającymi wyłącznie gałąź `main`, a także ochronę samego
`main` i tagów wersji. Sekrety KSeF należy przenieść do odpowiedniego środowiska
TEST/DEMO i usunąć ich kopie z poziomu repozytorium. Konfiguracja Trusted Publisher
w PyPI musi wskazywać środowisko `pypi`. Bez tych ustawień zmiana YAML nie stanowi
pełnej granicy bezpieczeństwa przed osobą mogącą zmieniać workflow na własnej gałęzi.
PR-y nie uruchamiają scenariuszy z sekretami; wymagany TEST nadal blokuje publikację.

Zależności runnerów Linux/Python 3.12 są przypięte wraz z hashami w
`requirements-ci.lock`; instalacja używa `--require-hashes`, a budowanie wyłącza
izolowaną instalację dodatkowych narzędzi. Aktualizacja lockfile:
`uv pip compile requirements-ci.in --python-version 3.12 --python-platform x86_64-manylinux_2_28 --generate-hashes --output-file requirements-ci.lock`.
Kontrola wheela przed instalacją odrzuca pliki `.pth`, nieoczekiwane pliki poza SDK,
symlinki i rozbieżności nazw dystrybucji z METADATA. Nie jest to skaner złośliwego kodu.

Manifest obowiązkowych scenariuszy znajduje się w `tests/required_test_e2e.json`.
TEST wymaga pełnego przepływu token/XAdES, wznowienia online/batch i kontynuacji
paginacji w nowym procesie. Każdy scenariusz jest wykonywany raz. Brak raportu,
brak testu, pominięcie, xfail lub błąd blokują publikację. Awaria TEST lub brak
sekretów także blokują publikację; DEMO nie zastępuje tej kontroli.

Wymagane sekrety GitHub: `KSEF_TEST_TOKEN`, `KSEF_TEST_CONTEXT_TYPE`,
`KSEF_TEST_CONTEXT_VALUE`, certyfikat i klucz XAdES jako
`KSEF_TEST_XADES_CERT_CRT`/`KSEF_TEST_XADES_PRIVATE_KEY_PEM` albo odpowiednie
warianty z sufiksem `_B64`. Hasło klucza jest opcjonalnym
`KSEF_TEST_XADES_PRIVATE_KEY_PASSWORD`. Konto TEST musi mieć uprawnienia używane
przez istniejące scenariusze. Scenariusz kursora wysyła 11 faktur, aby potwierdzić
przekroczenie minimalnego rozmiaru strony.

Do lokalnego odtworzenia bramy z zainstalowanym wheelem ustaw
`KSEF_TEST_INSTALLED=1`, `KSEF_E2E=1` i wymagane dane środowiska, oraz `KSEF_TEST_WHEEL` wskazujące testowany plik `.whl`, następnie uruchom:

```bash
python -m tools.verify_e2e_results output/required-test.xml --run
```

W tym trybie testy sprawdzają miejsce importu oraz bajtową zgodność plików
pakietu z podanym wheelem. Kontrola powtarza się po E2E. Raport JUnit i manifest
artefaktów są zachowywane w CI; nie zawierają celowo zapisywanych tokenów i kursorów.


## Zmiany po przeglądzie bezpieczeństwa

Nowe wyszukiwanie odrzuca niekompletne lub niepoprawnie typowane odpowiedzi API,
łącznie z brakiem `hasMore`/`isTruncated`/`invoices`; nie zamienia ich na sukces
z pustym wynikiem. Odczyt starszego kursora bez jawnej daty końcowej wykorzystuje
zapisany zakres zamiast ponownie porównywać jego początek z dzisiejszą datą.

Przykład SQLite jawnie otwiera i zatwierdza transakcję także dla połączenia
`isolation_level=None` lub `autocommit=True`. Odrzuca połączenie z aktywną
transakcją, aby nie zatwierdzić cudzych zmian. `COMMIT` i `ROLLBACK` są jawne.

Błędy transportu nie wyświetlają tekstu ani łańcucha oryginalnego wyjątku,
ponieważ mogą zawierać podpisane adresy. Niepoprawne odpowiedzi niebędące JSON
nie są wypisywane w komunikatach; ich treść pozostaje w `response_body` do
świadomej diagnostyki. Funkcja `update_continuation_point()` zgłasza `ValueError`,
jeśli paczka jest obcięta i nie ma bezpiecznej daty ostatniego rekordu, zamiast
przesunąć checkpoint do HWM i pominąć brakujące faktury.

Minimalne wersje `cryptography` i istniejących zależności HTTP zostały podniesione
po audycie podatności. Ograniczenia tranzytywne nie dodają nowych bibliotek do
rzeczywistego grafu HTTP, ale mogą wymagać aktualizacji lockfile aplikacji.
