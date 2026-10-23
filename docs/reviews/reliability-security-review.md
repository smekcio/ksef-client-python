# Przegląd błędów i bezpieczeństwa: niezawodność SDK

Data: 2026-10-23. Gałąź: `reliability-pagination-release-gate`.
Poprawki znajdują się w commitach tej gałęzi.

Przegląd objął implementację paginacji i kursorów, redakcję danych,
przykład checkpointów, bramę wydawniczą oraz powiązane ścieżki HTTP,
HWM, serializacji, generatora, zależności i testów. Łączył analizę kodu,
testy regresji i skan zależności. Nie stanowi gwarancji braku wszystkich
możliwych podatności.

## Wykryte problemy i naprawy

| Priorytet | Problem | Zastosowana poprawka |
| --- | --- | --- |
| P1 | Niepełna lub wadliwa odpowiedź metadanych mogła zostać uznana za koniec pobierania. | Nowe API waliduje surową odpowiedź przed konwersją do modeli i zgłasza błąd niekompletności z kursorem powtórzenia strony. |
| P1 | Kontynuacja HWM przy obcięciu bez daty ostatniej faktury mogła przeskoczyć do HWM. | Taki przypadek kończy się błędem; poprzedni punkt kontynuacji pozostaje zachowany. |
| P1 | Checkpoint SQLite nie był atomowy przy włączonym autocommit. | Jawna transakcja obejmuje faktury i checkpoint, z rollbackiem przy awarii. Przykład odmawia działania wewnątrz istniejącej transakcji aplikacji. |
| P1 | Wyjątki transportowe i nie-JSON-owe odpowiedzi mogły ujawniać podpisane URL-e lub poufne treści. | Bezpieczne komunikaty, bez formatowania pierwotnego łańcucha wyjątków; surowa odpowiedź pozostaje dostępna jawnie przez `response_body`. URL-e uploadu z danymi użytkownika są odrzucane. |
| P1 | Sprawdzenie samej ścieżki importu nie dowodziło uruchomienia dokładnie publikowanego wheela. | Porównanie plików zainstalowanego SDK z zawartością wskazanego wheela oraz weryfikacja manifestu, sum i SHA. |
| P1 | Raport JUnit mógł zawierać błędy na poziomie zestawu pomimo pozornie udanych wymaganych przypadków. | Brama odrzuca błędy i porażki zestawów, niewłaściwy korzeń XML, brakujące, powtórzone i pominięte testy. |
| P2 | Odtworzenie starego kursora bez pierwotnej daty końcowej ponownie liczyło zakres względem bieżącej daty. | Wznowienie korzysta z daty zamrożonej w kursorze i waliduje efektywny zakres. |
| P2 | Obcięcie po dacie Issue mogło utworzyć kursor wychodzący poza pierwotną granicę czasową. | Granica inkluzywna jest ograniczona zakresem wyszukiwania; dodano regresje obu kierunków. |
| P2 | Nietypowe daty i niekanoniczny JSON kursora mogły wywołać niekontrolowany wyjątek lub niejednoznaczną walidację. | Ograniczenie długości dat, obsługa przepełnienia, odrzucanie powtórzonych kluczy i NaN/Infinity oraz ścisłe porównanie typów. |
| P2 | Niestandardowy adres środowiska mógł przenieść dane uwierzytelnienia do kursora. | Nowe kursory zapisują skrót identyfikatora środowiska. Odczyt wcześniejszego formatu v1 pozostaje zgodny i migruje stan przy kontynuacji. |
| P2 | Diagnostyka mogła uruchomić reprezentację obcego obiektu albo nadmiernie rozbudować wynik. | Ograniczenie głębokości, liczby elementów i długości danych, wykrywanie cykli, ścisłe typy oraz maskowanie dodatkowych nagłówków i adresów konfiguracji. |
| P2 | Integralność sdist i zakres udostępniania sekretów CI wymagały wzmocnienia. | Kontrola metadanych sdist, odrzucanie niebezpiecznych nazw i symlinków manifestu, przypięcie akcji do SHA i sekrety ograniczone do wymagających ich kroków. |
| P2 | Skan lokalnego środowiska wykazał znane podatności zależności. | Podniesiono minimalne wersje zależności podstawowych, CLI i narzędzi deweloperskich. Ponowny skan zaktualizowanego środowiska nie zgłasza znanych podatności. |
| P2 | Końcowy przegląd wykazał, że konwersja modeli mogła ukryć błędny typ numeru KSeF, a zbyt długi numer tworzył nieodczytywalny następny kursor. | Nowe API sprawdza typ i długość identyfikatora oraz typy dat przed konwersją. Niepoprawne dane powodują jawny błąd niekompletności z kursorem powtórzenia, także w async. |

Wszystkie powyższe pozycje mają status **naprawione** i testy regresji
lub odpowiednią kontrolę narzędziową. Dodatkowo naprawiono izolację
testów platformowych zmieniających globalne `os.name` na Windows.

## Zgodność i zamierzone zmiany

- Istniejące publiczne metody zapytań i iteratory zachowują wcześniejsze
  zachowanie. Ścisła walidacja kompletności dotyczy nowego API wyszukiwania.
- `to_dict()` i `to_json()` pozostają serializacją transportową zawierającą
  dane; nie należy traktować ich jako bezpiecznej diagnostyki.
- Komunikaty wyjątków nie zawierają już surowego body ani komunikatu
  zewnętrznego transportu. Dostęp do `response_body` wymaga ostrożności.
- Kursory nadal nie są szyfrowane ani uwierzytelnione. Zawierają filtry
  i identyfikatory dokumentów, dlatego nie powinny trafiać do logów.
- Tryb testowania zainstalowanego pakietu wymaga `KSEF_TEST_INSTALLED=1`
  oraz `KSEF_TEST_WHEEL` wskazującego dokładny plik wheela.
- Należy odświeżyć własne lockfile po podniesieniu minimalnych wersji
  zależności. Nie dodano nowych bibliotek do podstawowego grafu zależności.

## Weryfikacja

- Pierwsza pełna kontrola na Pythonie 3.10, 3.11, 3.12 i 3.13 na Windows:
  po **2405 testów zaliczonych,
  15 pominiętych**, 61 zaliczonych podtestów na każdej wersji.
- Po poprawkach końcowego przeglądu: Python 3.12, **2426 testów zaliczonych,
  15 pominiętych, 100% pokrycia kodu źródłowego**, 15529 instrukcji.
  Na Pythonie 3.10, 3.11 i 3.13 ponownie zaliczono po 142 testy paginacji,
  regresji przeglądu i bramy wydawniczej.
- Testy obejmują utratę danych na granicach paginacji, restart,
  niepoprawne odpowiedzi, kursory, diagnostykę, SQLite i negatywne
  przypadki bramy wydawniczej; dodano deterministyczne mutacje kursorów.
- Ruff i mypy: zaliczone. Zgodność generatora i pokrycie 83/83 endpointów:
  zaliczone. Actionlint dla trzech zmienionych workflow: zaliczony.
- Kontrola pakowania CLI: zaliczona. `pip check`: zaliczony.
- `pip-audit` zaktualizowanego środowiska: brak znanych podatności
  według bazy dostępnej w dniu przeglądu. To nie zastępuje przyszłych skanów.

Rzeczywiste scenariusze KSeF TEST nie zostały wykonane lokalnie z powodu
braku poświadczeń. Przypadki wymagające środowiska zewnętrznego lub innej
platformy pozostają wśród pominiętych testów. Skonfigurowana brama publikacji
wymaga zaliczenia wszystkich pięciu scenariuszy TEST i blokuje wydanie przy
ich pominięciu albo braku sekretów. Wyniki lokalne nie oznaczają zgody na
publikację bez tej kontroli.
