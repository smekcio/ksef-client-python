# Faktury online, paczki, archiwum XML i kolejka offline w CLI

Polecenia korzystają z tego samego trwałego archiwum i maszyny stanów, co SDK.
Każdy cykl można uruchomić w osobnym procesie. Stan trafia do osobnego
podkatalogu dla kombinacji profilu, adresu API i kontekstu uwierzytelnienia.
Pliki XML w archiwum są jawne, więc katalog powinien znajdować się na prywatnym
woluminie aplikacji z odpowiednim ACL. Używaj tego samego katalogu po restarcie.

Jednorazowo zaloguj każdy profil pod jego właściwym adresem i kontekstem.
Po zmianie profilu zaloguj się ponownie. Dla logowań sprzed wprowadzenia
tych poleceń potrzebne jest ponowne logowanie w celu zapisania powiązania
tokenów z kontekstem.
Polecenia sieciowe używają adresu HTTPS zapisanego w profilu. W razie
potrzeby odświeżają i zapisują token dostępowy dla następnego cyklu.

Każda kolejka używa własnego losowego klucza o długości 32 bajtów zakodowanego w Base64.
Udostępnij procesowi klucze używanych operacji. `KSEF_EXPORT_STATE_KEY` chroni stan eksportu,
`KSEF_OFFLINE_STATE_KEY` chroni kolejkę offline, a `KSEF_ONLINE_STATE_KEY` chroni kolejkę online.
Przechowuj klucze w magazynie sekretów i dołącz je do procedury odtwarzania kopii.
Cykl korzysta z kluczy przekazanych procesowi i nigdy nie wypisuje ich w wyniku.

## Archiwum

```sh
ksef --profile firma-a --json archive sync --state-dir ./private --role Subject2 --since 2026-10-01T00:00:00Z
ksef --profile firma-a --json archive status --state-dir ./private --role Subject2
```

Zachowaj początki importu dla poszczególnych ról. Przy imporcie historii
dodaj `--until` i zachowaj tę samą wartość, aż zapisany `committed_hwm`
osiągnie oczekiwaną granicę. Limity `--max-documents` i `--timeout` dotyczą
jednego wywołania. `archive status` odczytuje zapisany stan bez logowania.
`pending` oznacza otwarty przedział, `importing` zapis części paczki,
a `truncated` oczekiwanie na dalszy fragment. Zasady znaku wodnego
opisuje [workflow eksportu](export.md#wznawialny-import-do-lokalnego-archiwum).

## Kolejka offline

```sh
ksef --profile firma-a --json offline enqueue --state-dir ./private --xml faktura.xml --due-at 2026-11-16T18:00:00+01:00 --mode offline24
ksef --profile firma-a --json offline status --state-dir ./private
ksef --profile firma-a --json offline run --state-dir ./private --limit 10
```

`enqueue` zapisuje oryginalne bajty bez połączenia z KSeF. System
wystawiający dokument przekazuje rzeczywisty termin dosłania oraz tryb
`offline24`, `unavailable` lub `emergency`. Zachowaj `invoice_hash`
do sprawdzania wyniku przez `offline status --invoice-hash`.
Po stanie `complete` użyj `offline upo --invoice-hash <hash> --out <plik>`
z tym samym `--state-dir`. Wskaż nowy plik w istniejącym prywatnym katalogu.
Polecenie pobiera zapisane UPO z kolejki bez uwierzytelniania w KSeF.

`offline run` wykonuje po jednym kroku dla pozycji w kolejności terminów.
`--timeout` dotyczy pojedynczej pozycji. Jeśli odpowiedź na wysyłkę zaginie,
kolejny cykl szuka istniejącej faktury w zapisanej sesji. Pozycja
`submission_unknown` wymaga uzgodnienia z KSeF. Sam upływ czasu jej nie
kwalifikuje do ponownej wysyłki. Szczegóły rozliczania stanów i odzyskiwania
opisuje [workflow offline](online-session.md).

- `offline reschedule --invoice-hash <hash> --revision <revision> --due-at <czas>` zmienia
  termin tylko dla wskazanej wersji aktualnego rekordu. Odczytaj wersję z `offline status`.
- `offline retry-cancelled --invoice-hash <hash>` wraca do kolejki po zapisanym potwierdzeniu
  anulowania przez KSeF.
- `offline retry-unsubmitted --invoice-hash <hash>` sprawdza niejednoznaczną wysyłkę.
  Wznowienie dopuszcza dopiero zamknięta sesja, dla której KSeF potwierdził brak faktur.

Do tych poleceń podaj ten sam profil i `--state-dir`.


W automatyzacji po błędzie z kodem wyjścia 4 odczekaj co najmniej wskazane
`errors[0].retry_after_seconds`, jeśli serwer podał taki czas. Uruchamiaj
cykle pozostałych profili niezależnie. W dużej kolejce zachowuj
`next_cursor` i przekaż jego pola jako `--after-due-at` i `--after-hash`,
a po ostatniej stronie rozpocznij następny cykl od początku.

## Wysyłka online po własnym ID

Jeśli zapisujesz fakturę u siebie jako `FV-123`, możesz tym samym ID posługiwać się aż do odebrania jej indywidualnego UPO.
Ustaw `KSEF_ONLINE_STATE_KEY` na zakodowany w Base64 losowy klucz o długości 32 bajtów.
Wygeneruj go raz, zapisz w magazynie sekretów i udostępniaj kolejnym procesom. Chroni on XML, UPO i powiązanie z lokalnym ID w pliku `online.db`.

```sh
ksef --profile firma-a send online --invoice faktura.xml --local-id FV-123 --state-dir ./private --wait-upo --save-upo ./out/FV-123-upo.xml
ksef --profile firma-a online status --id FV-123 --state-dir ./private
```

Po przerwaniu procesu sprawdź `online status`. Polecenie `online run` wykonuje jeden kolejny krok dla zapisanego XML. Możesz ponawiać je dla tego samego ID. Przy stanie `complete` odbierzesz UPO także po wylogowaniu.

```sh
ksef --profile firma-a --json online run --id FV-123 --state-dir ./private
ksef --profile firma-a online upo --id FV-123 --state-dir ./private --out ./FV-123-upo.xml
```

- Do pracy w tle użyj `online enqueue --id FV-123 --xml faktura.xml --state-dir ./private`, a następnie `online run`. Rejestracja i odczyt zapisanego statusu działają lokalnie.
- Ponowne `send online` z tym samym ID i XML kontynuuje tę samą fakturę. Próba użycia ID dla innego XML lub tego samego XML pod innym ID kończy się błędem.
- W stanie `submission_unknown` wykonaj `online run`, aby uzgodnić wynik z KSeF. `online retry-unsubmitted` może dopuścić nową wysyłkę po potwierdzeniu pustej, zamkniętej sesji. `online retry-cancelled` przywraca do kolejki dokument po potwierdzonym anulowaniu z kodem 550. Oba polecenia przyjmują `--id` i `--state-dir`.
- Tryb śledzony obsługuje FA (3), adres wybranego profilu i indywidualne UPO z ustawień sesji SDK. `--wait-status` czeka na rozstrzygnięcie, a `--wait-upo` także na UPO. Po odrzuceniu faktury, wykryciu duplikatu lub anulowaniu przez KSeF obie opcje zwracają kod wyjścia 5, również przy odczycie zapisanego wyniku. Po przekroczeniu `--max-attempts` CLI zwraca kod 4 i zachowuje postęp. `online upo` zapisuje do nowego pliku.

### Lokalny pakiet faktury i UPO

```sh
pip install "ksef-client[cli,pdf]"
ksef --profile firma-a --json online bundle --id FV-123 --state-dir ./private --out FV-123.zip
```

Użyj tego samego profilu, kontekstu, katalogu stanu i klucza co przy wysyłce. Pakiet powstaje lokalnie, także po wylogowaniu. Polecenie odczytuje zapisaną wersję faktury. Postęp wysyłki zmienia się przez `online run`. Domyślne wartości `--state-dir` oraz `--out` to bieżący katalog i `invoice-bundle.zip`. Wybierz nowy plik w istniejącym prywatnym katalogu. ZIP zawiera odszyfrowaną treść.

Paczka zawiera oryginalne bajty w `invoice.xml`, wizualizację FA(3) w `invoice.pdf` oraz `manifest.json` z wersją formatu, lokalnym ID, rewizją, statusem wysyłki, kodem statusu KSeF, przydzielonym numerem KSeF i skrótami SHA-256 plików. Do czasu przydzielenia numeru manifest zwraca `ksef_number: null`.

| `upo_status` | Znaczenie |
| --- | --- |
| `available` | Pakiet zawiera `upo.xml`. SDK porównał numer sesji, numer KSeF oraz skrót faktury z indywidualnym UPO zapisanym w kolejce. Strony UPO zbiorczego są odrzucane także wtedy, gdy dana strona wymienia tylko jedną fakturę. |
| `pending` | Wysyłka lub odbiór UPO jest w toku. Po zapisaniu nowszej rewizji możesz wyeksportować kolejny plik ZIP. |
| `unavailable` | KSeF odrzucił bieżącą próbę, zgłosił duplikat lub potwierdził anulowanie. Kod KSeF jest w manifeście. |

Kod wyjścia 0 oznacza zapis kompletnej paczki dla podanej rewizji. Obecność UPO sprawdzisz w polu `upo_status`. [Zakres wizualizacji PDF](../invoice-bundle-pdf.md)

## Raport faktur z paczki

Zapisz sesję przy wysyłce paczki. Później sprawdzisz, jaki wynik KSeF przypisał każdemu plikowi.

```sh
ksef --profile firma-a send batch --dir ./faktury --save-session listopad
ksef --profile firma-a session batch report --id listopad
ksef --profile firma-a --json session batch report --id listopad
```

Raport działa także dla `session batch open --id`. Zapisana sesja przechowuje manifest nazw i skrótów z faktycznych bajtów ZIP lub TarGz. Obsługuje również paczki zbudowane przez `--dir`. Dzięki temu po wysłaniu prawidłowo zindeksowanej paczki można przenieść pliki źródłowe. Przy starszym zapisie CLI odtwarza manifest z zachowanego źródła i sprawdza, czy rozmiar i SHA-256 pasują do zapisanej sesji. Archiwum spoza obsługiwanego formatu faktur XML może być wysłane dotychczasową ścieżką, lecz nie da się z niego utworzyć raportu.

Wynik zawiera nazwę pliku, rozstrzygnięcie (`accepted`, `rejected`, `duplicate`, `cancelled`, `unresolved`), kod statusu i dostępne numery KSeF. `complete: false` oznacza, że części wyników nie udało się jeszcze rozstrzygnąć. Odczytaj raport ponownie. Granice odczytu ustalają `--page-size` i `--max-pages`, domyślnie po 100. Dopiero pełny raport wskazuje pliki do sprawdzenia w `correction_candidates` i anulowane pliki do rozważenia ponownej wysyłki w `retry_candidates`. Samo odczytanie raportu nie wysyła faktur. [Zasady interpretacji w SDK](batch-session.md#wynik-każdej-faktury-w-paczce)

## Odbiór faktur zakupowych

Po `archive sync` dla roli `Subject2` możesz przekazywać dokumenty z tego samego archiwum do skryptu lub aplikacji. Nadaj odbiorcy stałą nazwę i wskaż katalog wyjściowy z prywatnymi uprawnieniami. Odbiór, potwierdzenie i zwolnienie rezerwacji działają lokalnie.

```sh
ksef --profile firma-a --json archive next --consumer zakupy --state-dir ./private --out ./odbior
```

Wynik `available: true` zawiera stabilne `event_id`, termin wygaśnięcia rezerwacji oraz ścieżki `xml`, `metadata` i `receipt` w nowym katalogu próby. Skrypt może użyć `event_id` do deduplikacji. Po trwałym zapisaniu dokumentu przekaż ścieżkę z pola `receipt` do `ack`. Po przejściowym błędzie użyj `retry`.

```sh
ksef --profile firma-a archive ack --state-dir ./private --receipt ./odbior/invoice-PRZYKLAD/receipt.json
# Alternatywnie, po błędzie odbiorcy
ksef --profile firma-a archive retry --state-dir ./private --receipt ./odbior/invoice-PRZYKLAD/receipt.json --delay-seconds 60
```

Plik `receipt.json` należy do jednej próby i pozwala ją potwierdzić. Przechowuj go razem z dokumentem w prywatnym katalogu. Powtórzenie zakończonego `ack` jest bezpieczne. Po wygaśnięciu aktywnej rezerwacji pobierz dokument ponownie i użyj nowego potwierdzenia. `--lease-seconds` domyślnie wynosi 300. `available: false` i kod wyjścia 0 oznaczają, że dla tego odbiorcy nie ma teraz dokumentu gotowego do pobrania. Różni odbiorcy mają niezależne potwierdzenia. [Dostarczanie dokumentów w SDK](../incoming-invoice-delivery.md)

Jeżeli podczas zapisu plików rezerwacja wygaśnie lub archiwum wycofa próbę,
`archive next` kończy się kodem 4. Ponów pobranie. Katalog z XML i potwierdzeniem
jest udostępniany odbiorcy dopiero po sprawdzeniu aktualności rezerwacji.

## Uruchamianie cykliczne

[Przykładowy worker](../examples/scheduled_ksef_operations.py) wywołuje oba
polecenia i zapisuje po jednym raporcie JSON na linię. Uruchom osobny proces
pod nadzorem systemowym dla każdego profilu.

```sh
python docs/examples/scheduled_ksef_operations.py --profile firma-a --state-dir ./private --since 2026-10-01T00:00:00Z
python docs/examples/scheduled_ksef_operations.py --profile firma-b --state-dir ./private --since 2026-10-01T00:00:00Z
```

Odpowiedź HTTP 429 wstrzymuje oba zadania danego profilu do końca okresu
oczekiwania. Restart może
powtórzyć odczyt pierwszej strony kolejki. Stan faktury i znak wodny XML
pozostają w SQLite. Wspólny limit wyjściowego adresu IP KSeF nadal dotyczy
procesów korzystających z tego samego połączenia sieciowego.

W partii `offline run` błędy poszczególnych faktur trafiają do
`data.failures` razem z identyfikatorem faktury. Kolejne pozycje pozostają
obsługiwane, a operator może sprawdzić stan konkretnej faktury przez
`offline status --invoice-hash`. Harmonogram powinien monitorować obie
listy, `invoices` i `failures`. Przekroczenie limitu API lub błąd
uwierzytelnienia przerywa bieżący cykl profilu.

### Logowanie aktywnym certyfikatem

`KSEF_XADES_SELECTOR` wskazuje bazę wyboru certyfikatów utworzoną przez
[rotację XAdES](../certificate-rotation.md). Przy takim ustawieniu każde
sieciowe polecenie trwałej wysyłki online, raportu paczki, `archive` i `offline` otwiera sesję dla aktualnego
certyfikatu i kończy ją po cyklu. Wybór korzysta z nazwy, adresu API
i kontekstu profilu CLI. Żeby zmienić certyfikat kolejnego cyklu,
aktywuj nowy wpis w tej samej bazie.

Dla tego trybu przekaż hasła wersji w `KSEF_XADES_KEY_PASSWORDS` jako obiekt
JSON. Opcjonalne `KSEF_XADES_CERTIFICATE_DIR` wskazuje katalog z szyfrowanymi
kluczami. Jeśli operator wybrał dodatkową weryfikację, ustaw
`KSEF_XADES_VERIFY_CHAIN` i `KSEF_XADES_ENFORCE_COMPLIANCE` odpowiednio na
`true` lub `false`, zgodnie z konfiguracją aktywacji.

Przykładowy harmonogram uruchamia `offline run --submit-immediately`.
W obrębie każdej strony najpierw obsługuje faktury z otwartą sesją.
Dla nowej faktury próbuje otworzyć sesję i wysłać dokument w tym samym
cyklu, w ramach wspólnego limitu czasu dla tej pozycji. Timeout pozycji
trafia do `data.failures` jako `request_timeout`. Następny cykl odczytuje
utrwalony stan, w tym stan niejednoznacznej wysyłki, jeśli odpowiedź zaginęła.
