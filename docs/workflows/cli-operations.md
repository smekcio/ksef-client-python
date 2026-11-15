# Archiwum XML i kolejka offline w CLI

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

Udostępnij procesowi dwa osobne, wygenerowane losowo klucze po 32 bajty
zakodowane w standardowym Base64. `KSEF_EXPORT_STATE_KEY` chroni stan
operacji eksportu, a `KSEF_OFFLINE_STATE_KEY` chroni kolejkę XML i UPO.
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
