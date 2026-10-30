# Naprawa live E2E synchronizacji XML — 2026-10-30

## Ustalenia z rzeczywistych jobów

- [40957395594 / 123742910968](https://github.com/smekcio/ksef-client-python/actions/runs/40957395594/job/123742910968),
  SHA `bcbd052`: siedem testów zaliczonych; scenariusz XML zakończył się błędem
  procesu po 1571,470 s. Supervisor ukrył prywatny stdout/stderr, więc ten job
  nie pozwalał ustalić przyczyny.
- [41080662527 / 124148770325](https://github.com/smekcio/ksef-client-python/actions/runs/41080662527/job/124148770325),
  SHA `5afc330`: siedem testów zaliczonych; XML zakończył się po 600,562 s z
  bezpieczną diagnostyką `stage=observe, failure=deadline`. Nie rozpoczął się
  jeszcze zapis metadanych ani pobieranie XML. W tym samym jobie przeszedł
  wcześniejszy scenariusz synchronizacji korzystający z szerszego zakresu dat.

Drugi wynik lokalizuje problem w oczekiwaniu na metadane przy dodatkowym filtrze
dokładnego numeru KSeF. Nie dowodzi ogólnej awarii SDK ani konkretnej usterki
wewnętrznego indeksu MF. Test restartu XML nie powinien dodatkowo zależeć od czasu
udostępnienia dokumentu przez osobne wyszukiwanie dokładnego numeru.

## Zmiana scenariusza

Podczas pracy na gałęzi pojawił się równoległy commit `ac32d86` z przejściem na
zakres dat i normalizacją numeru po wysyłce. Został włączony do historii bez
force push. Zachowano te zmiany i ich przypadki testowe; poniższe uzupełnienia
dodają m.in. publiczne, stronicowane sprawdzanie celu, obsługę trwałych blokad,
diagnostykę HWM oraz testy nadzoru procesów.

Helper obserwuje zakres dat `PermanentStorage` z zachowaniem HWM, jak działający
scenariusz metadanych. Wybiera docelową fakturę po numerze, a następnie uruchamia
rzeczywistą synchronizację metadanych. Przed zakończeniem pierwszego procesu
sprawdza w trwałej kolejce, że dokładnie ta faktura ma zadanie `pending`.

Zakres może zawierać inne faktury. Drugi proces musi doprowadzić wszystkie
zaobserwowane XML do gotowości, potwierdzić `ready` docelowego zadania i kompletność
raportu. Ponowny przebieg musi wykazać brak nowych claimów i pobrań. Nie zakłada
się już, że w całym zakresie jest tylko jeden dokument. Wyszukanie zadania jest
stronicowane, a historyczny alias numeru normalizowany.

Nie wstawia się metadanych ani zadań ręcznie i nie pomija weryfikacji hashy SDK.
Manifest nadal wymaga wszystkich ośmiu scenariuszy dokładnie raz, bez ponawiania
nieudanego scenariusza. Instalacja i kontrola dokładnego wheela pozostają
obowiązkowe przed i po E2E.

## Brak pozornego zawieszenia i bezpieczne błędy

- `pytest -v` z niebuforowanym Pythonem pokazuje aktualnie wykonywany test;
  `--durations=0` podaje czasy scenariuszy. `--show-capture=no` nadal chroni
  przechwycony output.
- Trwałe `blocked` po synchronizacji metadanych kończy helper natychmiast
  kontrolowanym błędem, zamiast czekać na stan `pending`, którego już nie będzie.
- Diagnostyka obserwacji rozróżnia `hwm_before_start`, `not_visible` i `visible`;
  są to stałe kody, bez numeru faktury, XML, tokenu ani parametrów zapytania.
- Supervisor wskazuje numer fazy i kod wyjścia. Prywatny stdout/stderr nadal
  trafia do `DEVNULL`; limity czasu oraz sprzątanie procesów potomnych pozostają
  egzekwowane.

## Regresje i walidacja

Testy z prawdziwymi adapterami SQLite/plików oraz transportem HTTP odtwarzają
pusty wynik przy filtrze dokładnego numeru, opóźniony HWM, dodatkowe dokumenty
w zakresie, trwałą blokadę oraz restart i odczyt gotowych XML. Osobny test sprawdza
stronicowane odnalezienie celu poza pierwszymi 100 zadaniami i alias numeru.
Test rzeczywistego procesu potomnego sprawdza numer nieudanej fazy i brak wycieku
stdout/stderr.

Ścisły lint, mypy, kontrola generowanych artefaktów, `pip check` oraz sprawdzenie
pakietów instalacyjnych przeszły. Pełny przebieg Linux/CPython 3.12.13:
**3759 passed, 14 skipped, 61 subtests passed; 20144/20144 linii SDK (100,00%)**,
przy wymaganym `--cov-fail-under=100`. Dodatkowe przypadki diagnostyki opóźnionego
HWM sprawdzono następnie osobnym przebiegiem helperów; konfiguracji pokrycia
nie zmieniano. Wynik nowego live E2E należy sprawdzić dla
commita zawierającego tę poprawkę; poprzednich siedmiu sukcesów nie zaliczamy
jako walidacji nowego scenariusza XML.
