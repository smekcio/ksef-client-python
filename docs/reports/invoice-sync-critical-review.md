# InvoiceSync — krytyczny przegląd, bug review i security review

Data: 28 października 2026. Przegląd lokalny zmian od `1db4dbe` do
`8aafc61`; poprawki: `221f1c4` i `bbd64e6500e80fc3f373fd8b870272f613fcf071`.
To drugi przegląd implementacji wykonany przez tego samego autora, z nowymi
reprodukcjami; nie jest niezależnym zewnętrznym audytem bezpieczeństwa.

Zakres obejmował źródła SDK, granice zaufania magazynu i transportu, pełne dane
obserwacji, niezmienność i walidację stanu, cancellation, deadline, SQLite,
generowany async adapter, bezpieczne raporty oraz nadzór procesów bramy TEST.

## Ustalenia i poprawki

| ID | Priorytet | Problem przed poprawką | Wdrożona poprawka i weryfikacja |
| --- | --- | --- | --- |
| R01 | P1 | Sprawdzano tylko environment/context źródła. Inna rola, filtr, granica lub parametry wykonania mogły być przyjęte pod właściwym scope checkpointu. | Pełne porównanie `InvoiceMetadataSearchIdentity`, ze wspólnym fingerprintem znormalizowanego query. Siedem podmian źródła odrzuconych przed HTTP. |
| R02 | P1 | `stop_reason` przenosił dowolny tekst z HTTP reasonCode lub wyjątku adaptera do repr/JSON raportu, również DSN z tokenem. | Zamknięta lista bezpiecznych przyczyn SDK, a dla HTTP i nieznanych powodów stabilny ErrorCode. Oryginalny wyjątek pozostaje prywatnym atrybutem. Dwie reprodukcje wycieku. |
| R03 | P2 | Anulowanie zadania oczekujące przed COMMIT mogło nie zapobiec rozpoczęciu zapisu. | Punkt dostarczenia cancellation i ponowna kontrola deadline'u przed utworzeniem zadania commita. Reprodukcja potwierdza zero wywołań adaptera. Rozpoczęty COMMIT nadal jest osłaniany i odbierany. |
| R04 | P2 | Wielokrotne anulowanie mogło przerwać zamykanie odpowiedzi HTTP i pozostawić strumień niezamknięty. Dotyczyło także implicit close przy EOF. | Wspólny `shield_and_drain` oraz ochrona zamykania async streamu i context managera. Osobne regresje anulowania podczas body i EOF. |
| R05 | P2 | Model roundtrip usuwał nieznany zagnieżdżony filtr, zanim sprawdzała go ścisła normalizacja. | Wspólna kontrola zachowania pól przed przyjęciem specyfikacji. Nieznany filtr daje błąd zamiast poszerzenia zapytania. |
| R06 | P2 | `KeyboardInterrupt`/`SystemExit` omijały cleanup transakcji przykładu SQLite. | Cleanup obejmuje BaseException, po czym zachowuje typ przerwania. Przy nieudanym rollbacku połączenie jest zamykane. Test przerwania po INSERT potwierdza rollback i niezmieniony checkpoint. |
| R07 | P2 | Publiczny load dopuszczał obcą aktywną transakcję; commit na zamkniętym połączeniu mógł zgłaszać surowe sqlite3 error. | Wspólny guard idle, prywatny odczyt w transakcji należącej do commita i bezpieczny StoreError/not_started przed BEGIN. |
| R08 | P2 | Koszt semantycznej walidacji kursora nie był sprawdzany na końcu kroku load. | Dodatkowy check kontroli czasu po walidacji. Reprodukcja opóźniająca tylko pierwszą walidację daje partial/step_time_budget, bez zatwierdzenia strony. |
| R09 | P2 | Przyszły początek jednej roli albo cofnięcie zegara względem HWM przerywały cały koordynator przez ValueError. | Jawny per-stream `cycle_end_before_start` bez zmiany HWM. Zdrowa rola kończy swój cykl. Pull nadal odrzuca błędny argument until. |
| R10 | P2 | Parser datetime normalizował niepoprawne minuty offsetu, np. +01:60, zamiast odrzucić wejście nowego sync API. | Ścisły format offsetu z minutami 00–59 i cyframi ASCII. Publiczny parser datetime starego SDK pozostaje bez zmian. |
| R11 | P2 | Koperta z JSON przechodziła walidację semantyczną przed strukturalnym preflightem; query było odtwarzane jako model przed kontrolą swojego rozmiaru. | Preflight głębokości/węzłów/znaków przed walidacją modeli i osobna kontrola query. Dodatkowo 308 deterministycznych mutacji checkpointu: poprawny roundtrip albo domenowy InvalidSyncCheckpointError. |
| R12 | P2 | Odrzucenie kompresji lub przekierowania było przedstawiane jako przekroczenie rozmiaru, co sugerowało nieskuteczne zmniejszenie strony. | SyncLimitError wyłącznie dla rozmiaru. Polityka transportu daje SyncError/response_encoding, response_redirect lub response_rejected, bez retry i bez przesunięcia checkpointu. Sześć przypadków sync/async. |
| R13 | P2 | JSON raportu pomijał indywidualne coverage, mimo obecności tego pola na obiekcie wyniku. | Bezpieczna serializacja coverage każdego strumienia oraz wspólnego pokrycia przez ten sam helper. |
| R14 | P2 | Supervisor nie sprzątał potomków po sukcesie lidera i nie odejmował kosztu uruchomienia procesu od pozostałego deadline'u. | Sprzątanie grupy po każdym zakończeniu fazy i ponowne wyliczenie czasu po Popen. Live node wymaga Linux CI; testy obejmują sukces, błąd i timeout lidera. Usunięto także wyścig exists/read przy odczycie /proc w testach. |

Pierwsze **17 reprodukcji** zakończyło się niepowodzeniem na poprzedniej
implementacji. Po poprawkach przechodzą. Kolejne regresje rozszerzyły zestaw
o EOF cleanup, rozróżnienie polityki/limitu, pokrycie JSON, mutacje checkpointu
i zakończenie potomków. Nie obniżano istniejących asercji ani progów pokrycia.

## Odbiór po poprawkach

Wszystkie lokalne bramki są zielone:

- po **3362 passed** na Linux/Python 3.10–3.14, po 61 podtestów;
- **3353 passed** na Windows/Python 3.12, 61 podtestów;
- **100% pokrycia SDK** na Linux i Windows, bez obniżenia progu;
- **630 passed** i 15 podtestów na dokładnym zainstalowanym wheelu;
- Ruff, mypy, generatory, pip check, wheel/sdist oraz base/CLI/FA(3) packaging;
- trzy pary procesów RSS: maksymalny wzrost **180 224 B**, poniżej 32 MiB.

Linux ma 13 pominiętych testów live, Windows 22 pominięcia obejmujące także
przypadki platformowe/opcjonalne. Nowe reprodukcje SDK przechodzą; dwie nowe
regresje grup procesów są wykonywane na Linux, pomijane na Windows.

Wyniki końcowych sprawdzeń i hashe nowego wheela/sdist znajdują się
w [invoice-sync-review-validation.json](invoice-sync-review-validation.json).
Pełny przegląd potwierdza nadal format checkpointu i kursora v1, inkluzywny HWM,
CAS i atomiczność dokumentów/obserwacji/checkpointu, brak nowych zależności
podstawowych i publiczne importy sync/async.

Zaliczone sprawdzenia są odnotowywane dla dokładnego commita kodu `bbd64e6`.
Późniejsze zmiany dokumentacji tego przeglądu nie zmieniają SDK ani testów.
Pomiary RSS dotyczą tego samego drzewa źródeł; nie są obietnicą przepustowości
serwera KSeF. Limity SDK pozostają kooperatywne, z dokończeniem rozpoczętego
COMMIT i cleanupu sieciowego.

Nie pozostało potwierdzone, otwarte ustalenie z tego przeglądu. Test live
A/HWM/B/restart pozostaje do wykonania w obowiązkowej, chronionej bramie CI,
zgodnie z wcześniejszą decyzją użytkownika. Nie wykonywano push, PR, publikacji
ani zmiany ochrony środowiska. Zaliczenie lokalnych regresji nie zastępuje
faktycznego zaliczenia tej bramy przed wydaniem.
