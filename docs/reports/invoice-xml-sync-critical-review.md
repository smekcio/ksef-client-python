# Krytyczny review synchronizacji XML — 2026-10-29

Review kodu z commitu `04f83ec` obejmował nową synchronizację XML, publiczne
adaptery, granice transakcji, obsługę błędów i anulowania, bezpieczeństwo plików
oraz instrukcje dla integratora. Poniższe ustalenia zostały poprawione.
Szczegóły końcowej walidacji zapisano w
[raporcie maszynowym](invoice-xml-sync-critical-review.json).

## Znalezione błędy

| Priorytet | Problem i skutek | Poprawka |
| --- | --- | --- |
| P2, bezpieczeństwo | Na POSIX `cleanup_staging()` po `close()` tracił deskryptor katalogu. Usuwanie nazwy tymczasowej mogło rozwiązać się względem bieżącego katalogu procesu i usunąć pasujący plik poza storage. Dodatkowo skanowanie po ścieżce i usuwanie po deskryptorze mogły dotyczyć różnych katalogów po zmianie nazwy katalogu storage. | Zamknięty magazyn odrzuca operację; skanowanie i usuwanie używają tego samego deskryptora. Blokada instancji chroni operacje przed równoległym `close()`. |
| P2, niezawodność | Nieudany rollback po konflikcie dzierżawy nadal zgłaszał zwykłą utratę dzierżawy. Worker mógł kontynuować na zamkniętym, niewiarygodnym połączeniu. | Błąd całego magazynu z niepewnym wynikiem zapisu; przerwanie przebiegu. Przerwania procesu pozostają przerwaniami. |
| P2, budżet | Wspólny przebieg zaczynał liczyć czas dopiero po walidacji magazynu; wolna walidacja mogła przekroczyć budżet i mimo tego uruchomić metadane. | Walidacja wliczana do budżetu. Po jego wyczerpaniu raport częściowy bez rozpoczynania cyklu metadanych. |
| P2, odporność na odpowiedź serwera | Liczbowo nieprzedstawialny `Retry-After` powodował wyjątek podczas klasyfikowania HTTP 429, zamiast trwałego zakończenia obsługi zadania. | Bezpieczny kod `invalid_retry_after` i stan `blocked`; zwykłe długie terminy serwera nadal są respektowane. |
| P2, diagnostyka | Nieudane rozpoczęcie transakcji migracji mogło zostać zamaskowane błędem rollbacku nieistniejącej transakcji. | Rollback tylko dla aktywnej transakcji, zachowanie pierwotnego błędu. Ta sama ochrona przy wiązaniu storage. |
| P2, zgodność API | Odczyt plikowy async nie przyjmował `max_bytes`, w przeciwieństwie do sync. XML pobrany ze zwiększonym limitem nie dawał się odczytać z domyślnym limitem cache. | Parametr dodany do implementacji async i obu protokołów. Testy mniejszego i większego limitu w obu wariantach. |

Pierwsze siedem przypadków regresji odtworzyło błędy przed poprawkami.
Niezależny test na Linux uruchomił wersję storage sprzed poprawki: potwierdził
usunięcie pasującego pliku w osobnym katalogu roboczym i pozostawienie pliku
w zamkniętym storage. Testy używają wyłącznie katalogów tymczasowych.

Regresje są w `tests/test_invoice_xml_critical_review.py`. Test
`tests/test_invoice_xml_documentation.py` wykonuje przykład z README i kompletny
skrypt na rzeczywistych adapterach SDK oraz lokalnej atrapie HTTP. Sprawdza
wznowienie bez ponownego GET i brak tokena w drukowanym wyniku.

## Security review: sprawdzone granice

- Tożsamość storage i zakres zadania są sprawdzane przed pobraniem. Klucze
  obiektów powstają z tożsamości i hasha; numer faktury nie jest ścieżką pliku.
- SHA-256 obejmuje oryginalne bajty. Hash metadanych jest obowiązkowy; obecny
  hash nagłówka również jest weryfikowany. XML nie jest parsowany w tej ścieżce,
  więc pobieranie i publikacja nie uruchamiają rozwiązywania encji XML.
- Odbiór HTTP ma limit rozmiaru; kolejka nie buforuje zbioru XML. Przekierowania,
  uwierzytelnianie i ograniczenia transportu pozostają w istniejącej ścieżce HTTP.
- Publikacja jest bez nadpisywania; istniejący plik jest ponownie sprawdzany.
  Testy obejmują dowiązania, pliki specjalne, podmianę katalogu i uchwyty Windows.
- Zatwierdzenie wymaga tokena, fencing i epoki; testy obejmują utratę dzierżawy,
  restart procesu i anulowanie w trakcie zatwierdzania. Raport zawiera znane kody,
  bez tekstów odpowiedzi HTTP, XML ani tokenów.

## Granice gwarancji i pozostała walidacja

To review kodu i testów, nie niezależny audyt penetracyjny całego SDK. Katalog
archiwum i bazę musi chronić system operacyjny przed niezaufanymi zapisującymi
procesami; na Windows należy ustawić odpowiednie ACL. Nazwy niejawne nie są
szyfrowaniem. Sprzątanie stagingu wymaga okna serwisowego z zatrzymanymi
publikującymi workerami — blokada jednej instancji nie koordynuje osobnych
procesów. Restore wymaga zatrzymania workerów przed przywróceniem bazy,
zwiększenia epoki i weryfikacji storage przed restartem.

Raport gotowości odzwierciedla ostatnio potwierdzony stan plików. Zewnętrzne
usunięcie pliku wykrywa odczyt lub `verify_ready`, a nie samo `describe`.
Odporność na utratę zasilania zależy również od platformy i systemu plików.
Test live KSeF TEST na dokładnym wheelu pozostaje do wykonania z poświadczeniami;
lokalne testy z atrapą HTTP nie potwierdzają zachowania usługi produkcyjnej.

## Dokumentacja

README przedstawia zastosowanie, kompletny przykład i obsługę wyniku. Przewodnik
prowadzi od instalacji przez pierwszy cykl, wznowienie i odczyt archiwum do async,
migracji i odzyskiwania. Wyjaśnia HWM oraz to, że sukces cyklu nadal wymaga
kolejnych uruchomień harmonogramu. Przykłady dotyczą kodu checkoutu, bez deklaracji
dostępności tych funkcji w opublikowanym wydaniu 0.22.0.
