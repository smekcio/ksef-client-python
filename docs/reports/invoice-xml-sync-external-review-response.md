# Rozstrzygnięcie zewnętrznego review XML — 2026-10-29

Źródło: `REVIEW_BUG_SECURITY_INVOICE-XML-SYNC_2026-10-29.md`, dostarczone przez
użytkownika, dotyczące `89ff23a`. Poniżej rozstrzygnięto wszystkie punkty X0–X27.
Weryfikacja obejmuje kod, testy z rzeczywistymi SQLite/plikami, lokalny transport
HTTP i rzeczywiste uchwyty Windows. Wyniki końcowych przebiegów znajdują się
w [raporcie walidacji](invoice-xml-sync-external-review-validation.json).

| Punkt | Rozstrzygnięcie |
| --- | --- |
| X0 | **Poprawiony.** Zatwierdzona lista live zawiera test restartu XML. Nowy test porównuje rzeczywisty manifest z listą gate'u, bez podstawiania obu stron. Nie uruchomiono live bez poświadczeń. |
| X1 | **Poprawiony.** Błędny numer jest zapisywany jako `blocked`; zastany wadliwy wiersz jest izolowany podczas przejęcia. Plik specjalny, dowiązanie lub odmowa odczytu pojedynczego obiektu blokują dokument, a nie całą kolejkę. Błąd całego dysku/SQLite nadal przerywa przebieg. Test obejmuje trzy dokumenty i dalszy postęp po dwóch wadliwych. Nie zaostrzono parsera metadanych starego API, aby nie naruszyć jego kontraktu. |
| X2 | **Poprawione przejście między adapterami; automatyczna migracja odrzucona.** Pierwotny plan wymaga jawnej migracji istniejących schematów. Komunikat wskazuje konieczność migracji; procedura jest opisana również w przewodniku samych metadanych i CHANGELOG. Migracja metadanych dopuszcza brak `xml_storage_id`; właściwe archiwum można związać później. Stare protokoły metadanych pozostają bez zmian. |
| X3 | **Poprawiony.** Schemat v2 dodaje indeksy dla oczekujących i wygasłych zadań. Claim robi trzy uporządkowane sondy z LIMIT 1, sprawdza obserwację przez EXISTS i sortuje najwyżej trzech kandydatów. Nie materializuje całej historii obserwacji pod blokadą. Dla baz v1 migracja jest jawna. Istotne ograniczenie: przy wielu zadaniach innych sync_key w tej samej tożsamości sondy mogą pominąć wiele kandydatów, zanim znajdą zadanie wybranego scope'u. Nie deklarujemy O(1) dla dowolnie rozłącznych filtrów. |
| X4 | **Poprawiony.** Pole checkpointów jest wymaganym argumentem nazwanym. Worker sprawdza liczbę i scope checkpointów przed pierwszym claimem; wadliwy adapter daje `invalid_report_checkpoints` przed pobraniem XML. Wymóg spójnej migawki jest opisany. |
| X5 | **Poprawiony kontrakt obsługi.** `report` zachowuje właściwy typ wyniku konkretnego wywołania, już bez Any. `exc.xml_report` i `exc.report.xml` działają zarówno dla workera XML, jak i wspólnego cyklu. Nie dokładamy fikcyjnego raportu metadanych do osobnego workera. |
| X6 | **Poprawiony.** Kontrola deadline'u/anulowania jest propagowana przed mapowaniem OSError. Test wywołuje deadline w trakcie haszowania istniejącego pliku. |
| X7 | **Poprawiony.** Surowy Retry-After jest zachowany w wyjątkach HTTP również poza statusami retry transportu. Trwała kolejka respektuje go dla 21165 i przejściowych HTTP; nie ogranicza do 429. |
| X8 | **Poprawiony.** Dodano ponawianie 408/409/425/507/520/522/524 z trwałym licznikiem błędów. Testy sprawdzają rzeczywiste przejście retry_wait → ponowny claim → wyczerpanie po trzech cyklach oraz zakaz przedwczesnego claimu. Pozostałe trwałe błędy nadal są blokowane, z diagnostyką. |
| X9 | **Poprawiony.** Gotowość backfillu korzysta z wartości kolumny zamiast porównania obiektu wiersza z tuple. Obsługiwane są tuple i sqlite3.Row; inne row_factory są odrzucane czytelnym błędem przy konstrukcji. |
| X10 | **Zachowana świadoma polityka limitu.** Limit dotyczy dokumentu, także odzyskiwanego; pierwotny plan przewiduje blokadę rozmiaru i jawne ponowienie po podniesieniu limitu. Inspect haszuje strumieniowo, w stałej pamięci, z kontrolą deadline'u między blokami. Nie obiecujemy ograniczenia łącznego I/O do max_xml_bytes. Doprecyzowano dokumentację zamiast milcząco omijać limit dla cache. |
| X11 | **Poprawiony.** Limit sprzątania liczy kandydatów `.tmp-*`, a nie zwykłe XML. Test wymusza kolejność z ponad tysiącem gotowych wpisów przed kandydatem. Pamięć pozostaje stała; pełny skan może trwać dłużej, co opisano. |
| X12 | **Odrzucona automatyczna weryfikacja każdego cyklu.** Pierwotny kontrakt mówi o ostatnio potwierdzonej gotowości i osobnym verify_ready. Audyt wszystkich plików przy każdym cyklu przeczyłby skończonej, ograniczonej pracy. Restore nadal wymaga zatrzymania workerów, fencing i weryfikacji przed wznowieniem. Pusta obserwacja jest logicznie kompletna dla XML, ale nie daje complete bez metadanych i backfillu. |
| X13 | **Udokumentowane ograniczenie zegara, bez niebezpiecznej zmiany terminów.** Terminy trwałe muszą być porównywalne między procesami i restartami; sam monotonic nie zapewnia tego po restarcie hosta. Automatyczne skracanie cooldownu przy skoku czasu naruszałoby Retry-After. Dokumentacja wymaga poprawnego czasu hosta. Raport ma leased/retry_wait i next_attempt_at, więc nie utożsamia braku gotowej pracy z pustą historią. |
| X14 | **Poprawiony.** Utrata dzierżawy kończy przebieg; for/else nie nadpisuje jej na work_limit. Zmieniono test oczekujący starego, błędnego powodu. Fence nadal wymaga zatrzymania procesów przed restore; nie jest zdalnym wyłącznikiem procesu. |
| X15 | **Poprawiony wyciek; przypinanie przodków zachowane dla bezpieczeństwa ścieżki.** Dodano finalizer dla surowych uchwytów i deskryptorów obu platform. Test na rzeczywistym Windows wykazał ponadto, że otwarcie katalogu z zerowym dostępem nie egzekwowało deklarowanej blokady rename; używane jest teraz FILE_LIST_DIRECTORY. Test sprawdza blokadę za życia magazynu i możliwość rename po GC. Context manager pozostaje zalecany. Także POSIX fd będący int nie zamyka się sam od GC — ta część opisu źródłowego była nieścisła. |
| X16 | **Poprawiony.** Wczesne zakończenie z powodu budżetu respektuje raise_on_error dla istniejących blokad. Testy sync/async. |
| X17 | **Poprawiony.** Klucze i nowe obserwacje publicznego adaptera mają postać kanoniczną. Jawne migracje scalają poprawne historyczne aliasy, zachowują outbox/obserwacje i odrzucają konflikt hashy. Dawny receipt nie jest dowodem gotowości nowej nazwy pliku: zadanie pozostaje do pobrania, stare pliki nie są kasowane. |
| X18 | **Poprawiony.** RunError dziedziczy po KsefSyncRunError i ma sync_run_failed. Dodano osobne kody xml_integrity_error/xml_storage_error. Komunikaty zawierają ograniczony identyfikator przyczyny, bez odpowiedzi serwera. |
| X19 | **Poprawiony.** Raport ma ograniczone reason_counts; dokumentacja pokazuje również last_reason z paginowanego list_xml. Nie dodano nieograniczonej listy dokumentów do raportu. |
| X20 | **Częściowo poprawiony; swobodny rebind odrzucony.** Migracja rozpoznaje pełne schematy własnych tabel i zachowuje dodatkowe tabele aplikacji. Nie wymaga zastępczego ID. Dowolna zmiana tożsamości storage mogłaby fałszywie zachować ready w pustym katalogu; przeniesienie kompletnego archiwum ma zachować jego prawdziwy identyfikator. |
| X21 | **Wyjaśnione i uzupełnione dowody.** W poprzednim raporcie rozdzielono drzewo wejściowe review od drzewa zweryfikowanego po poprawkach. Pierwotna macierz miała etapy full_suite i final_supplemental; nie była jedną równoczesną kolekcją. Zachowano historyczne liczby, dodano opis etapów. Uzupełniono 4 skipy instalowanego wheela; brak zapisanej selekcji 350 testów oznaczono wprost. Nowy raport podaje dokładne komendy i selekcje. |
| X22 | **Poprawiony close async; retencja pozostaje poza zakresem.** Po zakończonym lub anulowanym zamykaniu adapter odłącza store i odbiera zakończenie executor.shutdown. Kolejny close jest bezpieczny; dalszy odczyt daje store_closed. Pruning, kasowanie opublikowanych dokumentów i polityka backupów nie należą do tej wersji według pierwotnego planu. |
| X23 | **Poprawiony.** SQLite jest importowany leniwie przy żądaniu adaptera; samo import ksef_client działa bez rozszerzenia sqlite3. Importy TYPE_CHECKING zachowują publiczne typy adapterów. Test w świeżym interpreterze blokuje oba importy sqlite3/_sqlite3. |
| X24 | **Poprawiona dokumentacja.** Backfill korzysta z sync.xml.scopes. Opisano dozwolone stop_reason, dokładny zakres invalid_retry_after i kontrolę między blokami odczytu. Enum nie jest konieczny dla poprawności; wartości są jawnie opisane. |
| X25 | **Poprawione pusta ścieżka i diagnostyka unlink.** Pozostałe zachowania są granicami bezpieczeństwa: wewnętrzny identyfikator nie jest plikiem tekstowym do ręcznej edycji, reparse points są odrzucane celowo, wymagany jest system plików z odpowiednimi gwarancjami. Nie dodano mniej bezpiecznego fallbacku publikacji na FAT/udziałach sieciowych. |
| X26 | **Doprecyzowane publiczne użycie.** Przewodnik pokazuje environment z wybranego scope'u oraz formaty czasu i pola list_xml. Receipt jest weryfikowany na granicy publikacji/zatwierdzenia, claim przez fencing i zakres. Nie jest błędem samo rozdzielenie konstrukcji transportowego obiektu od jego walidacji w kontekście; przebudowę wszystkich publicznych wyników na nowe klasy pozostawiono poza poprawkami. |
| X27 | **Niepotwierdzony jako defekt publikacji.** Konfiguracja używa release-type python i changelog-type github; notatki powstają z commitów, w tym feat dodającego XML. W repo nie znaleziono mechanizmu dopisującego wydania na końcu pliku, o którym mówi raport. Doprecyzowano migrację w Unreleased, bez ręcznego tworzenia wydania ani deklaracji publikacji. |

## Dodatkowe testy istotne dla bezpieczeństwa

Dodano odczyt obciętego XML z odrzuceniem hasha, publikację przegrywającego pliku
o innej treści bez nadpisania zwycięzcy, odrzucenie receiptu z innym hashem,
kontrolę jittera, anulowanie po utrwaleniu claimu oraz rzeczywiste zwolnienie
zasobów systemowych. Pokrycie linii nie zastępuje tych asercji zachowania.

Pomiar wydajności dodatkowo wykrył wybór indeksu `xml_claim_expired` do zliczania
gotowości po szerokim prefiksie tożsamości, zamiast punktowego dopasowania
dokumentu. Złączenia raportów, backfillu i odzyskiwania wskazują teraz indeks
klucza dokumentu. Osobny test sprawdza plan zliczania; benchmark RSS na 50 tys.
i 500 tys. zadań potwierdza również, że raportowanie nadal kończy się poprawnie.
`tools/benchmark_invoice_xml_claims.py` rozdziela czas SELECT i pełnego claimu
z trwałym COMMIT; liczby nie obiecują stałego kosztu fsync na dowolnym dysku.

Review nie zmienia warunku wydania: live KSeF TEST na dokładnym wheelu musi
przejść w uprawnionym środowisku. Lokalny mock HTTP ani naprawa manifestu
nie są dowodem przejścia tego testu.
