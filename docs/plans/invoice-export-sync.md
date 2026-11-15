# Import paczek KSeF do archiwum faktur

Jawny tryb eksportu ma używać istniejącego transportu ZIP/TarGz i magazynów SQLite oraz XML. Pierwszy scenariusz odbioru obejmuje wieloletnią historię zakupów. Ten sam przepływ obsłuży bieżące przyrosty oraz pozostałe role. Konsument wywołuje cykl w wybranym harmonogramie. API sync i async mają te same gwarancje.

## Stan i granice transakcji

- Strumień jest określony przez środowisko, uwierzytelniony kontekst, namespace, klucz synchronizacji i kanoniczne filtry. Przechowuje osobno zatwierdzony HWM, początek aktualnego fragmentu oraz stan operacji eksportu. Obserwacje i XML trafiają do istniejącego archiwum z tą samą tożsamością dokumentu.
- Każde zapytanie korzysta z `PermanentStorage`, ograniczenia HWM i okien do 100 dni UTC. Po obcięciu zakres zaczyna się ponownie od `LastPermanentStorageDate`. Łączenie zachowuje wszystkie pozycje o tej samej dacie i deduplikuje po kanonicznym numerze KSeF. Powtórzona granica bez nowych pozycji zatrzymuje cykl jako niekompletny. Pełna paczka pozwala zatwierdzić zweryfikowaną granicę HWM.
- Po utworzeniu eksportu zachowujemy referencję i parametry odszyfrowania przed oczekiwaniem na paczkę. Stan roboczy jest poufny. Dalsze uruchomienie wznawia transfer, a po wygaśnięciu operacji może ponownie utworzyć eksport tego samego niezatwierdzonego fragmentu.
- Zgodność `_metadata.json`, liczby dokumentów, nazw i hashy XML jest warunkiem pokrycia. XML publikujemy po jednym dokumencie przez istniejący magazyn. Zapis do SQLite porównuje wersję stanu, utrwala obserwacje i potwierdza gotowość XML. Plik opublikowany przed przerwaniem procesu jest dostępny do ponownej weryfikacji po restarcie. HWM awansuje po zatwierdzeniu całego fragmentu, a SQLite pozostaje wolne od blokad podczas pobierania lub odczytu plików.

## Odbiór

Testy obejmą restart podczas transferu i importu, odnowienie wygasłej operacji, kilka paczek z dokumentami na identycznej granicy, pustą paczkę, zły hash, brak XML, konkurencję dwóch procesów i kontrolę uprawnień plików roboczych. Porównanie z `sync_documents()` na tym samym zbiorze obejmie liczbę żądań, pamięć i kompletność archiwum.

Źródło kontraktu: [przyrostowe pobieranie faktur CIRF](https://github.com/CIRFMF/ksef-api/blob/ce3670e/pobieranie-faktur/przyrostowe-pobieranie-faktur.md).
