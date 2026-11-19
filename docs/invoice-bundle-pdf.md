# Wizualizacja PDF faktury FA(3)

Pakiet wysyłki zawiera oryginalny XML i czytelny PDF do podglądu dokumentu. Zainstaluj `pip install "ksef-client[cli,pdf]"`, aby utworzyć pakiet w CLI. Sam moduł Pythona wymaga `pip install "ksef-client[pdf]"`.

```python
from pathlib import Path

from ksef_client.invoice_pdf import render_invoice_pdf

xml = Path("faktura.xml").read_bytes()
Path("faktura.pdf").write_bytes(render_invoice_pdf(xml))
```

Opcjonalny argument `ksef_number` służy do pokazania numeru nadanego przez KSeF. Eksport pakietu podstawia numer z zapisanego stanu wysyłki. Oryginałem pozostaje dołączony XML. PDF służy do odczytu zawartości i nie poświadcza przyjęcia faktury ani jej zgodności ze schemą. Potwierdzenie pochodzi z UPO.

Pierwsza część PDF pokazuje numer, datę wystawienia, dostępne nazwy stron i należność z walutą. Dalej widoczne są pola dokumentu w kolejności XML, również pozycje, płatności, odwołania do faktur korygowanych i dane załączników. Pola zrozumiałe dla użytkownika mają polskie etykiety. Pozostałe zachowują nazwy ze schemy. Wartości kwot i stawek pochodzą z pliku źródłowego.

Wizualizacja powstaje lokalnie, również bez sesji KSeF. Generator osadza font z polskimi znakami. Znaki spoza repertuaru fontu przedstawia kodem Unicode w nawiasach kwadratowych. Układ służy do podglądu danych i nie stanowi wzoru wizualizacji MF do przekazywania faktur poza KSeF. Funkcja obsługuje przestrzeń nazw FA(3), odrzuca DTD i ogranicza koszt przetwarzania do 20 MiB XML, 100 000 elementów, 64 poziomów, 65 536 znaków w pojedynczym polu i 500 stron. Przekroczenie limitu zgłasza błąd przed zwróceniem PDF.
