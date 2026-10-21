# Odczyt FA(3): XML → model

Moduł `ksef_client.documents.fa3.parse` zamienia dokument FA(3) (np. pobrany z KSeF) na
`FA3Invoice` — ten sam model, którego używają buildery i `invoice_to_xml`. Dzięki temu możesz
odczytać fakturę, przeanalizować ją, porównać z własnym rejestrem i w razie potrzeby
wygenerować XML ponownie.

```python
from pathlib import Path

from ksef_client.documents.fa3 import parse_invoice_xml

invoice = parse_invoice_xml(Path("fa.xml").read_bytes())

print(invoice.invoice_number, invoice.issue_date, invoice.total_gross)
for line in invoice.lines:
    print(line.description, line.quantity, line.effective_net_amount)
```

To samo przez model:

```python
from ksef_client.documents.fa3 import FA3Invoice

invoice = FA3Invoice.from_xml(xml_bytes)
assert invoice.to_xml()  # ponowna serializacja
```

## Co jest odczytywane

- nagłówek i rodzaj faktury (`VAT`, `UPR`, `KOR`, `ZAL`, `ROZ`, `KOR_ZAL`, `KOR_ROZ`),
- strony (`Podmiot1`, `Podmiot2`, `Podmiot3`, `PodmiotUpowazniony`) wraz z adresami,
  kontaktami, EORI, numerem klienta, rolą i udziałem,
- pozycje: opis, ilość, jednostka, ceny, rabat, identyfikatory (GTIN/PKWiU/CN/PKOB/indeks),
  GTU, procedura, akcyza, kurs waluty, `StanPrzed`, `P_12_Zal_15`, `P_12_XII`,
- adnotacje: split payment, metoda kasowa, samofakturowanie, odwrotne obciążenie, zwolnienie,
  nowe środki transportu (lądowe/wodne/powietrzne), procedura marży,
- korekta: przyczyna, typ, okres, numery faktur korygowanych, `Podmiot1K`/`Podmiot2K`,
  `P_15ZK` i kurs,
- zaliczki (`ZaliczkaCzesciowa`) i faktury zaliczkowe (`FakturaZaliczkowa`),
- rozliczenie (`Rozliczenie`), płatność (`Platnosc`) z terminami, rachunkami, skontem,
- warunki transakcji: umowy, zamówienia, partie towaru, transport (z przewoźnikiem i adresami),
- zamówienie (`Zamowienie`) z pozycjami,
- stopka i załącznik (bloki, tabele, metadane, sumy),
- `WZ`, `FP`, `TP`, `ZwrotAkcyzy`, `KursWalutyZ`, dodatkowe opisy, `P_1M`, `P_6`, `OkresFa`.

## Gwarancje i granice

### Roundtrip

Dla dokumentów zbudowanych przez SDK (i generalnie dla poprawnych FA(3) w zakresie modelu)
zachodzi:

```python
parse_invoice_xml(invoice.to_xml()).to_xml() == invoice.to_xml()   # poza Naglowek/DataWytworzeniaFa
```

Testy `tests/test_fa3_parse.py` weryfikują to dla wszystkich rodzajów faktur, adnotacji,
płatności, transportu, zamówień, załączników i korekt.

### Elementy nieobsługiwane

Nieznane elementy nie są po cichu pomijane — trafiają do `invoice.warnings` z nazwą i ścieżką:

```python
for warning in invoice.warnings:
    print(warning.message)
```

Parser **nie** jest odwzorowaniem bezstratnym: `raw_extensions` nie jest odtwarzane przez
serializator, więc elementów spoza modelu nie da się z powrotem wyemitować.

Liczba ostrzeżeń jest ograniczona do `MAX_PARSE_WARNINGS` (100). Dokument z milionem
nieznanych elementów nie zbuduje miliona obiektów — po przekroczeniu limitu `invoice.warnings`
zawiera 100 wpisów i jedno ostrzeżenie o obcięciu.

### Przestrzeń nazw

Elementy są dopasowywane po **pełnym tagu** w przestrzeni FA(3), nie po samej nazwie lokalnej.
Dokument, w którym `<P_2>` (albo inny element) leży w obcej przestrzeni nazw, nie przemyci
wartości: parser zgłosi brak wymaganego elementu i doda ostrzeżenie o nieobsługiwanym tagu.

### Zamówienie bez stawki

`P_12Z` jest w schemacie opcjonalne. Gdy dokument go nie podaje, `OrderLine.tax` ma wartość
`None` — parser **nie wymyśla** stawki 23%. Ponowna serializacja również nie dodaje wtedy
`P_12Z`, więc dokument pozostaje zgodny z wejściem.

### Terminy płatności

`PaymentTerms.due_dates` to skrót dla terminów bez opisu. Parser zapisuje **wszystkie** terminy
w `due_terms` (z `term_description=None` dla samych dat), bo tylko tak da się zachować kolejność
mieszanych terminów z XML. `due_dates` pozostaje puste; serializator i tak łączy oba źródła,
więc XML roundtrip jest identyczny.

### Zaliczki — stawka VAT

XML `ZaliczkaCzesciowa` nie zawiera stawki VAT; trafia ona tylko do `P_13_x`/`P_14_x`.
Parser wnioskuje ją z różnicy między podsumowaniem a wierszami:

- jedna stawka i jeden koszyk → stawka jest odtwarzana dokładnie (np. 8%),
- kilka koszyków, faktura rozliczająca (podsumowanie jest skalowane) albo brak
  jednoznacznego dopasowania → parser używa **23%** (tak samo jak builder bez podanej stawki)
  i dodaje ostrzeżenie. To świadoma decyzja: lepiej jawnie ostrzec niż zgadywać stawkę
  podatkową.

### Marża

Wiersz procedury marży nie niesie `P_11` (podstawą jest marża, nie obrót). Jeśli wiersz marży
jest jeden, parser przypisuje mu kwotę z `P_13_11`; przy kilku wierszach kwoty nie da się
podzielić bez zgadywania, więc zostają zera, a faktura dostaje ostrzeżenie. Gdy na fakturze
są zaliczki marży, ich kwota jest już częścią `P_13_11` i wiersze nie są modyfikowane.

### Daty i czasy

Daty (`P_1`, `P_6`, `P_6A`, `P_22A`, terminy płatności) są odczytywane jako `date`. `xs:date`
dopuszcza strefę czasową, więc `2026-03-01Z` i `2026-03-01+02:00` dają `date(2026, 3, 1)`.
Znaczniki czasu (transport) są normalizowane do UTC — `2026-01-01T10:00:00+02:00` i `...08:00Z`
dadzą ten sam `datetime`, więc ponowna serializacja może zapisać równoważny, ale nie identyczny
tekst.

## Bezpieczeństwo

- deklaracje `DOCTYPE`/`ENTITY` są odrzucane (`FA3ParseError`) **w każdym kodowaniu** —
  dokument jest najpierw parsowany przez `expat`, który sam rozpoznaje UTF-8/UTF-16, więc
  obejście przez zmianę kodowania nie działa, a encje nie są rozwijane,
- komentarz zawierający literalny tekst `<!DOCTYPE` nie jest błędem (kontrola działa na
  poziomie parsera, nie na bajtach),
- obowiązuje limit rozmiaru `MAX_XML_BYTES` (20 MiB),
- liczba ostrzeżeń jest ograniczona (`MAX_PARSE_WARNINGS`), więc dokument z milionem
  nieznanych elementów nie wyczerpie pamięci,
- dla wejścia `str` deklaracja kodowania z prologu jest ignorowana — tekst jest już
  zdekodowany, więc parser koduje go do UTF-8 i nie odczytuje go ponownie jako Latin-2
  (wejście `bytes` nadal jest dekodowane zgodnie z deklaracją),
- liczby muszą być zapisane dziesiętnie — notacja wykładnicza (`1e5`) jest odrzucana,
  tak jak wymaga tego XSD `decimal`,
- komunikaty błędów pokazują oczyszczony podgląd wartości (znaki sterujące → `?`, długość
  ograniczona), więc logowanie wyjątku nie przenosi surowych sekwencji terminala do logów,
- parser nie pobiera niczego z sieci i nie rozwiązuje zewnętrznych encji.

## Błędy

Wszystkie problemy to `FA3ParseError` (podklasa `ValueError`) z komunikatem wskazującym
ścieżkę elementu, np.:

```
Faktura/Fa/FaWiersz[1]/P_8B: 'abc' nie jest liczbą.
Faktura/Podmiot2: identyfikator unijny wymaga jednocześnie KodUE i NrVatUE.
```

Typowe przyczyny: brak wymaganego elementu, zły format liczby/daty, nieznany kod stawki,
nieznana rola podmiotu, dokument niebędący FA(3).

## Przykład: pobranie z KSeF i analiza

```python
from ksef_client import models as m

content = client.invoices.get_invoice_bytes(ksef_number, access_token=access_token)
invoice = parse_invoice_xml(content.content)

print(invoice.seller.name, invoice.buyer.name)
print("netto", invoice.total_net, "VAT", invoice.total_vat, "brutto", invoice.total_gross)
print("do zapłaty", invoice.summary_gross)

# porównanie z własnym rejestrem
assert invoice.invoice_number == expected_number
```

## Powiązane

- budowa i serializacja: [`docs/fa3-sdk.md`](fa3-sdk.md),
- walidacja XSD: `validate_fa3_xml_xsd`,
- przykłady: [`docs/examples/`](examples/README.md).
