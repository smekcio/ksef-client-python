# Pochodzenie plików XSD FA(3)

Ten katalog zawiera lokalne kopie schem XSD wykorzystywanych przez `ksef-client-python`
do walidacji XML FA(3).

## Dlaczego pliki są w repo

- spójna walidacja między środowiskami,
- powtarzalne testy i CI,
- brak zależności od zewnętrznego hostingu schem podczas uruchomienia.

Walidacja nie wymaga dostępu do sieci: `_schema_resolver` w `xml.py` przechwytuje
zasoby po nazwie pliku i rozwiązuje je do kopii z tego katalogu, również gdy
`schemaLocation` wskazuje adres URL.

## Źródła

- <https://github.com/CIRFMF/ksef-api> (repozytorium MF; link `CIRFMF/ksef-docs` przekierowuje tutaj)
- <https://github.com/CIRFMF/ksef-api/tree/main/faktury/schemy/FA>
- <https://ksef.podatki.gov.pl/informacje-ogolne-ksef-20/struktura-logiczna-fa-3/>
- wzór w CRWDE: `crd.gov.pl/wzor/2025/06/25/13775/` (ID `13775`, opublikowany `2025-06-25`);
  przeglądarka wzoru: <https://crd.e-instytucja.pl/index.php?r=wzor%2Fview&id=13775>

## Dokumentacja opisowa MF (broszura informacyjna)

Najbardziej użyteczne **opisowe** źródło wiedzy o FA(3) to broszura informacyjna MF:
pole po polu, z przykładowymi wartościami, dla każdego elementu schematu
(`Naglowek`, `Podmiot1/2/3`, `PodmiotUpowazniony`, `Fa`, `FaWiersz`, `Rozliczenie`,
`Platnosc`, `WarunkiTransakcji`, `Transport`, `Zamowienie`, `Stopka`).

| Dokument | Język | Objętość | Wersja |
| --- | --- | --- | --- |
| [Broszura informacyjna dotycząca struktury logicznej FA(3)](https://ksef.podatki.gov.pl/media/nuclnu0w/broszura-informacyjna-dotyczaca-struktury-logicznej-fa-3.pdf) | **PL** (wersja podstawowa) | 173 str. | sierpień 2026 |
| [Information sheet on the FA(3) logical structure](https://ksef.podatki.gov.pl/media/f2hnwjk2/information-sheet-on-the-fa-3-logical-structure.pdf) | EN | 174 str. | August 2026 |

Obie wersje są równoważne merytorycznie — to ten sam dokument MF w dwóch językach.

Wszystkie materiały MF (podręczniki KSeF 2.0, broszura, przykłady, tabele trybów wystawiania)
są zebrane na stronie [Pliki do pobrania KSeF 2.0](https://ksef.podatki.gov.pl/pliki-do-pobrania-ksef-20).

### Przykładowe pliki MF

[Przykładowe pliki dla struktury logicznej e-Faktury FA(3)](https://ksef.podatki.gov.pl/media/e5cia0ey/przykladowe-pliki-dla-struktury-logicznej-e-faktury-fa-3.zip)
(ZIP, ~196 KB) zawiera **26 przykładowych faktur XML** oraz PDF z ich opisem.

Wszystkie 26 plików XML przechodzi walidację wobec schematu z tego katalogu
(`validate_fa3_xml_xsd`) — to niezależne potwierdzenie, że lokalna kopia schematu
odpowiada wzorowi MF. Są też dobrym materiałem na fixtures dla testów.

## Odstępstwa od oryginału

Treść schematów odpowiada źródłu, ale **nie wszystkie różnice są formatujące** — stan
zweryfikowano bajtowo wobec oryginałów z `CIRFMF/ksef-api` (porównanie `git-blob-SHA1`,
nie tylko po normalizacji końcówek linii):

| Plik | Różnica wobec źródła |
| --- | --- |
| `schemat_FA(3)_v1-0E.xsd` | Usunięty końcowy whitespace w linii 2258 (w źródle 18 spacji). Poza tym plik identyczny; `schemaLocation` bez zmian. |
| `KodyKrajow_v10-0E.xsd` | Brak różnic — plik jest bajtowo identyczny ze źródłem. |
| `ElementarneTypyDanych_v10-0E.xsd` | Końcówki linii (samotny `CR` → `LF`; 360 wystąpień) oraz **zmienione** `schemaLocation` (ścieżka relatywna → absolutny URL). |
| `StrukturyDanych_v10-0E.xsd` | Końcówki linii (samotny `CR` → `LF`; 845 wystąpień) oraz **zmienione** `schemaLocation` (ścieżka relatywna → absolutny URL). |

Źródła MF używają niespójnych końcówek linii (dwa pliki: samotny `CR`, dwa: `LF`), więc
w repo ujednolicono je do `LF`. **Nie należy wprowadzać tu zmian merytorycznych** —
schemat musi odwzorowywać kontrakt produkcyjny KSeF.

### Adresy `schemaLocation`

Rzeczywisty stan kopii w tym katalogu (nie „wszystkie wskazują URL”):

| Plik | `schemaLocation` w kopii | W oryginale MF |
| --- | --- | --- |
| `schemat_FA(3)_v1-0E.xsd` | absolutny URL do `StrukturyDanych_v10-0E.xsd` | tak samo (URL) |
| `ElementarneTypyDanych_v10-0E.xsd` | absolutny URL do `KodyKrajow_v10-0E.xsd` | `KodyKrajow_v10-0E.xsd` (ścieżka relatywna) |
| `StrukturyDanych_v10-0E.xsd` | absolutny URL do `ElementarneTypyDanych_v10-0E.xsd` | `ElementarneTypyDanych_v10-0E.xsd` (ścieżka relatywna) |
| `KodyKrajow_v10-0E.xsd` | brak | brak |

Skutki, które trzeba znać:

- walidacja w SDK działa bez sieci nie dzięki tym adresom, lecz dlatego, że
  `_schema_resolver` w `xml.py` przechwytuje żądania zasobów i podstawia pliki z tego
  katalogu, dopasowując je po nazwie pliku (`Path(url).name`),
- XSD **wyjęty z paczki** i użyty w narzędziu bez własnego resolvera i bez sieci nie
  skompiluje się: `ElementarneTypyDanych` i `StrukturyDanych` każą wtedy pobrać plik
  z `crd.gov.pl` zamiast wziąć ten leżący obok (`XMLSchemaParseError` przy `include`),
- dotyczy to także `schemat_FA(3)_v1-0E.xsd` — jego `import` do `crd.gov.pl` jest
  absolutny już w źródle MF, więc również oryginał wymaga sieci albo resolvera;
  `KodyKrajow_v10-0E.xsd` nie ma zależności i kompiluje się offline.

Zmiana tych adresów (np. na ścieżki relatywne, tak jak w źródle MF dla
`ElementarneTypyDanych` i `StrukturyDanych`) wymaga świadomej decyzji i aktualizacji tego
README oraz `tests/test_fa3_schemas_integrity.py`, który utrwala obecny stan.

## Rozjazd słowników walut (OpenAPI ↔ XSD)

KSeF publikuje **dwie niezależne listy walut**:

- `CurrencyCode` w OpenAPI — m.in. dla identyfikatorów zbiorczych i filtrów wyszukiwania,
- `TKodWaluty` w `schemat_FA(3)_v1-0E.xsd` — dla walidacji treści faktury.

Listy nie są tożsame. API 2.8.0 dodało do OpenAPI kody **`CNH`, `VED`, `XTS`, `ZWG`,
`SLE`**, których nie ma w schemacie FA(3) — faktura w takiej walucie zostanie
odrzucona przez KSeF.

Moduł `ksef_client.documents.fa3.currency` wykrywa ten rozjazd i zwraca czytelny
komunikat zamiast surowego `SCHEMAV_CVC_ENUMERATION_VALID`:

```python
from ksef_client.documents.fa3 import validate_fa3_currency, openapi_only_currency_codes

openapi_only_currency_codes()  # frozenset({'CNH', 'VED', 'XTS', 'ZWG', 'SLE'})
validate_fa3_currency("PLN")   # OK
validate_fa3_currency("CNH")   # Fa3CurrencyMismatchError z wyjaśnieniem
```

Spójność pilnuje test `tests/test_fa3_currency_consistency.py` — rozszerzenie
rozjazdu wymaga świadomej aktualizacji `_KNOWN_OPENAPI_ONLY_CURRENCIES`.

## Licencja i noty prawne

Szczegóły pochodzenia i kontekstu licencyjnego są opisane w:

- `THIRD_PARTY_NOTICES.md` (w katalogu głównym projektu)
