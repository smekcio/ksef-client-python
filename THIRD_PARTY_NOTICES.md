# Noty prawne (third-party)

Ten projekt zawiera zewnętrzne pliki XSD używane do walidacji FA(3).

## Schemy XSD KSeF FA(3)

Pliki:

- `src/ksef_client/documents/fa3/schemas/schemat_FA(3)_v1-0E.xsd`
- `src/ksef_client/documents/fa3/schemas/StrukturyDanych_v10-0E.xsd`
- `src/ksef_client/documents/fa3/schemas/ElementarneTypyDanych_v10-0E.xsd`
- `src/ksef_client/documents/fa3/schemas/KodyKrajow_v10-0E.xsd`

Pochodzenie:

- repozytorium dokumentacji KSeF: `https://github.com/CIRFMF/ksef-docs`
- katalog schem FA: `https://github.com/CIRFMF/ksef-docs/tree/main/faktury/schemy/FA`
- strona informacyjna KSeF (FA(3)): `https://ksef.podatki.gov.pl/informacje-ogolne-ksef-20/struktura-logiczna-fa-3/`

Cel przechowywania plików w repo:

- deterministyczna walidacja XML,
- odtwarzalność testów i CI,
- brak zależności runtime od dostępności zewnętrznych URL.

Data weryfikacji źródeł:

- `2026-05-16`

## Uwagi

Projekt nie rości sobie praw autorskich do powyższych schem.
