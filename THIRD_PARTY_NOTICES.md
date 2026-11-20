# Noty prawne (third-party)

Ten projekt zawiera zewnętrzne pliki XSD używane do walidacji FA(3).

## Schemy XSD KSeF FA(3)

Pliki:

- `src/ksef_client/documents/fa3/schemas/schemat_FA(3)_v1-0E.xsd`
- `src/ksef_client/documents/fa3/schemas/StrukturyDanych_v10-0E.xsd`
- `src/ksef_client/documents/fa3/schemas/ElementarneTypyDanych_v10-0E.xsd`
- `src/ksef_client/documents/fa3/schemas/KodyKrajow_v10-0E.xsd`

Pochodzenie:

- repozytorium dokumentacji KSeF: `https://github.com/CIRFMF/ksef-api` (link `CIRFMF/ksef-docs` przekierowuje tutaj)
- katalog schem FA: `https://github.com/CIRFMF/ksef-api/tree/main/faktury/schemy/FA`
- wzór w Centralnym Repozytorium Wzorów Dokumentów Elektronicznych: `crd.gov.pl/wzor/2025/06/25/13775/`
  (ID `13775`, opublikowany `2025-06-25`, nazwa „FA USTRUKTURYZOWANA FAKTURA VAT")
- strona informacyjna KSeF (FA(3)): `https://ksef.podatki.gov.pl/informacje-ogolne-ksef-20/struktura-logiczna-fa-3/`
- broszura informacyjna MF o strukturze logicznej FA(3): `https://ksef.podatki.gov.pl/media/nuclnu0w/broszura-informacyjna-dotyczaca-struktury-logicznej-fa-3.pdf`

Cel przechowywania plików w repo:

- deterministyczna walidacja XML,
- odtwarzalność testów i CI,
- brak zależności runtime od dostępności zewnętrznych URL.

Data weryfikacji źródeł:

- `2026-05-16`
- źródła i linki ponownie zweryfikowane przy okazji przeglądu błędów (broszura FA(3), przykładowe pliki MF)

## Uwagi

Projekt nie rości sobie praw autorskich do powyższych schem.

## Generator PDF CIRFMF

Pakiet zawiera generator MF 1.1.48, commit d766b7b79486ed401cd40fac27402ffecd672bd7.
Źródło https://github.com/CIRFMF/ksef-pdf-generator. Licencja pliku LICENSE to MIT.
Pełne teksty licencji generatora, zależności i fontów są dołączone do dystrybucji
w `_mf_pdf/LICENSE-MF.txt`, `_mf_pdf/LICENSE-Roboto.txt` i `_mf_pdf/THIRD-PARTY-LICENSES.txt`.
