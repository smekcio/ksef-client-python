# Znaczniki czasu z API (`ksef_client.utils.datetime_parsing`)

API KSeF zwraca znaczniki czasu z **siedmioma** cyframi części ułamkowej, np.:

```text
2025-10-11T12:23:56.0154302+00:00
2024-07-11T12:23:56.0154302+00:00
```

`datetime.datetime.fromisoformat()` przyjmuje na Pythonie 3.10 tylko 3 albo 6 cyfr, więc bez
normalizacji taki znacznik jest **nieparsowalny na najniższej wspieranej wersji** Pythona
(`requires-python = ">=3.10"`). Skutki były ciche i poważne:

* filtr ważności certyfikatów uznawał **wygasły** certyfikat za aktualny (a `max()` wybierał
  pierwszy element listy zamiast najnowszego certyfikatu),
* sortowanie punktów HWM wybierało starszą datę, więc przyrostowy eksport pobierał faktury ponownie,
* walidacja zakresu dat odrzucała poprawny znacznik zwrócony przez API.

Ten moduł jest **jednym** miejscem, w którym odbywa się normalizacja — korzystają z niego
`clients.security`, `clients.invoices`, `services.hwm`, `utils.collective_identifier`,
`documents.fa3.validation.engine` oraz oba moduły CLI.

## `normalize_api_timestamp(value: str) -> str`

Sprowadza ułamek sekundy do **dokładnie 6 cyfr** (dłuższy obcina, krótszy dopełnia zerami) i zamienia
końcowe `Z`/`z` na `+00:00`. Funkcja jest idempotentna i nie zmienia wartości znacznika: `datetime`
przechowuje mikrosekundy, więc obcinanie jest bezstratne dla typowego użycia.

```python
from ksef_client.utils import normalize_api_timestamp

normalize_api_timestamp("2025-10-11T12:23:56.0154302+00:00")
# '2025-10-11T12:23:56.015430+00:00'
```

## `parse_api_datetime(value: str) -> datetime`

Parsuje znacznik i zwraca `datetime` **w UTC**. Wartość bez informacji o strefie jest interpretowana
jako UTC (API zwraca czasy w UTC, a porównania muszą być wykonywane na wartościach świadomych strefy).
Dla wartości nieparsowalnej podnosi `ValueError`.

```python
from ksef_client.utils import parse_api_datetime

parse_api_datetime("2025-10-11T12:23:56.0154302+00:00")
# datetime.datetime(2025, 10, 11, 12, 23, 56, 15430, tzinfo=datetime.timezone.utc)
```

## `try_parse_api_datetime(value: str | None) -> datetime | None`

To samo, ale zwraca `None` dla wartości nieparsowalnej — dla miejsc, w których brak możliwości
sparsowania daty jest sam w sobie informacją. Filtr ważności certyfikatu musi wtedy uznać certyfikat
za **nie**aktualny, a nie za aktualny.

```python
from ksef_client.utils import try_parse_api_datetime

assert try_parse_api_datetime("nie-data") is None
```

## Obsługiwane zapisy

| Zapis | Obsługa |
| --- | --- |
| `YYYY-MM-DDTHH:MM:SS+HH:MM` | tak |
| `YYYY-MM-DDTHH:MM:SSZ` (także małe `z`) | tak |
| `YYYY-MM-DDTHH:MM:SS.fff…` (3–9+ cyfr, dowolna długość) | tak (normalizacja do 6 cyfr) |
| `YYYY-MM-DDTHH:MM:SS` (bez strefy → UTC) | tak |
| `YYYY-MM-DD` (sama data) | tak |
| format podstawowy `20250101T000000Z` | nie (API go nie zwraca) |

Powiązane: [Identyfikator zbiorczy](collective-identifier.md), [HWM](../services/hwm.md).
