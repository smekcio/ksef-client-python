"""Wspólne parsowanie znaczników czasu zwracanych przez API KSeF.

API KSeF zwraca znaczniki czasu z **siedmioma** cyframi części ułamkowej
(np. ``2025-10-11T12:23:56.0154302+00:00`` — 33 takie przykłady w snapshocie
OpenAPI, m.in. ``validFrom``/``validTo`` w ``/security/public-key-certificates``
oraz ``startDate`` w ``/auth/sessions``). ``datetime.fromisoformat`` przyjmuje
na Pythonie 3.10 tylko 3 albo 6 cyfr, więc bez normalizacji każdy taki znacznik
staje się nieparsowalny na najniższej wspieranej wersji Pythona
(``requires-python = ">=3.10"``).

Skutki braku normalizacji były realne i ciche: filtr ważności certyfikatów
uznawał **wygasły** certyfikat za aktualny, sortowanie punktów HWM wybierało
starszą datę, a walidacja zakresu dat odrzucała poprawny znacznik API.

Ten moduł jest jednym miejscem, w którym normalizacja się odbywa. Każdy ułamek
sekundy jest sprowadzany do **dokładnie 6 cyfr** (dłuższy obcinany, krótszy
dopełniany zerami), dzięki czemu wynik nie zależy od wersji Pythona ani od
liczby cyfr w odpowiedzi API. Obsługiwany jest format rozszerzony ISO-8601
(``YYYY-MM-DDTHH:MM:SS[.frakcja][Z|±HH:MM]``) oraz sama data. Format podstawowy
(``20250101T000000Z``) nie występuje w API; jego obsługa zależy od interpretera —
``datetime.fromisoformat`` przyjmuje go od Pythona 3.11, na 3.10 kończy się
``ValueError`` (patrz ``docs/utils/datetime-parsing.md``).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

#: Dowolny ułamek sekundy — sprowadzamy go do dokładnie 6 cyfr, bo tyle
#: przechowuje ``datetime`` (``microsecond``), a ``fromisoformat`` na Pythonie
#: 3.10 przyjmuje wyłącznie 3 albo 6 cyfr.
_FRACTION = re.compile(r"\.(\d+)")

__all__ = ["normalize_api_timestamp", "parse_api_datetime", "try_parse_api_datetime"]


def _normalize_fraction(match: re.Match[str]) -> str:
    """Obcina/dopełnia ułamek sekundy do 6 cyfr (bez zmiany wartości liczby)."""
    digits = match.group(1)[:6].ljust(6, "0")
    return f".{digits}"


def normalize_api_timestamp(value: str) -> str:
    """Sprowadza ułamek sekundy do 6 cyfr i zamienia końcowe ``Z`` na ``+00:00``.

    Wartości bez ułamka i bez strefy przechodzą bez zmian — funkcja jest
    idempotentna i nie zmienia znaczenia znacznika: nadmiarowe cyfry są obcinane
    (a nie zaokrąglane), bo ``datetime`` i tak przechowuje tylko mikrosekundy,
    a krótsze ułamki są dopełniane zerami, żeby 4- i 5-cyfrowy zapis nie był
    odrzucany na Pythonie 3.10.
    """
    normalized = value.strip()
    if normalized.endswith(("Z", "z")):
        normalized = f"{normalized[:-1]}+00:00"
    return _FRACTION.sub(_normalize_fraction, normalized)


def parse_api_datetime(value: str) -> datetime:
    """Parsuje znacznik czasu z API KSeF na ``datetime`` w UTC.

    Znacznik bez informacji o strefie jest interpretowany jako UTC — API KSeF
    zwraca czasy w UTC, a porównania (ważność certyfikatu, zakres zapytania)
    muszą być wykonywane na wartościach świadomych strefy.

    :raises ValueError: gdy wartość nie jest poprawnym znacznikiem czasu.
    """
    parsed = datetime.fromisoformat(normalize_api_timestamp(value))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def try_parse_api_datetime(value: str | None) -> datetime | None:
    """Jak :func:`parse_api_datetime`, ale zwraca ``None`` dla wartości złej.

    Do miejsc, w których brak możliwości sparsowania daty jest sam w sobie
    informacją (np. filtr ważności certyfikatu musi wtedy uznać certyfikat
    za NIEaktualny, a nie za aktualny).
    """
    if value in (None, ""):
        return None
    try:
        return parse_api_datetime(str(value))
    except ValueError:
        return None
