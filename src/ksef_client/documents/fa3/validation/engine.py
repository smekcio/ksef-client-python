"""Walidacja wygenerowanego XML FA(3) wobec ograniczeń schematu.

Silnik celowo pracuje na **drzewie XML**, a nie na obiektach domenowych. Dzięki
temu jedna implementacja pokrywa wszystkie ścieżki serializacji (typed buildery,
`FA3Draft`/`FA3InvoiceBuilder`, przyszłe), a każdy błąd serializatora ujawnia się
w tym samym miejscu — bez potrzeby powielania reguł per klasa.

Sprawdzane są cztery klasy ograniczeń (wszystkie pochodzą ze schematu, patrz
:mod:`ksef_client.documents.fa3.validation.facets`):

* **długość tekstu** (``xsd:maxLength``/``minLength``),
* **precyzja liczb** (``xsd:fractionDigits``) i zgodność z formatem liczby,
* **słowniki wartości** (``xsd:enumeration``) oraz wzorce (``xsd:pattern``),
* **liczność elementów** (``xsd:maxOccurs``) i elementy wymagane (``minOccurs``).

Walidacja XSD (`xsd_validate=True`) pozostaje ostatecznym arbitrem; ten moduł
działa także bez `lxml` i daje komunikaty z konkretną ścieżką elementu, zamiast
surowego błędu `SCHEMAV_CVC_*`.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING

from .facets import (
    ELEMENT_FACETS,
    REQUIRED_IN_PARENT,
    Facet,
    FacetKind,
    occurrence_limit,
)

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

_NAMESPACE_OPEN = "{"


def _local_name(tag: str) -> str:
    """Zwraca nazwę lokalną elementu (bez przestrzeni nazw)."""
    if tag.startswith(_NAMESPACE_OPEN):
        return tag.split("}", 1)[1]
    return tag


def _is_fa3_element(tag: str) -> bool:
    """Czy element należy do przestrzeni nazw FA(3) (pomijamy np. `xsi`)."""
    return tag.startswith(_NAMESPACE_OPEN)


@dataclass(frozen=True)
class FacetIssue:
    """Pojedyncze naruszenie ograniczenia schematu.

    ``path`` to ścieżka elementu w drzewie (np. ``Fa/FaWiersz[2]/P_9A``), dzięki
    czemu komunikat wskazuje konkretne miejsce w dokumencie.
    """

    path: str
    element: str
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


def _parse_decimal(text: str) -> Decimal | None:
    try:
        value = Decimal(text)
    except (InvalidOperation, ValueError):
        return None
    return value if value.is_finite() else None


def _decimal_places(number: Decimal) -> int:
    """Liczba miejsc po przecinku w zapisie liczby."""
    exponent = number.as_tuple().exponent
    if isinstance(exponent, int) and exponent < 0:
        return -exponent
    return 0


def _check_text(value: str, facet: Facet, path: str, element: str) -> list[FacetIssue]:
    """Sprawdza wartość tekstową wobec typu zadeklarowanego w schemacie."""
    issues = _check_date_range(value, facet, path, element)

    if facet.allowed is not None:
        if value not in facet.allowed:
            issues.append(
                FacetIssue(
                    path,
                    element,
                    f"wartość {value!r} nie należy do słownika ({facet.describe()})",
                )
            )
        return issues

    if facet.kind is FacetKind.STRING:
        length = len(value)
        if facet.lengths is not None:
            if length not in facet.lengths:
                issues.append(
                    FacetIssue(
                        path,
                        element,
                        f"długość {length} jest niedozwolona ({facet.describe()}, "
                        f"{facet.xsd_type})",
                    )
                )
        elif facet.max_length is not None and length > facet.max_length:
            issues.append(
                FacetIssue(
                    path,
                    element,
                    f"długość {length} przekracza maksimum {facet.max_length} ({facet.xsd_type})",
                )
            )
        if (
            facet.lengths is None
            and facet.minimum_length is not None
            and length < facet.minimum_length
        ):
            issues.append(
                FacetIssue(
                    path,
                    element,
                    f"długość {length} jest mniejsza niż minimum "
                    f"{facet.minimum_length} ({facet.xsd_type})",
                )
            )
        issues.extend(_check_date_range(value, facet, path, element))
        return issues

    number = _parse_decimal(value)
    if number is None:
        return [
            FacetIssue(
                path,
                element,
                f"wartość {value!r} nie jest poprawną liczbą ({facet.xsd_type})",
            )
        ]

    issues = []
    if facet.kind is FacetKind.INTEGER and number != number.to_integral_value():
        issues.append(FacetIssue(path, element, f"wartość {value!r} musi być liczbą całkowitą"))
    if facet.decimals is not None:
        places = _decimal_places(number)
        if places > facet.decimals:
            issues.append(
                FacetIssue(
                    path,
                    element,
                    f"wartość {value!r} ma {places} miejsc po przecinku, "
                    f"a schemat dopuszcza {facet.decimals} ({facet.xsd_type})",
                )
            )
    if facet.minimum is not None and number < facet.minimum:
        issues.append(
            FacetIssue(
                path,
                element,
                f"wartość {value!r} jest mniejsza od minimum {facet.minimum}",
            )
        )
    if facet.maximum is not None and number > facet.maximum:
        issues.append(
            FacetIssue(
                path,
                element,
                f"wartość {value!r} przekracza maksimum {facet.maximum}",
            )
        )
    return issues


def _parse_bound(value: str) -> datetime:
    """Parsuje granice zakresu daty (obsługuje ``Z`` jako UTC)."""
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _parse_datetime(value: str) -> datetime | None:
    """Parsuje datę lub znacznik czasu z XML (``Z`` i brak strefy => UTC)."""
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _check_date_range(value: str, facet: Facet, path: str, element: str) -> list[FacetIssue]:
    """Sprawdza zakres daty/znacznika czasu (``xsd:minInclusive``/``maxInclusive``).

    Schemat ogranicza daty FA(3) z obu stron (np. ``TData`` od 2016-07-01,
    ``TDataCzas`` od 2021-10-01), więc data spoza zakresu jest odrzucana przez
    KSeF mimo poprawnego formatu. ``xsd:dateTime`` dopuszcza brak strefy
    czasowej — taką wartość traktujemy jak UTC, bo schemat porównuje ją z
    granicami podanymi w UTC.
    """
    if facet.minimum_date is None and facet.maximum_date is None:
        return []

    parsed = _parse_datetime(value)
    if parsed is None:
        return [
            FacetIssue(
                path,
                element,
                f"wartość {value!r} nie jest poprawną datą ({facet.xsd_type})",
            )
        ]

    issues: list[FacetIssue] = []
    if facet.minimum_date is not None and parsed < _parse_bound(facet.minimum_date):
        issues.append(
            FacetIssue(
                path,
                element,
                f"data {value!r} jest wcześniejsza niż minimum "
                f"{facet.minimum_date} ({facet.xsd_type})",
            )
        )
    if facet.maximum_date is not None and parsed > _parse_bound(facet.maximum_date):
        issues.append(
            FacetIssue(
                path,
                element,
                f"data {value!r} jest późniejsza niż maksimum "
                f"{facet.maximum_date} ({facet.xsd_type})",
            )
        )
    return issues


def _check_value(element: Element, name: str, path: str) -> list[FacetIssue]:
    """Sprawdza tekst elementu: typ, słownik i wzorzec."""
    entry = ELEMENT_FACETS.get(name)
    if entry is None:
        return []
    text = element.text
    # `Element.text` może być dowolnym obiektem, jeśli drzewo zbudowano ręcznie
    # (np. wstawiono model zamiast łańcucha) — walidujemy wyłącznie tekst.
    if not isinstance(text, str) or text == "":
        return []

    issues = _check_text(text, entry.facet, path, name)
    if entry.pattern is not None and not entry.pattern.fullmatch(text):
        issues.append(
            FacetIssue(
                path,
                name,
                f"wartość {text!r} nie pasuje do formatu: {entry.pattern_hint}",
            )
        )
    return issues


def _check_occurrences(
    parent_name: str, counter: Counter[str], paths: dict[str, str]
) -> list[FacetIssue]:
    """Zgłasza elementy występujące częściej, niż dopuszcza schemat."""
    issues: list[FacetIssue] = []
    for name, count in counter.items():
        limit = occurrence_limit(parent_name, name)
        if limit is not None and count > limit:
            issues.append(
                FacetIssue(
                    paths[name],
                    name,
                    f"element występuje {count} razy, a schemat dopuszcza "
                    f"maksymalnie {limit} w {parent_name}",
                )
            )
    return issues


def _check_required(present: set[str], parent_name: str, path: str) -> list[FacetIssue]:
    """Zgłasza brak elementów wymaganych w danym rodzicu."""
    return [
        FacetIssue(path, child, f"brak wymaganego elementu {child} w {parent_name}")
        for parent, child in sorted(REQUIRED_IN_PARENT)
        if parent == parent_name and child not in present
    ]


def _walk(element: Element, path: str) -> list[FacetIssue]:
    """Rekurencyjnie waliduje poddrzewo, budując ścieżki i liczniki rodzeństwa."""
    parent_name = _local_name(element.tag)
    children = [child for child in element if _is_fa3_element(child.tag)]
    counter: Counter[str] = Counter(_local_name(child.tag) for child in children)

    issues: list[FacetIssue] = []
    issues.extend(_check_required(set(counter), parent_name, path))
    issues.extend(_check_occurrences(parent_name, counter, _first_paths(path, children)))

    seen: Counter[str] = Counter()
    for child in children:
        name = _local_name(child.tag)
        seen[name] += 1
        child_path = f"{path}/{name}"
        if counter[name] > 1:
            child_path = f"{child_path}[{seen[name]}]"
        issues.extend(_check_value(child, name, child_path))
        issues.extend(_walk(child, child_path))
    return issues


def _first_paths(parent_path: str, children: list[Element]) -> dict[str, str]:
    """Mapa nazwa -> ścieżka pierwszego wystąpienia (do komunikatów o liczności)."""
    paths: dict[str, str] = {}
    for child in children:
        name = _local_name(child.tag)
        paths.setdefault(name, f"{parent_path}/{name}")
    return paths


def validate_xml_facets(root: Element) -> list[FacetIssue]:
    """Waliduje drzewo XML FA(3) wobec ograniczeń schematu.

    Zwraca listę naruszeń w kolejności dokumentu; pusta lista oznacza dokument
    zgodny z tabelą ograniczeń. Nie zwalnia to z walidacji XSD, która sprawdza
    dodatkowo kolejność elementów i pełną strukturę.
    """
    return _walk(root, _local_name(root.tag))
