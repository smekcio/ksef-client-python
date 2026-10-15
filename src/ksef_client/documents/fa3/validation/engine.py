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
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING

from ....utils.datetime_parsing import parse_api_datetime
from .facets import (
    _DECIMAL_TEXT,
    ELEMENT_FACETS,
    REQUIRED_IN_ANCESTOR,
    REQUIRED_IN_PARENT,
    Facet,
    FacetKind,
    fixed_value,
    occurrence_limit,
)

if TYPE_CHECKING:
    from xml.etree.ElementTree import Element

_NAMESPACE_OPEN = "{"


def _local_name(tag: object) -> str:
    """Zwraca nazwę lokalną elementu (bez przestrzeni nazw).

    ``tag`` bywa obiektem, a nie łańcuchem, gdy drzewo zbudował ``lxml`` albo
    ``ET.TreeBuilder(insert_comments=True)``: komentarze i instrukcje
    przetwarzania mają ``tag`` będący funkcją. Taki węzeł nie jest elementem
    FA(3) i nie może wywracać publicznego walidatora.
    """
    if not isinstance(tag, str):
        return ""
    if tag.startswith(_NAMESPACE_OPEN):
        return tag.split("}", 1)[1]
    return tag


def _is_fa3_element(tag: object) -> bool:
    """Czy element należy do przestrzeni nazw FA(3) (pomijamy np. `xsi`)."""
    return isinstance(tag, str) and tag.startswith(_NAMESPACE_OPEN)


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
    # Schemat wymusza wzorzec `-?([1-9]\d{0,N}|0)(\.\d{1,M})?`: brak zer
    # wiodących, brak wykładnika, brak kropki bez cyfr. `Decimal("007.50")`
    # przechodził przez samą kontrolę precyzji i dopiero KSeF go odrzucał.
    if not _DECIMAL_TEXT.fullmatch(value):
        issues.append(
            FacetIssue(
                path,
                element,
                f"wartość {value!r} nie pasuje do zapisu liczby wymaganego przez "
                f"schemat (bez zer wiodących, bez wykładnika, {facet.xsd_type})",
            )
        )
        return issues
    if facet.integer_digits is not None:
        integer_part = value.lstrip("-").split(".", 1)[0]
        if len(integer_part) > facet.integer_digits:
            issues.append(
                FacetIssue(
                    path,
                    element,
                    f"wartość {value!r} ma {len(integer_part)} cyfr części całkowitej, "
                    f"a schemat dopuszcza {facet.integer_digits} ({facet.xsd_type})",
                )
            )
    if facet.total_digits is not None:
        # `xsd:totalDigits` liczy wszystkie cyfry wartości (bez znaku i separatora),
        # a wcześniej nie był sprawdzany w ogóle — `TNaturalny` (`totalDigits=14`)
        # i typy kwotowe (`totalDigits=18/22`) przepuszczały zbyt długie liczby.
        digits = sum(character.isdigit() for character in value.lstrip("-").replace(".", ""))
        if digits > facet.total_digits:
            issues.append(
                FacetIssue(
                    path,
                    element,
                    f"wartość {value!r} ma {digits} cyfr, a schemat dopuszcza "
                    f"{facet.total_digits} ({facet.xsd_type})",
                )
            )
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
    return parse_api_datetime(value)


def _parse_datetime(value: str) -> datetime | None:
    """Parsuje datę lub znacznik czasu z XML (``Z`` i brak strefy => UTC).

    Używa wspólnego parsera API, więc 7-cyfrowy ułamek sekundy (którego
    ``datetime.fromisoformat`` na Pythonie 3.10 nie przyjmuje) jest obsługiwany
    tak samo na każdej wspieranej wersji Pythona — wcześniej poprawny znacznik
    ``xsd:dateTime`` był na 3.10 zgłaszany jako „nie jest poprawną datą".
    """
    try:
        return parse_api_datetime(value)
    except ValueError:
        return None


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


def _illegal_xml_characters(text: str) -> list[int]:
    """Zwraca kody znaków spoza produkcji ``Char`` XML 1.0 (bez duplikatów).

    XML 1.0 dopuszcza ``#x9``, ``#xA``, ``#xD``, ``#x20``-``#xD7FF``,
    ``#xE000``-``#xFFFD`` oraz ``#x10000``-``#x10FFFF``. Wszystko inne (np.
    ``\\x0b`` wklejone z PDF-a albo ``\\x00``) sprawia, że ``ET.tostring``
    zwraca bajty, których nie zaakceptuje żaden parser — a KSeF tym bardziej.
    """
    illegal: list[int] = []
    seen: set[int] = set()
    for character in text:
        code = ord(character)
        if code in seen:
            continue
        allowed = (
            code in (0x09, 0x0A, 0x0D)
            or 0x20 <= code <= 0xD7FF
            or 0xE000 <= code <= 0xFFFD
            or 0x10000 <= code <= 0x10FFFF
        )
        if not allowed:
            seen.add(code)
            illegal.append(code)
    return illegal


def _apply_whitespace(value: str, mode: str) -> str:
    """Stosuje ``xsd:whiteSpace`` typu bazowego, tak jak robi to walidator XSD.

    Schemat liczy długość i dopasowuje wzorce do wartości PO tej normalizacji:

    * ``preserve`` (``xsd:string``) — bez zmian: ``<NIP> 1111111111</NIP>`` jest
      niezgodny ze schematem i musi zostać zgłoszony,
    * ``replace`` (``xsd:normalizedString``) — ``\\t``/``\\n``/``\\r`` na spację,
    * ``collapse`` (``xsd:token``, typy liczbowe i daty) — dodatkowo zwinięcie
      powtórzonych spacji i obcięcie skrajnych.
    """
    if mode == "collapse":
        return " ".join(value.split())
    if mode == "replace":
        return value.replace("\t", " ").replace("\n", " ").replace("\r", " ")
    return value


def _check_value(element: Element, name: str, path: str) -> list[FacetIssue]:
    """Sprawdza tekst elementu: typ, słownik, wzorzec i znaki dozwolone w XML."""
    entry = ELEMENT_FACETS.get(name)
    if entry is None:
        return []
    raw_text = element.text
    # `Element.text` bywa dowolnym obiektem, jeśli drzewo zbudowano ręcznie
    # (np. wstawiono model zamiast łańcucha) — walidujemy wyłącznie tekst.
    # `None` oznacza jednak element pusty (`<Nazwa/>`) i TAKI przypadek musi
    # przejść przez walidację: schemat wymaga tam `minLength=1`.
    if raw_text is None:
        text = ""
    elif isinstance(raw_text, str):
        text = raw_text
    else:
        return []

    illegal = _illegal_xml_characters(text)
    if illegal:
        # Znaki spoza produkcji `Char` XML 1.0 dają bajty, których nie przyjmie
        # żaden parser — dalsze sprawdzanie tej wartości nie ma sensu.
        return [
            FacetIssue(
                path,
                name,
                "wartość zawiera znaki niedozwolone w XML 1.0 "
                f"({', '.join(f'U+{code:04X}' for code in illegal)})",
            )
        ]

    # Tryb białych znaków bierzemy z typu bazowego w schemacie: `xsd:token`
    # i typy liczbowe zwijają spacje, ale `xsd:string` (np. `TNrNIP`, `TNrRB`)
    # ich NIE zwija — mierzenie tam wartości obciętej przepuszczałoby dokument,
    # który KSeF odrzuci (`<NIP> 1111111111</NIP>`).
    value = _apply_whitespace(text, entry.facet.whitespace)

    # Pusty tekst nie jest „brakiem wartości": schemat wymaga `minLength=1`,
    # więc `<Klucz/>` musi zostać zgłoszony, a nie pominięty.
    issues = _check_text(value, entry.facet, path, name)
    if (
        entry.facet.date_format is not None
        and value
        # Gdy wartość nie jest datą w ogóle, `_check_date_range` już to zgłosił —
        # drugi komunikat o formacie tylko zaciemnia obraz.
        and not any("nie jest poprawną datą" in issue.message for issue in issues)
    ):
        # `date_format` był w tabeli faset zadeklarowany, ale nigdy sprawdzany:
        # `2026-4-1` albo `20260401` przechodziło kontrolę typu DATA (parser API
        # jest tolerancyjny), a odrzucał je dopiero schemat/KSeF.
        issues.extend(_check_date_format(value, entry.facet, path, name))
    if entry.pattern is not None and not entry.pattern.fullmatch(value):
        issues.append(
            FacetIssue(
                path,
                name,
                f"wartość {value!r} nie pasuje do formatu: {entry.pattern_hint}",
            )
        )
    return issues


def _check_date_format(value: str, facet: Facet, path: str, name: str) -> list[FacetIssue]:
    """Sprawdza wartość typu data/data-czas zgodnie z `date_format` fasetu.

    `TDataCzas` to w schemacie `xsd:dateTime`, w którym offset strefy jest
    OPCJONALNY — dlatego format z `%z` traktujemy jako „offset dozwolony", a nie
    wymagany. Wartości spoza kalendarza (`2026-4-1`, `2026-13-45`) odrzuca
    wcześniej `_check_date_range` przez wspólny parser API; tutaj domykamy
    przypadki, które ten parser przyjmuje, a schemat nie (`20260401`,
    `2026-04-01 08:30:00`).
    """
    assert facet.date_format is not None
    candidates = [facet.date_format]
    if facet.date_format.endswith("%z"):
        candidates.append(facet.date_format.replace("%z", ""))
    for candidate in candidates:
        try:
            datetime.strptime(value, candidate)
        except ValueError:
            continue
        return []
    return [
        FacetIssue(
            path,
            name,
            f"wartość {value!r} nie jest poprawną datą w formacie {facet.date_format}",
        )
    ]


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


def _check_required(
    present: set[str], parent_name: str, path: str
) -> list[FacetIssue]:
    """Zgłasza brak elementów wymaganych w danym rodzicu.

    Poza płaską tabelą ``REQUIRED_IN_PARENT`` sprawdzane są wymagania zależne od
    przodka (``REQUIRED_IN_ANCESTOR``) — ta sama nazwa ``DaneIdentyfikacyjne``
    występuje w kilku typach, a ``Nazwa`` jest obowiązkowa tylko w ``TPodmiot1``.
    """
    issues = [
        FacetIssue(path, child, f"brak wymaganego elementu {child} w {parent_name}")
        for parent, child in sorted(REQUIRED_IN_PARENT)
        if parent == parent_name and child not in present
    ]
    for ancestor, parent, child in sorted(REQUIRED_IN_ANCESTOR):
        if parent != parent_name or child in present:
            continue
        if not path.endswith(f"/{ancestor}/{parent}"):
            continue
        issues.append(
            FacetIssue(
                path,
                child,
                f"brak wymaganego elementu {child} w {ancestor}/{parent}",
            )
        )
    return issues


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
        fixed = fixed_value(parent_name, name)
        if fixed is not None and isinstance(child.text, str) and child.text != fixed:
            # `xsd:element/@fixed` wymusza dokładnie jedną wartość, niezależnie od
            # słownika typu. `Podmiot1/PrefiksPodatnika` ma `fixed="PL"`, choć jego
            # typ `TKodyKrajowUE` dopuszcza 28 kodów — bez tej kontroli `DE`
            # przechodziło przez słownik, a dokument odrzucał dopiero KSeF.
            issues.append(
                FacetIssue(
                    child_path,
                    name,
                    f"wartość {child.text!r} musi być równa {fixed!r} — schemat ma dla "
                    f"tego elementu w {parent_name} stałą wartość",
                )
            )
        else:
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
