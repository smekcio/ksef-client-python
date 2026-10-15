"""Walidacja XML FA(3) wobec ograniczeń schematu.

Dwa poziomy testów:

1. **Spójność tabeli ze schematem** — parser XSD wyciąga faktyczne ograniczenia
   i porównuje je z tabelą `ELEMENT_FACETS`. Dzięki temu tabela nie może po cichu
   rozjechać się z kontraktem (test jest jedynym miejscem, w którym wolno
   „tłumaczyć" schemat na kod).
2. **Zachowanie silnika** — walidacja wykrywa naruszenia długości, precyzji,
   słowników, wzorców, liczności i braków elementów wymaganych.
"""

from __future__ import annotations

import functools
import re
from datetime import date
from decimal import Decimal
from pathlib import Path
from typing import Any, cast
from xml.etree import ElementTree as ET

import pytest

from ksef_client.documents.fa3 import (
    BasicInvoiceBuilder,
    InvoiceParty,
    TaxCategory,
)
from ksef_client.documents.fa3.validation import (
    ELEMENT_FACETS,
    OCCURRENCE_LIMITS,
    REQUIRED_IN_ANCESTOR,
    REQUIRED_IN_PARENT,
    Facet,
    FacetKind,
    occurrence_limit,
    validate_xml_facets,
)
from ksef_client.documents.fa3.xml import FA3XmlValidationError, _q

SCHEMAS = Path(__file__).resolve().parents[1] / "src/ksef_client/documents/fa3/schemas"
XSD_FILES = (
    "schemat_FA(3)_v1-0E.xsd",
    "StrukturyDanych_v10-0E.xsd",
    "ElementarneTypyDanych_v10-0E.xsd",
    "KodyKrajow_v10-0E.xsd",
)

_XSD = "{http://www.w3.org/2001/XMLSchema}"

#: Poprawny `LinkDoPlatnosci` — schemat wymaga tu adresu z parametrem `IPKSeF`.
_VALID_PAYMENT_LINK = "https://pay.example.com/invoice?IPKSeF=123abc456DEFG"


# ---------------------------------------------------------------------------
# 1. Spójność tabeli ograniczeń ze schematem
# ---------------------------------------------------------------------------


def _xsd_simple_types() -> dict[str, ET.Element]:
    """Wszystkie `xsd:simpleType` z kompletu schematów, po nazwie."""
    found: dict[str, ET.Element] = {}
    for name in XSD_FILES:
        root = ET.parse(SCHEMAS / name).getroot()
        for node in root.iter(f"{_XSD}simpleType"):
            type_name = node.get("name")
            if type_name:
                found.setdefault(type_name, node)
    return found


def _xsd_restriction_facets(node: ET.Element) -> dict[str, Any]:
    """Wartości `xsd:maxLength`/`fractionDigits`/`enumeration` danego typu."""
    restriction = node.find(f"{_XSD}restriction")
    if restriction is None:
        return {}
    facets: dict[str, Any] = {
        "base": restriction.get("base"),
        "maxLength": None,
        "minLength": None,
        "fractionDigits": None,
        "enumerations": frozenset(),
        "pattern": None,
        "minInclusive": None,
        "maxInclusive": None,
    }
    for child in restriction:
        tag = child.tag.replace(_XSD, "")
        if tag in {"maxLength", "minLength", "fractionDigits", "minInclusive", "maxInclusive"}:
            facets[tag] = child.get("value")
        elif tag == "pattern":
            facets["pattern"] = child.get("value")
        elif tag == "enumeration":
            facets["enumerations"] = facets["enumerations"] | {child.get("value")}
    return facets


def _resolve(type_name: str, types: dict[str, ET.Element], seen: set[str] | None = None):
    """Facety typu prostego wraz z odziedziczonymi, z zachowaniem ``xsd:restriction``.

    W schemacie XSD facet zdefiniowany w typie **pochodnym zastępuje** facet typu
    bazowego (restriction może go tylko zaostrzyć), więc idąc w górę łańcucha
    ``base`` nadpisujemy wartości tylko wtedy, gdy typ pochodny ich nie podał.
    Wcześniejsza wersja scalała je w drugą stronę, przez co ``TZnakowy2``
    (``minLength=0``) dziedziczyło ``minLength=1`` z ``TZnakowy``.
    """
    seen = seen or set()
    if type_name in seen or type_name not in types:
        return {}
    seen.add(type_name)
    facets = dict(_xsd_restriction_facets(types[type_name]))
    base = facets.get("base")
    if base and base not in {
        "xsd:string",
        "xsd:token",
        "xsd:decimal",
        "xsd:integer",
        "xsd:byte",
        "xsd:normalizedString",
        "xsd:dateTime",
        "xsd:date",
    }:
        inherited = _resolve(base, types, seen)
        for key, value in inherited.items():
            if facets.get(key) in (None, frozenset()):
                facets[key] = value
    return facets


@pytest.fixture(scope="module")
def xsd_types() -> dict[str, ET.Element]:
    return _xsd_simple_types()


def test_every_facet_type_exists_in_the_schema(xsd_types: dict[str, ET.Element]) -> None:
    """Każdy `xsd_type` użyty w tabeli musi istnieć w schemacie."""
    unknown = sorted(
        {
            entry.facet.xsd_type
            for entry in ELEMENT_FACETS.values()
            if entry.facet.xsd_type is not None and entry.facet.xsd_type not in xsd_types
        }
    )
    assert not unknown, f"typy spoza schematu: {unknown}"


def test_declared_enumerations_match_the_schema(xsd_types: dict[str, ET.Element]) -> None:
    """Słowniki wartości muszą być identyczne z `xsd:enumeration` schematu."""
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        declared = entry.facet.allowed
        if declared is None:
            continue
        if entry.facet.xsd_type is None:
            continue
        schema_enums = _resolve(entry.facet.xsd_type, xsd_types).get("enumerations") or frozenset()
        if not schema_enums:
            continue
        checked += 1
        if declared != schema_enums:
            mismatches.append(
                f"{element} ({entry.facet.xsd_type}): tabela={sorted(declared)} "
                f"schemat={sorted(schema_enums)}"
            )
    assert checked >= 10, "test nie sprawdził żadnego słownika — sprawdź mapowanie typów"
    assert not mismatches, "\n".join(mismatches)


def test_declared_max_length_matches_the_schema(xsd_types: dict[str, ET.Element]) -> None:
    """`max_length` w tabeli musi zgadzać się z `xsd:maxLength` schematu."""
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        facet = entry.facet
        if facet.kind is not FacetKind.STRING or facet.max_length is None:
            continue
        if facet.xsd_type is None:
            # Ograniczenie inline w schemacie (bez nazwanego typu) — pomijamy
            # w porownaniu z nazwanymi typami, zachowanie pilnuje test silnika.
            continue
        schema_facets = _resolve(facet.xsd_type, xsd_types)
        schema_max = schema_facets.get("maxLength")
        if schema_max is None:
            continue
        checked += 1
        if int(schema_max) != facet.max_length:
            mismatches.append(
                f"{element} ({facet.xsd_type}): tabela={facet.max_length} schemat={schema_max}"
            )
    assert checked >= 10, "test nie sprawdził żadnego limitu długości"
    assert not mismatches, "\n".join(mismatches)


def test_declared_decimals_match_the_schema(xsd_types: dict[str, ET.Element]) -> None:
    """`decimals` w tabeli musi zgadzać się z `xsd:fractionDigits` schematu."""
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        facet = entry.facet
        if facet.decimals is None or facet.xsd_type is None:
            continue
        schema_facets = _resolve(facet.xsd_type, xsd_types)
        schema_fraction = schema_facets.get("fractionDigits")
        if schema_fraction is None:
            continue
        checked += 1
        if int(schema_fraction) != facet.decimals:
            mismatches.append(
                f"{element} ({facet.xsd_type}): tabela={facet.decimals} schemat={schema_fraction}"
            )
    assert checked >= 3, "test nie sprawdził żadnej precyzji"
    assert not mismatches, "\n".join(mismatches)


def test_declared_patterns_accept_schema_valid_samples(xsd_types: dict[str, ET.Element]) -> None:
    """Wzorce w tabeli muszą przepuszczać wartości zgodne ze wzorcem schematu."""
    samples = {
        "NIP": "1111111111",
        "IDWew": "1111111111-00001",
        "NrVatUE": "DE123456",
        "SWIFT": "DEUTDEFF",
        "KRS": "0000111111",
        "REGON": "123456789",
        "IPKSeF": "123abc456DEFG",
        "NrKSeFFaKorygowanej": "1111111111-20260101-AAAAAA-BBBBBB-01",
    }
    for element, sample in samples.items():
        entry = ELEMENT_FACETS[element]
        assert entry.pattern is not None, element
        assert entry.pattern.fullmatch(sample), f"{element}: {sample!r} odrzucone"


def test_ksef_number_pattern_accepts_both_schema_lengths() -> None:
    """Schemat dopuszcza 35 i 36 znaków numeru KSeF (myślnik jest opcjonalny)."""
    entry = ELEMENT_FACETS["NrKSeFFaKorygowanej"]
    assert entry.facet.lengths == frozenset({35, 36})
    for value in (
        "1111111111-20260101-AAAAAA-BBBBBB-01",
        "1111111111-20260101-AAAAAABBBBBB-01",
        "9999999999-20260401-D5FB0C9ED490-9A",
    ):
        assert entry.pattern is not None and entry.pattern.fullmatch(value), value
        assert len(value) in entry.facet.lengths


# ---------------------------------------------------------------------------
# 2. Zachowanie silnika
# ---------------------------------------------------------------------------


def _invoice_xml(**line_kwargs: Any) -> str:
    builder = BasicInvoiceBuilder(invoice_number="FV/FACETS")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2"))
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100", **line_kwargs)
    return builder.build().to_xml().decode("utf-8")


def _tree(**line_kwargs: Any) -> ET.Element:
    return ET.fromstring(_invoice_xml(**line_kwargs))


def test_valid_invoice_has_no_facet_issues() -> None:
    assert validate_xml_facets(_tree()) == []


def test_self_closing_element_is_not_silently_skipped() -> None:
    """`<Nazwa/>` ma `text is None`, ale `minLength=1` nadal obowiązuje.

    Wcześniej silnik zwracał `[]` dla `text is None`, więc samozamykający się
    element wymagany omijał **całą** walidację faset, a dokument wychodził
    z SDK i był odrzucany dopiero przez KSeF (`SCHEMAV_CVC_MINLENGTH_VALID`).
    """
    root = _tree()
    element = root.find(f".//{_q('Podmiot1')}/{_q('DaneIdentyfikacyjne')}/{_q('Nazwa')}")
    assert element is not None
    element.text = None
    issues = validate_xml_facets(root)
    assert any(
        issue.path.endswith("/Nazwa") and "minimum 1" in issue.message for issue in issues
    ), [str(issue) for issue in issues]


def test_buyer_without_name_is_accepted() -> None:
    """`TPodmiot2` ma `<xsd:sequence minOccurs="0">` wokół `Nazwa` (faktura uproszczona).

    Oficjalny `FA_3_Przykład_15.xml` ma `Podmiot2` złożony z samego `NIP`.
    """
    root = _tree()
    identity = root.find(f".//{_q('Podmiot2')}/{_q('DaneIdentyfikacyjne')}")
    assert identity is not None
    name = identity.find(_q("Nazwa"))
    assert name is not None
    identity.remove(name)
    assert validate_xml_facets(root) == []


def test_seller_without_name_is_reported() -> None:
    """`TPodmiot1` wymaga `Nazwa` — brak jest błędem, nie milczeniem."""
    root = _tree()
    identity = root.find(f".//{_q('Podmiot1')}/{_q('DaneIdentyfikacyjne')}")
    assert identity is not None
    name = identity.find(_q("Nazwa"))
    assert name is not None
    identity.remove(name)
    issues = validate_xml_facets(root)
    assert any(
        "brak wymaganego elementu Nazwa" in issue.message and "Podmiot1" in issue.message
        for issue in issues
    ), [str(issue) for issue in issues]


def test_whitespace_padded_value_is_not_over_rejected() -> None:
    """Typy tekstowe schematu to `xsd:token` — białe znaki są zwijane."""
    root = _tree()
    number = root.find(f".//{_q('P_2')}")
    assert number is not None and number.text is not None
    number.text = " " * 250 + number.text
    assert validate_xml_facets(root) == []


#: Białe znaki, które `str.split()`/`str.strip()` zwijają, a `xsd:whiteSpace`
#: i tak NIE: schemat zamienia na spację wyłącznie ``#x9``/``#xA``/``#xD``.
#: ``U+000B`` pomijamy tutaj, bo XML 1.0 w ogóle go nie dopuszcza (osobna reguła).
_NON_XML_SPACES = ("\u00a0", "\u3000", "\u0085", "\u2028")


@functools.lru_cache(maxsize=1)
def _fa3_xsd_schema() -> Any:
    """Skompilowany, bundlowany schemat FA(3) — wzorzec werdyktu dla faset."""
    from lxml import etree

    return etree.XMLSchema(etree.parse(str(SCHEMAS / "schemat_FA(3)_v1-0E.xsd")))


def _xsd_accepts(root: ET.Element) -> bool:
    """Czy schemat FA(3) przyjmuje dokument (walidacja lxml)."""
    from lxml import etree

    document = etree.fromstring(ET.tostring(root, encoding="utf-8"))
    return bool(_fa3_xsd_schema().validate(document))


@pytest.mark.parametrize("space", _NON_XML_SPACES)
@pytest.mark.parametrize("element", ["Nazwa", "P_2"])
def test_unicode_space_does_not_shorten_the_value(element: str, space: str) -> None:
    """``600×NBSP + "A"`` ma dla faset 601 znaków — dokładnie tak, jak liczy XSD.

    Wcześniej `_apply_whitespace` wołało `str.split()` bez argumentu, które
    zwijało także U+00A0/U+3000/U+0085/U+2028, więc wartość malała do jednego
    znaku i dokument z 601 znakami przechodził walidację SDK.
    """
    root = _tree()
    target = root.find(f".//{_q(element)}")
    assert target is not None
    target.text = space * 600 + "A"

    issues = validate_xml_facets(root)

    assert any(
        issue.element == element and "przekracza maksimum" in issue.message for issue in issues
    ), [str(issue) for issue in issues]


@pytest.mark.parametrize("space", _NON_XML_SPACES)
@pytest.mark.parametrize("element", ["Nazwa", "P_2"])
def test_facet_verdict_matches_lxml_for_unicode_spaces(element: str, space: str) -> None:
    """Fasety i walidacja XSD muszą wydać TEN SAM werdykt dla nietypowych spacji."""
    root = _tree()
    target = root.find(f".//{_q(element)}")
    assert target is not None
    target.text = space * 600 + "A"

    reported = any(issue.element == element for issue in validate_xml_facets(root))

    assert reported is True
    assert _xsd_accepts(root) is False


@pytest.mark.parametrize("element", ["Nazwa", "P_2"])
def test_ascii_spaces_are_still_collapsed(element: str) -> None:
    """Kontrola: ``#x20`` nadal jest zwijane, więc 600 spacji to nie 600 znaków."""
    root = _tree()
    target = root.find(f".//{_q(element)}")
    assert target is not None
    target.text = " " * 600 + "A"

    assert validate_xml_facets(root) == []
    assert _xsd_accepts(root) is True


def test_whitespace_preserving_type_still_rejects_padding() -> None:
    """`TNrNIP` bazuje na `xsd:string`, więc spacje NIE są zwijane.

    Mierzenie zawsze wartości obciętej przepuszczało `<NIP> 1111111111</NIP>`:
    SDK emitował dokument, a KSeF odrzucał go facetem `pattern`/`maxLength`.
    """
    root = _tree()
    nip = root.find(f".//{_q('Podmiot2')}//{_q('NIP')}")
    assert nip is not None
    nip.text = " 2222222222"
    issues = validate_xml_facets(root)
    assert any("nie pasuje do formatu" in issue.message for issue in issues), [
        str(issue) for issue in issues
    ]


def _schema_namespaces() -> dict[str, str]:
    """Mapa prefiks -> URI zadeklarowanych w plikach schematu.

    ``ElementTree`` nie udostępnia deklaracji ``xmlns`` w ``attrib`` (zjadają je
    parser), więc czytamy je z tekstu — inaczej typy dziedzinowe (``etd:TData``,
    ``etd:TWybor1``) byłyby nierozwiązywalne.
    """
    namespaces = {"xsd": "http://www.w3.org/2001/XMLSchema"}
    for schema in XSD_FILES:
        text = (SCHEMAS / schema).read_text(encoding="utf-8")
        for match in re.finditer(r'xmlns(?::([A-Za-z0-9_.-]+))?="([^"]+)"', text):
            namespaces.setdefault(match.group(1) or "", match.group(2))
    return namespaces


def _xsd_whitespace_modes() -> tuple[dict[str, set[str]], set[str]]:
    """Tryb `xsd:whiteSpace` dla każdego elementu schematu.

    Zwraca ``(tryby, elementy_kompleksowe)``. Kluczem typu jest pełna nazwa z
    przestrzenią nazw, bo ten sam lokalny typ występuje w kilku schematach
    (np. `TNaturalny` w FA(3) i w typach dziedzinowych).
    """
    builtin = {
        "xsd:string": "preserve",
        "xsd:normalizedString": "replace",
        "xsd:token": "collapse",
        "xsd:decimal": "collapse",
        "xsd:integer": "collapse",
        "xsd:int": "collapse",
        "xsd:byte": "collapse",
        "xsd:date": "collapse",
        "xsd:dateTime": "collapse",
        "xsd:nonNegativeInteger": "collapse",
        "xsd:positiveInteger": "collapse",
        "xsd:anyURI": "collapse",
        "xsd:base64Binary": "collapse",
    }
    namespaces = _schema_namespaces()
    types: dict[tuple[str, str], ET.Element] = {}
    elements: list[tuple[str, ET.Element]] = []

    for schema in XSD_FILES:
        root = ET.parse(SCHEMAS / schema).getroot()
        target = root.get("targetNamespace") or ""
        for node in root.iter(f"{_XSD}simpleType"):
            if node.get("name"):
                types.setdefault((target, node.get("name") or ""), node)
        for node in root.iter(f"{_XSD}element"):
            if node.get("name"):
                elements.append((target, node))

    def split_qualified(target: str, qualified: str) -> tuple[str, str]:
        prefix, _, local = qualified.partition(":")
        if not local:
            return target, prefix
        return namespaces.get(prefix, target), local

    def mode(target: str, qualified: str, seen: frozenset[str]) -> str:
        if qualified in builtin:
            return builtin[qualified]
        uri, local = split_qualified(target, qualified)
        key = f"{uri}|{local}"
        if key in seen:
            return "nieznany"
        node = types.get((uri, local))
        if node is None:
            return "nieznany"
        restriction = node.find(f"{_XSD}restriction")
        if restriction is None:
            union = node.find(f"{_XSD}union")
            if union is not None:
                members = (union.get("memberTypes") or "").split()
                if not members:
                    inline = union.find(f"{_XSD}simpleType/{_XSD}restriction")
                    if inline is not None:
                        return mode(uri, inline.get("base") or "", seen | {key})
                    return "nieznany"
                modes = {mode(uri, member, seen | {key}) for member in members}
                return modes.pop() if len(modes) == 1 else "nieznany"
            return "nieznany"
        explicit = None
        for child in restriction:
            if child.tag == f"{_XSD}whiteSpace":
                explicit = child.get("value")
        return explicit or mode(uri, restriction.get("base") or "", seen | {key})

    modes: dict[str, set[str]] = {}
    complex_elements: set[str] = set()
    for target, node in elements:
        name = node.get("name") or ""
        declared = node.get("type")
        if declared:
            modes.setdefault(name, set()).add(mode(target, declared, frozenset()))
            continue
        inline_simple = node.find(f"{_XSD}simpleType/{_XSD}restriction")
        if inline_simple is not None:
            base = inline_simple.get("base") or ""
            modes.setdefault(name, set()).add(mode(target, base, frozenset()))
            continue
        inline_complex = node.find(f"{_XSD}complexType/{_XSD}simpleContent/{_XSD}extension")
        if inline_complex is not None:
            modes.setdefault(name, set()).add(
                mode(target, inline_complex.get("base") or "", frozenset())
            )
            continue
        complex_elements.add(name)
    return modes, complex_elements


def test_whitespace_mode_matches_the_schema() -> None:
    """`Facet.whitespace` musi odpowiadać `xsd:whiteSpace` typu bazowego.

    Rozjazd w obie strony jest realnym błędem: zbyt surowy tryb odrzuca dokument
    zgodny ze schematem (np. `P_2` z wcięciem), a zbyt łagodny przepuszcza
    `<NIP> 1111111111</NIP>` albo `KodKraju=" PL "`, które XSD odrzuca.
    """
    modes, complex_elements = _xsd_whitespace_modes()
    mismatches: list[str] = []
    checked = 0
    unresolved: list[str] = []
    for element, entry in sorted(ELEMENT_FACETS.items()):
        element_modes = modes.get(element)
        if not element_modes or element_modes == {"nieznany"}:
            unresolved.append(element)
            continue
        checked += 1
        if entry.facet.whitespace not in element_modes:
            mismatches.append(
                f"{element}: tabela={entry.facet.whitespace} schemat={sorted(element_modes)}"
            )
    assert checked >= 200, (
        f"test sprawdził tylko {checked} elementów; nierozwiązane: {sorted(unresolved)}"
    )
    assert not mismatches, "\n".join(mismatches)

    # Kontrola czułości: gdyby wszystko było `collapse`, test nie miałby zębów.
    non_collapse = {
        element
        for element, entry in ELEMENT_FACETS.items()
        if entry.facet.whitespace != "collapse" and element in modes
    }
    assert {"NIP", "KRS", "NrRB", "NrVatUE", "SWIFT", "StopkaFaktury"} <= non_collapse
    assert {"KodKraju", "KodUE", "PrefiksPodatnika", "NrID"} <= {
        element
        for element in non_collapse
        if ELEMENT_FACETS[element].facet.whitespace == "replace"
    }
    _ = complex_elements


def test_comment_and_processing_instruction_do_not_crash() -> None:
    """`validate_xml_facets` jest publiczne i musi przyjąć drzewo z lxml/treebuilder."""
    parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
    root = ET.fromstring(
        _invoice_xml().replace("<Naglowek>", "<!-- komentarz --><?pi test?><Naglowek>", 1),
        parser=parser,
    )
    assert any(not isinstance(child.tag, str) for child in root)
    assert validate_xml_facets(root) == []
    # Węzeł nie-elementowy jako korzeń też nie może wywrócić walidatora.
    assert validate_xml_facets(cast(Any, ET.Comment("x"))) == []


def test_non_string_text_is_ignored() -> None:
    """Ręcznie zbudowane drzewo może mieć w `text` obiekt zamiast łańcucha."""
    root = _tree()
    element = root.find(f".//{_q('P_7')}")
    assert element is not None
    element.text = object()  # type: ignore[assignment]
    assert validate_xml_facets(root) == []


def test_fixed_value_is_enforced_only_in_podmiot1() -> None:
    """`Podmiot1/PrefiksPodatnika` ma `fixed="PL"`, `Podmiot1K` już nie."""
    root = _tree()
    podmiot1 = root.find(_q("Podmiot1"))
    assert podmiot1 is not None
    ET.SubElement(podmiot1, _q("PrefiksPodatnika")).text = "DE"
    issues = validate_xml_facets(root)
    assert any("stałą wartość" in issue.message for issue in issues), [
        str(issue) for issue in issues
    ]

    other = _tree()
    podmiot1k = ET.SubElement(other, _q("Podmiot1K"))
    ET.SubElement(podmiot1k, _q("PrefiksPodatnika")).text = "DE"
    identity = ET.SubElement(podmiot1k, _q("DaneIdentyfikacyjne"))
    ET.SubElement(identity, _q("NIP")).text = "2222222222"
    ET.SubElement(identity, _q("Nazwa")).text = "Stary"
    address = ET.SubElement(podmiot1k, _q("Adres"))
    ET.SubElement(address, _q("KodKraju")).text = "PL"
    ET.SubElement(address, _q("AdresL1")).text = "ul. Stara 1"
    assert validate_xml_facets(other) == []


def test_data_wytworzenia_fa_uses_the_element_restriction() -> None:
    """Element ma własne `minInclusive=2025-09-01`, węższe niż `TDataCzas`."""
    root = _tree()
    created = root.find(f".//{_q('DataWytworzeniaFa')}")
    assert created is not None
    created.text = "2024-01-01T00:00:00Z"
    issues = validate_xml_facets(root)
    assert any("2025-09-01" in issue.message for issue in issues), [
        str(issue) for issue in issues
    ]


def test_empty_nkom_is_legal() -> None:
    """`NKom` to `xsd:extension base="TZnakowy2"` (minLength=0), tak jak `SKom`."""
    assert ELEMENT_FACETS["NKom"].facet.minimum_length == 0
    root = _tree()
    kol = ET.SubElement(root, _q("Kol"))
    ET.SubElement(kol, _q("NKom"))
    assert validate_xml_facets(root) == []


def test_country_code_dictionary_is_enforced() -> None:
    """`TKodKraju` to 254-wartościowy słownik — `XX` musi zostać zgłoszone."""
    root = _tree()
    country = root.find(f".//{_q('Adres')}/{_q('KodKraju')}")
    assert country is not None
    country.text = "XX"
    issues = validate_xml_facets(root)
    assert any(
        issue.element == "KodKraju" and "TKodKraju" in issue.message for issue in issues
    ), [str(issue) for issue in issues]


def test_unknown_vat_rate_is_reported() -> None:
    """Silnik sprawdza słownik `P_12` niezależnie od walidacji biznesowej."""
    root = _tree()
    row = root.find(f".//{_q('FaWiersz')}")
    assert row is not None
    rate = row.find(_q("P_12"))
    assert rate is not None
    rate.text = "17"
    issues = validate_xml_facets(root)
    assert any(issue.element == "P_12" and "słownika" in issue.message for issue in issues)


def test_text_length_overflow_is_reported() -> None:
    root = _tree()
    description = root.find(f".//{_q('P_7')}")
    assert description is not None
    description.text = "x" * 513
    issues = validate_xml_facets(root)
    assert any("513" in issue.message and "P_7" in issue.path for issue in issues)


def test_decimal_precision_overflow_is_reported() -> None:
    """`P_9A` dopuszcza 8 miejsc; 9 musi zostać zgłoszone."""
    root = _tree()
    price = root.find(f".//{_q('P_9A')}")
    assert price is not None
    price.text = "1.123456789"
    issues = validate_xml_facets(root)
    assert any("miejsc po przecinku" in issue.message for issue in issues)


def test_non_numeric_value_is_reported() -> None:
    root = _tree()
    amount = root.find(f".//{_q('P_11')}")
    assert amount is not None
    amount.text = "nie-liczba"
    issues = validate_xml_facets(root)
    assert any("nie jest poprawną liczbą" in issue.message for issue in issues)


def test_out_of_range_percentage_is_reported() -> None:
    root = _tree()
    share_holder = ET.SubElement(ET.SubElement(root, _q("Podmiot3")), _q("Udzial"))
    share_holder.text = "150"
    issues = validate_xml_facets(root)
    assert any("przekracza maksimum 100" in issue.message for issue in issues)


def test_too_many_occurrences_are_reported() -> None:
    """`FaWiersz` ma limit 10 000 — silnik liczy rodzeństwo."""
    root = _tree()
    fa = root.find(_q("Fa"))
    assert fa is not None
    row = fa.find(_q("FaWiersz"))
    assert row is not None
    for _ in range(3):
        fa.append(ET.fromstring(ET.tostring(row)))
    # Zmniejszamy limit w locie, żeby nie budować 10 001 wierszy.
    from ksef_client.documents.fa3.validation import engine as engine_module

    original = engine_module.occurrence_limit
    engine_module.occurrence_limit = lambda parent, child: (
        2 if child == "FaWiersz" else original(parent, child)
    )
    try:
        issues = validate_xml_facets(root)
    finally:
        engine_module.occurrence_limit = original
    assert any("dopuszcza maksymalnie 2" in issue.message for issue in issues)


def test_missing_required_element_is_reported() -> None:
    """Brak `P_15` w `Fa` musi być zgłoszony."""
    root = _tree()
    fa = root.find(_q("Fa"))
    assert fa is not None
    total = fa.find(_q("P_15"))
    assert total is not None
    fa.remove(total)
    issues = validate_xml_facets(root)
    assert any(
        issue.element == "P_15" and "brak wymaganego elementu" in issue.message for issue in issues
    )


def test_pattern_violation_is_reported() -> None:
    root = _tree()
    nip = root.find(f".//{_q('NIP')}")
    assert nip is not None
    nip.text = "123"
    issues = validate_xml_facets(root)
    assert any("nie pasuje do formatu" in issue.message for issue in issues)


def test_payment_link_is_validated_by_facets() -> None:
    """`LinkDoPlatnosci` ma wzorzec w tabeli, więc fasety łapią zły link same.

    Ograniczenie mieszkało wyłącznie w `FA3Invoice.validate()`, więc dokument
    z ręcznie podstawionym linkiem (edycja drzewa, `to_xml(validate=False)`)
    przechodził `validate_xml_facets` i `to_xml(facets=True)` bez sygnału —
    odrzucał go dopiero schemat (a w produkcji KSeF).
    """
    from ksef_client.documents.fa3.validation import FacetIssue

    def _issues(payment_link: str) -> list[FacetIssue]:
        root = _tree()
        fa = root.find(_q("Fa"))
        assert fa is not None
        payment = ET.SubElement(fa, _q("Platnosc"))
        ET.SubElement(payment, _q("LinkDoPlatnosci")).text = payment_link
        return validate_xml_facets(root)

    assert _issues(_VALID_PAYMENT_LINK) == []
    for broken in (
        # Adres http(s), ale bez parametru `IPKSeF`.
        "https://pay.example.com/invoice",
        "http://pay.example.com/invoice",
        # Inny schemat niż `https?` dopuszczony przez wzorzec schematu.
        "ftp://pay.example.com/invoice?IPKSeF=123abc456DEFG",
        # Identyfikator krótszy niż 3 cyfry + 10 znaków alfanumerycznych.
        "https://pay.example.com/invoice?IPKSeF=123",
    ):
        assert any(issue.element == "LinkDoPlatnosci" for issue in _issues(broken)), broken


def test_invalid_date_is_reported() -> None:
    root = _tree()
    issue_date = root.find(f".//{_q('P_1')}")
    assert issue_date is not None
    issue_date.text = "nie-data"
    issues = validate_xml_facets(root)
    assert any("nie jest poprawną datą" in issue.message for issue in issues)


def test_date_before_schema_minimum_is_reported() -> None:
    """`P_1` jest typu `TDataT`, którego dolna granica to 2006-01-01.

    Wcześniejsza wersja tabeli mapowała `P_1` na `TData` (granica 2016-07-01),
    przez co faktura z datą wystawienia z lat 2006-2016 była odrzucana, mimo że
    schemat ją dopuszcza.
    """
    root = _tree()
    issue_date = root.find(f".//{_q('P_1')}")
    assert issue_date is not None
    issue_date.text = "2005-12-31"
    issues = validate_xml_facets(root)
    assert any("wcześniejsza niż minimum" in issue.message for issue in issues)


def test_date_in_the_2006_2016_window_is_accepted() -> None:
    """Data wystawienia między 2006-01-01 a 2016-06-30 musi przechodzić."""
    root = _tree()
    issue_date = root.find(f".//{_q('P_1')}")
    assert issue_date is not None
    issue_date.text = "2010-01-01"
    assert validate_xml_facets(root) == []


def test_date_after_schema_maximum_is_reported() -> None:
    root = _tree()
    issue_date = root.find(f".//{_q('P_1')}")
    assert issue_date is not None
    issue_date.text = "2099-01-01"
    issues = validate_xml_facets(root)
    assert any("późniejsza niż maksimum" in issue.message for issue in issues)


def test_datetime_without_timezone_is_accepted() -> None:
    """`xsd:dateTime` dopuszcza brak strefy — nie może to być błąd."""
    from ksef_client.documents.fa3.validation.engine import _check_date_range
    from ksef_client.documents.fa3.validation.facets import DATA_CZAS

    assert _check_date_range("2026-04-01T08:30:00", DATA_CZAS, "path", "El") == []
    assert _check_date_range("2026-04-01T08:30:00Z", DATA_CZAS, "path", "El") == []


def test_datetime_before_schema_minimum_is_reported() -> None:
    from ksef_client.documents.fa3.validation.engine import _check_date_range
    from ksef_client.documents.fa3.validation.facets import DATA_CZAS

    issues = _check_date_range("2020-01-01T00:00:00Z", DATA_CZAS, "path", "El")
    assert issues and "wcześniejsza niż minimum" in issues[0].message


def test_integer_facet_rejects_fractional_value() -> None:
    from ksef_client.documents.fa3.validation.engine import _check_text
    from ksef_client.documents.fa3.validation.facets import NATURALNY

    issues = _check_text("1.5", NATURALNY, "path", "NrWierszaFa")
    assert any("liczbą całkowitą" in issue.message for issue in issues)


def test_integer_facet_rejects_value_below_minimum() -> None:
    from ksef_client.documents.fa3.validation.engine import _check_text
    from ksef_client.documents.fa3.validation.facets import NATURALNY

    issues = _check_text("0", NATURALNY, "path", "NrWierszaFa")
    assert any("mniejsza od minimum" in issue.message for issue in issues)


def test_integer_facet_enforces_the_xsd_integer_lexical_space() -> None:
    """`xsd:integer` dopuszcza wyłącznie ``[+-]?[0-9]+`` — ``30.0`` nie jest liczbą.

    `Decimal("30.0") == Decimal("30")`, więc kontrola wartości przepuszczała
    float przekazany do pola całkowitego (`Ilosc` z `payment_due_description`),
    a dokument odrzucał dopiero schemat (`SCHEMAV_CVC_DATATYPE_VALID_1_2_1`).
    """
    from ksef_client.documents.fa3.validation.engine import _check_text

    naturalny = ELEMENT_FACETS["NrWierszaFa"].facet
    for value in ("30.0", "23.00", "1E+1", "+1.0", "-0.0"):
        assert _check_text(value, naturalny, "path", "NrWierszaFa"), value


def test_integer_facet_accepts_what_the_schema_accepts() -> None:
    """``007``, ``+1`` i ``0`` są w XSD poprawne — fałszywy alarm to błąd.

    Tabela wymuszała na polach całkowitych wzorzec liczb KWOTOWYCH (bez zer
    wiodących i bez znaku ``+``), więc poprawne w ``xsd:integer`` wartości były
    odrzucane lokalnie. ``0`` jest poprawne dla `Ilosc` (``xsd:integer``), a dla
    `TNaturalny` (``totalDigits=14``) zgłaszany jest wyłącznie zakres.
    """
    from ksef_client.documents.fa3.validation.engine import _check_text

    ilosc = ELEMENT_FACETS["Ilosc"].facet
    naturalny = ELEMENT_FACETS["NrWierszaFa"].facet
    for value in ("007", "+1", "0", "12345678901234"):
        assert _check_text(value, ilosc, "path", "Ilosc") == [], value
    for value in ("007", "+1", "12345678901234"):
        assert _check_text(value, naturalny, "path", "NrWierszaFa") == [], value
    zero = _check_text("0", naturalny, "path", "NrWierszaFa")
    assert zero and all("mniejsza od minimum" in issue.message for issue in zero), zero


def test_deeply_nested_document_is_validated_without_recursion_error() -> None:
    """Głębokie drzewo (1500 elementów) nie może wywracać walidatora.

    Przejście rekurencyjne sięgało limitu stosu Pythona przy ~1000 zagnieżdżonych
    elementach, choć sam dokument parsował się bez problemu — publiczne API
    przestawało działać na poprawnym XML-u.
    """
    depth = 1500
    body = "<FaWiersz><P_7>w</P_7>" * depth + "</FaWiersz>" * depth
    document = ET.fromstring(
        f'<Faktura xmlns="http://crd.gov.pl/wzor/2025/06/25/13775/">{body}</Faktura>'
    )

    issues = validate_xml_facets(document)

    rows = [issue for issue in issues if issue.element == "NrWierszaFa"]
    assert len(rows) == depth, "każdy FaWiersz musi zgłosić brakujący NrWierszaFa"
    assert rows[0].path == "Faktura/FaWiersz"
    assert rows[-1].path.count("/") == depth, "ścieżka musi sięgać najgłębszego elementu"


def test_facet_describe_covers_all_kinds() -> None:
    """`describe()` musi dawać czytelny opis dla każdego wariantu ograniczenia."""
    assert "dozwolone wartości" in Facet(FacetKind.STRING, "X", allowed=frozenset({"1"})).describe()
    assert "długość 35, 36" in Facet(FacetKind.STRING, "X", lengths=frozenset({35, 36})).describe()
    assert (
        "długość 1-10" in Facet(FacetKind.STRING, "X", max_length=10, minimum_length=1).describe()
    )
    assert "maksymalnie 5 znaków" in Facet(FacetKind.STRING, "X", max_length=5).describe()
    assert "co najmniej 3 znaków" in Facet(FacetKind.STRING, "X", minimum_length=3).describe()
    assert "2 miejsc po przecinku" in Facet(FacetKind.DECIMAL, "X", decimals=2).describe()
    assert (
        "zakres 0-100"
        in Facet(FacetKind.DECIMAL, "X", minimum=Decimal("0"), maximum=Decimal("100")).describe()
    )
    assert "minimum 1" in Facet(FacetKind.INTEGER, "X", minimum=Decimal("1")).describe()
    assert "maksimum 7" in Facet(FacetKind.INTEGER, "X", maximum=Decimal("7")).describe()
    assert (
        "zakres dat"
        in Facet(
            FacetKind.STRING, "X", minimum_date="2016-07-01", maximum_date="2050-01-01"
        ).describe()
    )
    assert "typ X" in Facet(FacetKind.STRING, "X").describe()


def test_facet_issue_str_includes_path() -> None:
    from ksef_client.documents.fa3.validation import FacetIssue

    issue = FacetIssue("Fa/FaWiersz/P_7", "P_7", "za długie")
    assert str(issue) == "Fa/FaWiersz/P_7: za długie"


def test_engine_ignores_non_fa3_namespaced_elements() -> None:
    """Elementy spoza przestrzeni nazw FA(3) nie są walidowane."""
    root = _tree()
    foreign = ET.SubElement(root, "{http://example.com/other}Cos")
    foreign.text = "x" * 5000
    assert validate_xml_facets(root) == []


def test_facet_for_returns_none_for_unknown_element() -> None:
    from ksef_client.documents.fa3.validation import facet_for

    assert facet_for("NieMaTakiegoElementu") is None
    assert facet_for("P_7") is not None


def test_validation_error_message_points_at_element() -> None:
    """`to_xml()` ma zgłaszać ścieżkę elementu, a nie surowy błąd SCHEMAV."""
    builder = BasicInvoiceBuilder(invoice_number="FV/FACETS-ERR")
    builder.seller(
        InvoiceParty.polish_company(nip="1111111111", name="Sprzedawca", address="ul. A 1")
    )
    builder.buyer(InvoiceParty.polish_company(nip="2222222222", name="Nabywca", address="ul. B 2"))
    builder.add_service_line("Usługa", quantity="1", unit_net_price="100")
    invoice = builder.build()
    broken = invoice.to_xml().decode("utf-8").replace("<P_12>23</P_12>", "<P_12>99</P_12>")
    root = ET.fromstring(broken)
    issues = validate_xml_facets(root)
    assert issues
    assert all(issue.path.startswith("Faktura") for issue in issues)


def test_margin_rate_code_is_accepted() -> None:
    """Procedura marży nie podaje stawki — wiersz nie może nieść `P_12`.

    Oficjalny `FA_3_Przykład_8.xml` ma w wierszu wyłącznie `P_8A`, `P_8B`,
    `P_9B`, `P_11A` i `GTU`; wcześniejsza wersja SDK emitowała tam
    `P_12="np I"` („dostawa poza terytorium kraju"), co było nieprawdziwą
    deklaracją dla krajowej sprzedaży opodatkowanej od marży.
    """
    root = _tree(tax=TaxCategory.margin())
    assert root.find(f".//{_q('P_12')}") is None
    assert validate_xml_facets(root) == []


def test_regex_patterns_in_table_are_anchored() -> None:
    """Wzorce muszą odrzucać wartości z nadmiarowymi znakami."""
    entry = ELEMENT_FACETS["KRS"]
    assert entry.pattern is not None
    assert not entry.pattern.fullmatch("0000111111X")
    assert not entry.pattern.fullmatch("000011111")
    assert re.fullmatch(entry.pattern, "0000111111")


def test_date_facets_declare_schema_bounds() -> None:
    """Zakresy dat w tabeli muszą odpowiadać schematowi."""
    assert ELEMENT_FACETS["P_1"].facet.minimum_date == "2006-01-01"
    assert ELEMENT_FACETS["P_1"].facet.maximum_date == "2050-01-01"
    assert ELEMENT_FACETS["DataUmowy"].facet.minimum_date == "1990-01-01"
    assert ELEMENT_FACETS["P_22A"].facet.minimum_date == "2006-01-01"
    assert ELEMENT_FACETS["DataGodzRozpTransportu"].facet.minimum_date == "2021-10-01T00:00:00Z"


def test_issue_date_today_is_within_bounds() -> None:
    """Sanity check: dzisiejsza data mieści się w zakresie schematu."""
    today = date.today().isoformat()
    from ksef_client.documents.fa3.validation.engine import _check_date_range
    from ksef_client.documents.fa3.validation.facets import DATA

    assert _check_date_range(today, DATA, "path", "P_1") == []


def test_xml_validation_error_is_a_value_error() -> None:
    assert issubclass(FA3XmlValidationError, ValueError)


def test_local_name_without_namespace_prefix() -> None:
    """Element bez przestrzeni nazw też ma czytelną nazwę lokalną."""
    from ksef_client.documents.fa3.validation.engine import _local_name

    assert _local_name("P_7") == "P_7"
    assert _local_name("{http://crd.gov.pl/wzor/2025/06/25/13775/}P_7") == "P_7"


def test_disallowed_length_is_reported() -> None:
    """Pola z zamkniętą listą długości (np. numer KSeF) muszą ją respektować."""
    from ksef_client.documents.fa3.validation.engine import _check_text
    from ksef_client.documents.fa3.validation.facets import NUMER_KSEF

    issues = _check_text(
        "1111111111-20260101-AAAAAA-BBBBBBB-01", NUMER_KSEF, "p", "NrKSeFFaKorygowanej"
    )
    assert issues and "niedozwolona" in issues[0].message
    assert _check_text("1111111111-20260101-AAAAAA-BBBBBB-01", NUMER_KSEF, "p", "X") == []


# ---------------------------------------------------------------------------
# 3. Spójność tabeli ze schematem: deklarowany typ, nazwy, liczności, wymagane
# ---------------------------------------------------------------------------
#
# Poprzednia wersja tych testów rozwiązywała typ Z TABELI (a nie z deklaracji
# elementu), więc błędne mapowania typów (P_1 -> TData zamiast TDataT,
# P_22C -> TIlosci zamiast TZnakowy, Ilosc -> TNaturalny zamiast xsd:integer)
# i literówki w nazwach elementów przechodziły na zielono. Poniższe testy
# porównują tabelę z FAKTYCZNĄ deklaracją elementu w schemacie.


def _xsd_element_declarations() -> dict[str, set[str]]:
    """Mapa nazwa elementu -> zbiór zadeklarowanych typów (po wszystkich XSD)."""
    declarations: dict[str, set[str]] = {}
    for name in XSD_FILES:
        root = ET.parse(SCHEMAS / name).getroot()
        for node in root.iter(f"{_XSD}element"):
            element_name = node.get("name")
            if not element_name:
                continue
            declared = node.get("type")
            if declared is None:
                restriction = node.find(f"{_XSD}simpleType/{_XSD}restriction")
                if restriction is not None:
                    declared = restriction.get("base")
                else:
                    # `complexType/simpleContent/extension` (np. `NKom`
                    # rozszerza `TZnakowy2`) też jest deklaracją typu.
                    extension = node.find(
                        f"{_XSD}complexType/{_XSD}simpleContent/{_XSD}extension"
                    )
                    if extension is not None:
                        declared = extension.get("base")
                    else:
                        declared = "(inline complexType)"
            declarations.setdefault(element_name, set()).add(declared or "")
    return declarations


def _xsd_sequence_children() -> dict[tuple[str, str], tuple[str | None, str | None]]:
    """Mapa (rodzic, dziecko) -> (minOccurs, maxOccurs) z całego kompletu schematów.

    Schemat FA(3) miesza typy anonimowe (struktura wprost w elemencie) z nazwanymi
    (`type="tns:TNaglowek"`), a część z nich żyje w importowanych plikach
    dziedzinowych. Walker musi więc rozwiązywać referencje do nazwanych typów —
    wcześniejsza wersja widziała tylko typy anonimowe i uznawała m.in.
    `Naglowek/KodFormularza` oraz `RachunekBankowy/NrRB` za nieistniejące.
    """
    from lxml import etree as _lxml_etree

    children: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    named_types: dict[str, object] = {}

    roots = [_lxml_etree.parse(str(SCHEMAS / schema)).getroot() for schema in XSD_FILES]
    for root in roots:
        for node in root.iter(f"{_XSD}complexType"):
            type_name = node.get("name")
            if type_name:
                named_types.setdefault(type_name, node)

    def record(parent: str, child: Any) -> None:
        name = child.get("name")
        if name is None:
            return
        key = (parent, name)
        value = (child.get("minOccurs"), child.get("maxOccurs"))
        if key not in children or children[key][0] in (None, "1"):
            children[key] = value

    def walk(node: Any, parent: str | None, seen: frozenset[str]) -> None:
        for child in node:
            tag = child.tag
            if not isinstance(tag, str):
                continue
            if tag.endswith("}element"):
                name = child.get("name")
                if name is None:
                    continue
                if parent is not None:
                    record(parent, child)
                walk(child, name, seen)
                declared = child.get("type")
                if declared:
                    local = declared.split(":", 1)[-1]
                    definition = named_types.get(local)
                    if definition is not None and local not in seen:
                        walk(definition, name, seen | {local})
            elif tag.endswith("}complexContent"):
                walk(child, parent, seen)
            else:
                walk(child, parent, seen)

    for root in roots:
        walk(root, None, frozenset())
    return children


@pytest.fixture(scope="module")
def xsd_elements() -> dict[str, set[str]]:
    return _xsd_element_declarations()


@pytest.fixture(scope="module")
def xsd_children() -> dict[tuple[str, str], tuple[str | None, str | None]]:
    return _xsd_sequence_children()


def test_every_table_element_exists_in_the_schema(xsd_elements: dict[str, set[str]]) -> None:
    """Literówka w nazwie elementu = reguła, która nigdy nie zadziała."""
    unknown = sorted(name for name in ELEMENT_FACETS if name not in xsd_elements)
    assert not unknown, f"elementy spoza schematu (reguły martwe): {unknown}"


def test_declared_type_matches_the_element_declaration(
    xsd_elements: dict[str, set[str]],
) -> None:
    """`xsd_type` w tabeli musi być typem ZADEKLAROWANYM dla tego elementu.

    To jest test, który wyłapałby mapowanie `P_1` na `TData` zamiast `TDataT`
    oraz `P_22C` na `TIlosci` zamiast `TZnakowy`.
    """
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        facet = entry.facet
        if facet.xsd_type is None:
            continue  # ograniczenie inline, bez nazwanego typu
        declared = xsd_elements.get(element)
        if not declared:
            continue
        expected = f"tns:{facet.xsd_type}"
        normalized = {candidate.split(":", 1)[-1] for candidate in declared}
        if facet.xsd_type not in normalized:
            mismatches.append(f"{element}: tabela={expected} schemat={sorted(declared)}")
            continue
        checked += 1
    assert checked >= 150, f"test sprawdził tylko {checked} elementów"
    assert not mismatches, "\n".join(mismatches)


#: Pary, których limitu celowo nie pilnujemy w tabeli: elementy jednokrotne
#: w schemacie, ale wyprowadzane strukturalnie (nie przez powtarzalny blok).
_OCCURRENCE_EXEMPT: frozenset[tuple[str, str]] = frozenset(
    {
        ("Fa", "KodWaluty"),
        ("Fa", "P_1"),
        ("Fa", "P_1M"),
        ("Fa", "P_2"),
        ("Fa", "P_6"),
        ("Fa", "OkresFa"),
        ("Fa", "RodzajFaktury"),
        ("Fa", "Adnotacje"),
        ("Fa", "P_15"),
        ("Fa", "Platnosc"),
        ("Fa", "WarunkiTransakcji"),
        ("Fa", "Rozliczenie"),
        ("Fa", "Zamowienie"),
        ("Fa", "Stopka"),
        ("Fa", "Zalacznik"),
        ("Faktura", "Fa"),
        ("Faktura", "Naglowek"),
        ("Faktura", "Podmiot1"),
        ("Faktura", "Podmiot2"),
        ("Naglowek", "KodFormularza"),
        ("Naglowek", "WariantFormularza"),
        ("Naglowek", "DataWytworzeniaFa"),
        ("Adres", "KodKraju"),
        ("Adres", "AdresL1"),
        ("Adres", "AdresL2"),
        ("Adres", "GLN"),
        ("DaneIdentyfikacyjne", "NIP"),
        ("DaneIdentyfikacyjne", "Nazwa"),
        ("DaneIdentyfikacyjne", "KodUE"),
        ("DaneIdentyfikacyjne", "NrVatUE"),
        ("DaneIdentyfikacyjne", "KodKraju"),
        ("DaneIdentyfikacyjne", "NrID"),
        ("DaneIdentyfikacyjne", "BrakID"),
        ("FaWiersz", "NrWierszaFa"),
        ("MetaDane", "ZKlucz"),
        ("MetaDane", "ZWartosc"),
        ("TMetaDane", "TKlucz"),
        ("TMetaDane", "TWartosc"),
        ("Kol", "NKom"),
        ("OkresFa", "P_6_Od"),
        ("OkresFa", "P_6_Do"),
        ("Obciazenia", "Kwota"),
        ("Obciazenia", "Powod"),
        ("Odliczenia", "Kwota"),
        ("Odliczenia", "Powod"),
        ("DodatkowyOpis", "Klucz"),
        ("DodatkowyOpis", "Wartosc"),
        ("DodatkowyOpis", "NrWiersza"),
        ("NowySrodekTransportu", "P_22A"),
        ("NowySrodekTransportu", "P_NrWierszaNST"),
        ("DaneFaKorygowanej", "DataWystFaKorygowanej"),
        ("DaneFaKorygowanej", "NrFaKorygowanej"),
        ("Podmiot1", "DaneIdentyfikacyjne"),
        ("Podmiot1", "Adres"),
        ("Podmiot1K", "DaneIdentyfikacyjne"),
        ("Podmiot1K", "Adres"),
        ("Podmiot2", "DaneIdentyfikacyjne"),
        ("Podmiot2", "Adres"),
        ("Przewoznik", "DaneIdentyfikacyjne"),
        ("Adnotacje", "P_16"),
        ("Adnotacje", "P_17"),
        ("Adnotacje", "P_18"),
        ("Adnotacje", "P_18A"),
        ("Adnotacje", "P_23"),
        ("Adnotacje", "Zwolnienie"),
        ("Adnotacje", "NoweSrodkiTransportu"),
        ("Adnotacje", "PMarzy"),
        ("TerminOpis", "Ilosc"),
        ("TerminOpis", "Jednostka"),
        ("TerminOpis", "ZdarzeniePoczatkowe"),
        ("ZaliczkaCzesciowa", "P_6Z"),
        ("ZaliczkaCzesciowa", "P_15Z"),
        ("Zamowienie", "WartoscZamowienia"),
        ("RachunekBankowy", "NrRB"),
        ("RachunekBankowyFaktora", "NrRB"),
        ("ZaplataCzesciowa", "KwotaZaplatyCzesciowej"),
        ("ZaplataCzesciowa", "DataZaplatyCzesciowej"),
        ("BlokDanych", "ZNaglowek"),
        ("BlokDanych", "Tekst"),
        ("Tabela", "Opis"),
        ("Tabela", "TNaglowek"),
        ("TNaglowek", "Kol"),
        ("Kol", "NKom"),
        ("Wiersz", "WKom"),
        ("Suma", "SKom"),
        ("Stopka", "StopkaFaktury"),
    }
)


def test_occurrence_limits_cover_every_single_occurrence_pair(
    xsd_children: dict[tuple[str, str], tuple[str | None, str | None]],
) -> None:
    """Każda para z `maxOccurs=1` w schemacie musi mieć limit w tabeli.

    Kontrola w OBIE strony: sam wpis bez odpowiednika w schemacie nigdy nie
    zadziała, ale też usunięcie wpisu dla pary, która w schemacie występuje raz,
    pozwalałoby wyemitować zdublowany element obowiązkowy (`KodWaluty`, `P_15`).
    """
    dead = sorted(key for key in OCCURRENCE_LIMITS if key not in xsd_children)
    assert not dead, f"wiersze bez odpowiednika w schemacie (nigdy nie zadziałają): {dead}"

    uncovered: list[str] = []
    for key, (_min_occurs, max_occurs) in sorted(xsd_children.items()):
        if max_occurs != "1" or key in _OCCURRENCE_EXEMPT:
            continue
        if occurrence_limit(*key) is None:
            uncovered.append(f"{key[0]}/{key[1]}")
    assert not uncovered, "pary jednokrotne bez limitu w tabeli: " + ", ".join(uncovered)


def test_required_entries_exist_in_the_schema(
    xsd_children: dict[tuple[str, str], tuple[str | None, str | None]],
) -> None:
    """Każdy wiersz `REQUIRED_IN_PARENT` musi istnieć i być naprawdę wymagany."""
    problems: list[str] = []
    for key in sorted(REQUIRED_IN_PARENT):
        if key not in xsd_children:
            problems.append(f"{key[0]}/{key[1]}: brak pary w schemacie")
            continue
        min_occurs = xsd_children[key][0]
        if min_occurs == "0":
            problems.append(f"{key[0]}/{key[1]}: schemat ma minOccurs=0")
    assert not problems, "\n".join(problems)


def test_no_declared_element_is_missing_a_value_facet(
    xsd_elements: dict[str, set[str]],
) -> None:
    """Elementy ze schematu, które serializer emituje, powinny mieć wpis w tabeli.

    Kontrola kompletności: brak wpisu nie jest błędem sam w sobie (element może
    być kontenerem), ale każdy element, który SDK faktycznie wypisuje jako tekst,
    musi mieć zdefiniowane ograniczenie.
    """
    import re as _re
    from pathlib import Path as _Path

    serializer = (
        _Path(__file__).resolve().parents[1] / "src/ksef_client/documents/fa3/xml.py"
    ).read_text(encoding="utf-8")
    emitted = set(_re.findall(r'_q\("([A-Za-z_][A-Za-z0-9_.]*)"\)', serializer))
    missing = sorted(
        name
        for name in emitted
        if name in xsd_elements and name not in ELEMENT_FACETS
    )
    # Elementy-kontenery nie mają wartości tekstowej, więc nie potrzebują faceta.
    containers = {
        "Faktura", "Naglowek", "Fa", "Podmiot1", "Podmiot2", "Podmiot3",
        "PodmiotUpowazniony", "Podmiot1K", "Podmiot2K", "DaneIdentyfikacyjne",
        "Adres", "AdresKoresp", "DaneKontaktowe", "FaWiersz", "Adnotacje",
        "Zwolnienie", "NoweSrodkiTransportu", "NowySrodekTransportu", "PMarzy",
        "DaneFaKorygowanej", "ZaliczkaCzesciowa", "FakturaZaliczkowa",
        "DodatkowyOpis", "Rozliczenie", "Obciazenia", "Odliczenia", "Platnosc",
        "ZaplataCzesciowa", "TerminPlatnosci", "TerminOpis", "RachunekBankowy",
        "RachunekBankowyFaktora", "Skonto", "WarunkiTransakcji", "Umowy",
        "Zamowienia", "Transport", "Przewoznik", "WysylkaZ", "WysylkaPrzez",
        "WysylkaDo", "Zamowienie", "ZamowienieWiersz", "Stopka", "Rejestr",
        "Rejestry", "Zalacznik", "BlokDanych", "MetaDane", "Tekst", "Tabela",
        "TNaglowek", "Kol", "Wiersz", "Suma", "PodmiotPosredniczacy",
        "WariantFormularza", "OkresFa", "Informacje", "P_22B1", "P_22B2",
        "P_22B3", "P_22B4",
    }
    unresolved = [name for name in missing if name not in containers]
    assert not unresolved, f"elementy bez ograniczeń: {unresolved}"


#: Pary, których obecność w `REQUIRED_IN_PARENT` jest wymagana przez schemat
#: (minOccurs=1 i poza `xsd:choice`). Lista jest kontrolą w drugą stronę:
#: poprzednia wersja testu sprawdzała tylko, że wpisy tabeli istnieją w schemacie,
#: więc USUNIĘCIE wpisu przechodziło na zielono.
_MUST_BE_REQUIRED: frozenset[tuple[str, str]] = frozenset(
    {
        ("Faktura", "Naglowek"),
        ("Faktura", "Podmiot1"),
        ("Faktura", "Podmiot2"),
        ("Faktura", "Fa"),
        ("Naglowek", "KodFormularza"),
        ("Naglowek", "WariantFormularza"),
        ("Fa", "KodWaluty"),
        ("Fa", "P_1"),
        ("Fa", "P_2"),
        ("Fa", "P_15"),
        ("Fa", "RodzajFaktury"),
        ("Fa", "Adnotacje"),
        ("BlokDanych", "MetaDane"),
        ("Zalacznik", "BlokDanych"),
        ("Tabela", "TNaglowek"),
        ("Tabela", "Wiersz"),
        ("TNaglowek", "Kol"),
        ("Zamowienie", "WartoscZamowienia"),
        ("Zamowienie", "ZamowienieWiersz"),
        ("Przewoznik", "AdresPrzewoznika"),
        ("RachunekBankowy", "NrRB"),
        ("RachunekBankowyFaktora", "NrRB"),
        ("ZaplataCzesciowa", "KwotaZaplatyCzesciowej"),
        ("ZaplataCzesciowa", "DataZaplatyCzesciowej"),
        ("Adres", "KodKraju"),
        ("Adres", "AdresL1"),
        ("MetaDane", "ZKlucz"),
        ("MetaDane", "ZWartosc"),
        ("FaWiersz", "NrWierszaFa"),
        ("TerminOpis", "Ilosc"),
        ("TerminOpis", "Jednostka"),
        ("TerminOpis", "ZdarzeniePoczatkowe"),
    }
)


def test_required_table_covers_mandatory_schema_pairs() -> None:
    """Każda para wymagana przez schemat musi być pokryta przez jedną z tabel.

    Para może być wymagana bezwarunkowo (`REQUIRED_IN_PARENT`) albo tylko
    w konkretnym kontekście (`REQUIRED_IN_ANCESTOR`) — ta sama nazwa
    `DaneIdentyfikacyjne` występuje w siedmiu typach i `Nazwa` jest obowiązkowa
    wyłącznie w `TPodmiot1` (w `TPodmiot2`/`TPodmiot3` schemat ma
    `<xsd:sequence minOccurs="0">`, żeby dało się wystawić fakturę uproszczoną).
    """
    covered = set(REQUIRED_IN_PARENT)
    covered |= {(parent, child) for _ancestor, parent, child in REQUIRED_IN_ANCESTOR}
    missing = sorted(_MUST_BE_REQUIRED - covered)
    assert not missing, "brak wymaganych wpisów: " + ", ".join(f"{p}/{c}" for p, c in missing)


def test_ancestor_scoped_requirements_match_the_schema() -> None:
    """Wymagania zależne od przodka muszą odpowiadać deklaracjom typów w XSD.

    `Nazwa` jest obowiązkowa w `TPodmiot1` (sekwencja bez `minOccurs="0"`),
    a opcjonalna w `TPodmiot2`/`TPodmiot3` — czyli pod `Podmiot2`, `Podmiot3`,
    `Podmiot2K` i `Przewoznik` NIE wolno jej wymagać.
    """
    schema = ET.parse(SCHEMAS / "schemat_FA(3)_v1-0E.xsd").getroot()
    nazwa_min_occurs: dict[str, str | None] = {}
    for complex_type in schema.iter(f"{_XSD}complexType"):
        type_name = complex_type.get("name")
        if type_name is None:
            continue
        # `Nazwa` w TPodmiot2/TPodmiot3 siedzi w ZAGNIEŻDŻONEJ sekwencji
        # (`<xsd:sequence minOccurs="0">` wewnątrz sekwencji głównej).
        for sequence in complex_type.iter(f"{_XSD}sequence"):
            for child in sequence.findall(f"{_XSD}element"):
                if child.get("name") == "Nazwa":
                    nazwa_min_occurs[type_name] = sequence.get("minOccurs")

    assert nazwa_min_occurs == {
        "TPodmiot1": None,
        "TPodmiot2": "0",
        "TPodmiot3": "0",
    }, nazwa_min_occurs

    # Typy użyte przez elementy FA(3) rozstrzygają, gdzie `Nazwa` jest wymagana.
    parents_requiring_nazwa: set[str] = set()
    parents_allowing_omission: set[str] = set()
    for parent_name in (
        "Podmiot1",
        "Podmiot2",
        "Podmiot3",
        "Podmiot1K",
        "Podmiot2K",
        "PodmiotUpowazniony",
        "Przewoznik",
    ):
        for parent in schema.iter(f"{_XSD}element"):
            if parent.get("name") != parent_name:
                continue
            for identity in parent.iter(f"{_XSD}element"):
                if identity.get("name") != "DaneIdentyfikacyjne":
                    continue
                type_name = (identity.get("type") or "").split(":", 1)[-1]
                if nazwa_min_occurs.get(type_name) == "0":
                    parents_allowing_omission.add(parent_name)
                else:
                    parents_requiring_nazwa.add(parent_name)

    assert {"Podmiot1", "Podmiot1K", "PodmiotUpowazniony"} <= parents_requiring_nazwa
    assert {"Podmiot2", "Podmiot3", "Podmiot2K", "Przewoznik"} <= parents_allowing_omission

    declared = {(ancestor, parent, child) for ancestor, parent, child in REQUIRED_IN_ANCESTOR}
    assert declared == {
        ("Podmiot1", "DaneIdentyfikacyjne", "Nazwa"),
        ("Podmiot1K", "DaneIdentyfikacyjne", "Nazwa"),
        ("PodmiotUpowazniony", "DaneIdentyfikacyjne", "Nazwa"),
    }
    flat_pairs = {pair for pair in REQUIRED_IN_PARENT if pair[1] == "Nazwa"}
    assert not flat_pairs, (
        f"`Nazwa` nie może być wymagana płasko (łapie też Podmiot2/Podmiot3): {flat_pairs}"
    )


def _xsd_declared_type_map() -> dict[str, set[str]]:
    """Mapa element -> zadeklarowane typy (z prefiksem, np. ``tns:TDataT``)."""
    declared: dict[str, set[str]] = {}
    for name in XSD_FILES:
        root = ET.parse(SCHEMAS / name).getroot()
        for node in root.iter(f"{_XSD}element"):
            element_name = node.get("name")
            if not element_name:
                continue
            type_name = node.get("type")
            if type_name is None:
                restriction = node.find(f"{_XSD}simpleType/{_XSD}restriction")
                if restriction is not None:
                    type_name = restriction.get("base")
            if type_name:
                declared.setdefault(element_name, set()).add(type_name.split(":", 1)[-1])
    return declared


@pytest.fixture(scope="module")
def xsd_declared_types() -> dict[str, set[str]]:
    return _xsd_declared_type_map()


def _xsd_element_inline_bounds() -> dict[str, tuple[set[str], set[str]]]:
    """Granice dat zadeklarowane BEZPOŚREDNIO w elemencie (restriction inline).

    ``Naglowek/DataWytworzeniaFa`` ma własne, węższe ``minInclusive`` niż typ
    ``TDataCzas`` (2025-09-01 zamiast 2021-10-01), więc tabela musi móc podać
    granicę elementu, a nie tylko granicę nazwanego typu.
    """
    bounds: dict[str, tuple[set[str], set[str]]] = {}
    for name in XSD_FILES:
        root = ET.parse(SCHEMAS / name).getroot()
        for node in root.iter(f"{_XSD}element"):
            element_name = node.get("name")
            if not element_name:
                continue
            lowers: set[str] = set()
            uppers: set[str] = set()
            for restriction in node.iter(f"{_XSD}restriction"):
                for child in restriction:
                    if child.tag == f"{_XSD}minInclusive":
                        lowers.add(child.get("value") or "")
                    elif child.tag == f"{_XSD}maxInclusive":
                        uppers.add(child.get("value") or "")
            if lowers or uppers:
                existing = bounds.get(element_name, (set(), set()))
                bounds[element_name] = (existing[0] | lowers, existing[1] | uppers)
    return bounds


def test_date_bounds_match_the_declared_xsd_type(
    xsd_types: dict[str, ET.Element], xsd_declared_types: dict[str, set[str]]
) -> None:
    """`minimum_date`/`maximum_date` muszą zgadzać się z `xsd:minInclusive`.

    Test rozwiązuje typ Z DEKLARACJI ELEMENTU (nie z tabeli), więc wyłapuje
    mapowanie elementu na zły typ — np. `P_1` na `TData` (2016-07-01) zamiast
    `TDataT` (2006-01-01), przez co schemat-valid faktury były odrzucane.
    Granica zadeklarowana wprost w elemencie (restriction inline) też jest
    dopuszczalna — jest wtedy węższa niż granica typu.
    """
    inline_bounds = _xsd_element_inline_bounds()
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        facet = entry.facet
        if facet.minimum_date is None and facet.maximum_date is None:
            continue
        declared = xsd_declared_types.get(element)
        if not declared:
            continue
        # Zbierz granice ze WSZYSTKICH zadeklarowanych typów (element może mieć
        # różne deklaracje w różnych plikach).
        lowers: set[str] = set()
        uppers: set[str] = set()
        for type_name in declared:
            resolved = _resolve(type_name, xsd_types)
            if resolved.get("minInclusive"):
                lowers.add(resolved["minInclusive"])
            if resolved.get("maxInclusive"):
                uppers.add(resolved["maxInclusive"])
        inline_lowers, inline_uppers = inline_bounds.get(element, (set(), set()))
        lowers |= inline_lowers
        uppers |= inline_uppers
        if not lowers and not uppers:
            continue
        checked += 1
        if facet.minimum_date is not None and facet.minimum_date not in lowers:
            mismatches.append(
                f"{element}: tabela min={facet.minimum_date} schemat={sorted(lowers)}"
            )
        if facet.maximum_date is not None and uppers and facet.maximum_date not in uppers:
            mismatches.append(
                f"{element}: tabela max={facet.maximum_date} schemat={sorted(uppers)}"
            )
    assert checked >= 8, f"test sprawdził tylko {checked} elementów z granicami dat"
    assert not mismatches, "\n".join(mismatches)


def test_lengths_match_the_declared_xsd_type(
    xsd_types: dict[str, ET.Element], xsd_declared_types: dict[str, set[str]]
) -> None:
    """`lengths` (zamknięta lista długości) musi odpowiadać schematowi."""
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        facet = entry.facet
        if facet.lengths is None:
            continue
        declared = xsd_declared_types.get(element)
        if not declared:
            continue
        lengths: set[int] = set()
        for type_name in declared:
            resolved = _resolve(type_name, xsd_types)
            if resolved.get("minLength") and resolved.get("maxLength"):
                lengths.add(int(resolved["minLength"]))
                lengths.add(int(resolved["maxLength"]))
        if not lengths:
            continue
        checked += 1
        # Wartości z tabeli muszą mieścić się w granicach typu bazowego: żadna nie
        # może przekroczyć `maxLength` ani zejść poniżej `minLength`.
        lowest, highest = min(facet.lengths), max(facet.lengths)
        if highest > max(lengths) or lowest < min(lengths):
            mismatches.append(
                f"{element}: tabela lengths={sorted(facet.lengths)} "
                f"granice schematu={min(lengths)}-{max(lengths)}"
            )
    # Tylko `IPKSeF` ma w schemacie zamknięty zbiór długości (minLength+maxLength
    # na tym samym typie). `SWIFT`/numer KSeF mają wzorce, nie długości.
    assert checked >= 1, f"test sprawdził tylko {checked} elementów z listą długości"
    assert not mismatches, "\n".join(mismatches)


def test_minimum_length_matches_the_declared_xsd_type(
    xsd_types: dict[str, ET.Element], xsd_declared_types: dict[str, set[str]]
) -> None:
    """`minimum_length` musi odpowiadać `xsd:minLength` zadeklarowanego typu."""
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        facet = entry.facet
        if facet.minimum_length is None or facet.lengths is not None:
            continue
        declared = xsd_declared_types.get(element)
        if not declared:
            continue
        expected: set[int] = set()
        for type_name in declared:
            resolved = _resolve(type_name, xsd_types)
            if resolved.get("minLength"):
                expected.add(int(resolved["minLength"]))
        if not expected:
            continue
        checked += 1
        if facet.minimum_length not in expected:
            mismatches.append(
                f"{element}: tabela minLength={facet.minimum_length} schemat={sorted(expected)}"
            )
    assert checked >= 8, f"test sprawdził tylko {checked} elementów z minLength"
    assert not mismatches, "\n".join(mismatches)


def test_numeric_bounds_match_the_declared_xsd_type(
    xsd_types: dict[str, ET.Element], xsd_declared_types: dict[str, set[str]]
) -> None:
    """`minimum`/`maximum` dla wartości liczbowych muszą odpowiadać schematowi."""
    mismatches: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        facet = entry.facet
        if facet.minimum is None and facet.maximum is None:
            continue
        declared = xsd_declared_types.get(element)
        if not declared:
            continue
        lowers: set[str] = set()
        uppers: set[str] = set()
        for type_name in declared:
            resolved = _resolve(type_name, xsd_types)
            if resolved.get("minInclusive"):
                lowers.add(resolved["minInclusive"])
            if resolved.get("maxInclusive"):
                uppers.add(resolved["maxInclusive"])
        if not lowers and not uppers:
            continue
        checked += 1
        if facet.minimum is not None and str(facet.minimum) not in lowers:
            mismatches.append(
                f"{element}: tabela min={facet.minimum} schemat={sorted(lowers)}"
            )
        if facet.maximum is not None and uppers and str(facet.maximum) not in uppers:
            mismatches.append(
                f"{element}: tabela max={facet.maximum} schemat={sorted(uppers)}"
            )
    assert checked >= 1, f"test sprawdził tylko {checked} elementów z zakresem liczbowym"
    assert not mismatches, "\n".join(mismatches)


#: Limity liczności, które muszą być w tabeli (schemat: maxOccurs o tej wartości).
_MUST_BE_LIMITED: dict[tuple[str, str], int] = {
    ("Fa", "FaWiersz"): 10000,
    ("Fa", "DodatkowyOpis"): 10000,
    ("Fa", "ZaliczkaCzesciowa"): 31,
    ("Fa", "FakturaZaliczkowa"): 100,
    ("Fa", "DaneFaKorygowanej"): 50000,
    ("Fa", "Podmiot2K"): 101,
    ("Faktura", "Podmiot3"): 100,
    ("Platnosc", "TerminPlatnosci"): 100,
    ("Platnosc", "RachunekBankowy"): 100,
    ("Platnosc", "RachunekBankowyFaktora"): 20,
    ("Rozliczenie", "Obciazenia"): 100,
    ("Rozliczenie", "Odliczenia"): 100,
    ("WarunkiTransakcji", "Transport"): 20,
    ("WarunkiTransakcji", "NrPartiiTowaru"): 1000,
    ("Transport", "WysylkaPrzez"): 20,
    ("Zamowienie", "ZamowienieWiersz"): 10000,
    ("Stopka", "Informacje"): 3,
    ("Stopka", "Rejestry"): 100,
    ("Zalacznik", "BlokDanych"): 1000,
    ("BlokDanych", "MetaDane"): 1000,
    ("Tekst", "Akapit"): 10,
    ("TNaglowek", "Kol"): 20,
    ("Tabela", "Wiersz"): 1000,
    ("Wiersz", "WKom"): 20,
    ("Suma", "SKom"): 20,
}


def test_occurrence_limits_match_the_schema_value(
    xsd_children: dict[tuple[str, str], tuple[str | None, str | None]],
) -> None:
    """Wartości limitów muszą zgadzać się z `xsd:maxOccurs` (nie tylko istnieć)."""
    mismatches: list[str] = []
    for key, expected in sorted(_MUST_BE_LIMITED.items()):
        actual = occurrence_limit(*key)
        if actual != expected:
            mismatches.append(f"{key[0]}/{key[1]}: tabela={actual} schemat={expected}")
        schema_value = xsd_children.get(key, (None, None))[1]
        if schema_value is not None and int(schema_value) != expected:
            mismatches.append(
                f"{key[0]}/{key[1]}: oczekiwano {expected}, schemat={schema_value}"
            )
    assert not mismatches, "\n".join(mismatches)


#: Elementy, których wzorzec pochodzi wprost ze schematu, wraz z wartościami,
#: które schemat ODRZUCA (a więc i tabela nie może ich zaakceptować).
_PATTERN_MUST_REJECT: dict[str, tuple[str, ...]] = {
    "NIP": ("0000000000", "123456789", "12345678901", "123456789a"),
    "IDWew": ("1111111111", "1111111111-0000", "1111111111-000011"),
    "SWIFT": ("DEUTDEFF5", "DEUTDEFF50", "deutdeff", "DEUTDEFF5000"),
    "KRS": ("000011111", "00001111111", "000011111a"),
    "REGON": ("12345678", "1234567890", "1234567890123", "123456789012345"),
    "IPKSeF": ("123abc456DEF", "123abc456DEFGH", "12abc456DEFG", "123abc456DE-"),
    "NrKSeFFaKorygowanej": (
        "1111111111-20260101-AAAAAA-BBBBBB-0G",
        "1111111111-20260101-AAAAAA-BBBBBB-GG",
        "0111111111-20260101-AAAAAA-BBBBBB-01",
    ),
    "NrKSeFFaZaliczkowej": (
        "x" * 35,
        "1111111111-20260101-AAAAAA-BBBBBB-0G",
        "0111111111-20260101-AAAAAA-BBBBBB-01",
    ),
    "LinkDoPlatnosci": (
        "https://pay.example.com/invoice",
        "http://pay.example.com/invoice",
        "ftp://pay.example.com/invoice?IPKSeF=123abc456DEFG",
        "https://pay.example.com/invoice?IPKSeF=123",
        "https://pay.example.com/invoice?IPKSeF=123abc456DEFGH",
    ),
}


def test_ksef_number_elements_share_the_schema_pattern() -> None:
    """`NrKSeFFaKorygowanej` i `NrKSeFFaZaliczkowej` mają ten sam typ `TNumerKSeF`.

    Wcześniej `NrKSeFFaZaliczkowej` deklarował wyłącznie długości (35/36), więc
    dowolny napis tej długości przechodził walidację i dopiero KSeF go odrzucał.
    """
    correcting = ELEMENT_FACETS["NrKSeFFaKorygowanej"]
    advance = ELEMENT_FACETS["NrKSeFFaZaliczkowej"]
    assert advance.pattern is not None
    assert correcting.pattern is not None
    assert advance.facet == correcting.facet
    assert advance.pattern.pattern == correcting.pattern.pattern


def test_payment_link_pattern_has_a_single_source() -> None:
    """Wzorzec `LinkDoPlatnosci` ma jedno źródło, a nie kopię literału.

    Tabela faset i `FA3Invoice.validate()` muszą egzekwować dokładnie ten sam
    wzorzec — kopia rozjechałaby oba poziomy walidacji przy pierwszej zmianie.
    """
    from ksef_client.documents.fa3.domain import PAYMENT_LINK_PATTERN

    entry = ELEMENT_FACETS["LinkDoPlatnosci"]
    assert entry.pattern is PAYMENT_LINK_PATTERN


def test_patterns_reject_values_the_schema_rejects() -> None:
    r"""Wzorzec w tabeli nie może być łagodniejszy niż wzorzec schematu.

    Samo sprawdzenie, że poprawna wartość przechodzi, nie wykrywa osłabienia
    wzorca (np. zamiany wzorca NIP na ``\d{10}``) — trzeba dowieść, że wartości
    spoza schematu są odrzucane.
    """
    problems: list[str] = []
    for element, invalid_values in sorted(_PATTERN_MUST_REJECT.items()):
        entry = ELEMENT_FACETS[element]
        for value in invalid_values:
            # Sam wzorzec: długość nie rozstrzyga, bo 35/36 znaków może być
            # poprawne wymiarowo, a niepoprawne co do zawartości grup hex.
            if entry.pattern is not None and entry.pattern.fullmatch(value):
                problems.append(f"{element}: wzorzec akceptuje {value!r}")
    assert not problems, "\n".join(problems)


def test_patterns_accept_values_the_schema_accepts() -> None:
    """Wzorzec nie może być ostrzejszy niż schemat."""
    valid = {
        "NIP": "1111111111",
        "IDWew": "1111111111-00001",
        "SWIFT": "DEUTDEFF",
        "KRS": "0000111111",
        "REGON": "12345678901234",
        "IPKSeF": "123abc456DEFG",
        "NrKSeFFaKorygowanej": "1111111111-20260101-AAAAAA-BBBBBB-01",
        "NrKSeFFaZaliczkowej": "1111111111-20260101-AAAAAABBBBBB-01",
        "LinkDoPlatnosci": _VALID_PAYMENT_LINK,
    }
    problems: list[str] = []
    for element, value in sorted(valid.items()):
        entry = ELEMENT_FACETS[element]
        if entry.pattern is not None and not entry.pattern.fullmatch(value):
            problems.append(f"{element}: wzorzec odrzuca poprawną wartość {value!r}")
        if entry.facet.lengths is not None and len(value) not in entry.facet.lengths:
            problems.append(f"{element}: długość {len(value)} odrzucona dla {value!r}")
    assert not problems, "\n".join(problems)


def test_patterns_come_from_the_declared_xsd_type(
    xsd_types: dict[str, ET.Element], xsd_declared_types: dict[str, set[str]]
) -> None:
    """Wzorzec w tabeli musi być zgodny ze wzorcem typu zadeklarowanego w schemacie.

    Porównujemy zbiory wartości akceptowanych na reprezentatywnej próbce: wzorzec
    tabeli nie może przyjmować niczego, co odrzuca schemat, ani odwrotnie.
    """
    from itertools import product

    alphabet = "0123456789ABCDEFabcdef-"
    samples = [
        "".join(chars)
        for length in (8, 9, 10, 11, 13, 14, 16, 35, 36)
        for chars in list(product(alphabet[:8], repeat=min(length, 3)))
    ]
    problems: list[str] = []
    checked = 0
    for element, entry in sorted(ELEMENT_FACETS.items()):
        if entry.pattern is None:
            continue
        declared = xsd_declared_types.get(element)
        if not declared:
            continue
        schema_patterns: list[str] = []
        for type_name in declared:
            resolved = _resolve(type_name, xsd_types)
            if resolved.get("pattern"):
                schema_patterns.append(resolved["pattern"])
        if not schema_patterns:
            continue
        checked += 1
        compiled = [re.compile(p) for p in schema_patterns]
        for sample in samples:
            table_ok = bool(entry.pattern.fullmatch(sample))
            schema_ok = any(p.fullmatch(sample) for p in compiled)
            if table_ok and not schema_ok:
                problems.append(f"{element}: tabela akceptuje {sample!r}, schemat nie")
                break
    assert checked >= 3, f"test sprawdził tylko {checked} elementów ze wzorcem"
    assert not problems, "\n".join(problems)


def _inline_restriction(element_name: str) -> dict[str, str]:
    """Facety z inline `xsd:simpleType/xsd:restriction` danego elementu.

    Część elementów FA(3) ma ograniczenia wpisane wprost w deklarację (np.
    ``IPKSeF``: ``maxLength=13`` na bazie ``TZnakowy20``, ``SWIFT``: sam wzorzec).
    Wtedy o dopuszczalnych wartościach decyduje ta deklaracja, a nie typ bazowy.
    """
    for name in XSD_FILES:
        root = ET.parse(SCHEMAS / name).getroot()
        for node in root.iter(f"{_XSD}element"):
            if node.get("name") != element_name:
                continue
            restriction = node.find(f"{_XSD}simpleType/{_XSD}restriction")
            if restriction is None:
                continue
            return {
                child.tag.replace(_XSD, ""): child.get("value") or ""
                for child in restriction
            }
    return {}


#: Elementy z inline wzorcem: wzorzec tabeli musi akceptować dokładnie to samo,
#: co wzorzec schematu (na wspólnej próbce).
_INLINE_PATTERN_ELEMENTS = ("SWIFT", "IPKSeF", "LinkDoPlatnosci")


def test_inline_patterns_match_the_element_declaration() -> None:
    """Wzorzec tabeli nie może być łagodniejszy ani ostrzejszy od inline wzorca."""
    samples = [
        "",
        "123",
        "123abc456DEFG",
        "12abc456DEFG",
        "123abc456DEFGH",
        "DEUTDEFF",
        "DEUTDEFF5",
        "DEUTDEFF50",
        "deutdeff",
        "DEUTDEFF500",
        "https://pay.example.com/i?IPKSeF=123abc456DEFG",
        "https://pay.example.com/i",
        "https://pay.example.com/i?IPKSeF=12abc456DEFG",
        "https://pay.example.com/i?IPKSeF=123abc456DEFGH",
        "http://a.pl/x?y=1&IPKSeF=123abc456DEFG#f",
    ]
    problems: list[str] = []
    checked = 0
    for element in _INLINE_PATTERN_ELEMENTS:
        entry = ELEMENT_FACETS[element]
        inline = _inline_restriction(element)
        schema_pattern = inline.get("pattern")
        if not schema_pattern or entry.pattern is None:
            continue
        checked += 1
        compiled = re.compile(schema_pattern)
        for sample in samples:
            table_ok = bool(entry.pattern.fullmatch(sample))
            schema_ok = bool(compiled.fullmatch(sample))
            if table_ok != schema_ok:
                problems.append(
                    f"{element}: {sample!r} tabela={table_ok} schemat={schema_ok}"
                )
    # `IPKSeF` i `LinkDoPlatnosci` mają wzorzec wpisany wprost w deklarację
    # elementu; `SWIFT` używa typu nazwanego (patrz test niżej), więc wypada
    # z porównania.
    assert checked >= 2, f"test sprawdził tylko {checked} elementów z inline wzorcem"
    assert not problems, "\n".join(problems)


def test_inline_length_bounds_match_the_element_declaration() -> None:
    """`lengths`/`max_length` muszą mieścić się w granicach inline `maxLength`."""
    problems: list[str] = []
    checked = 0
    for element in _INLINE_PATTERN_ELEMENTS + ("BDO", "IDNabywcy"):
        entry = ELEMENT_FACETS[element]
        inline = _inline_restriction(element)
        max_length = inline.get("maxLength")
        if not max_length:
            continue
        checked += 1
        limit = int(max_length)
        if entry.facet.lengths is not None:
            if max(entry.facet.lengths) > limit:
                problems.append(
                    f"{element}: tabela lengths={sorted(entry.facet.lengths)} "
                    f"przekracza inline maxLength={limit}"
                )
        elif entry.facet.max_length is not None and entry.facet.max_length > limit:
            problems.append(
                f"{element}: tabela max_length={entry.facet.max_length} "
                f"przekracza inline maxLength={limit}"
            )
    assert checked >= 2, f"test sprawdził tylko {checked} elementów z inline maxLength"
    assert not problems, "\n".join(problems)


def test_swift_pattern_and_lengths_match_the_named_type(
    xsd_types: dict[str, ET.Element], xsd_declared_types: dict[str, set[str]]
) -> None:
    """`SWIFT_Type` dopuszcza 8 albo 11 znaków — tabela nie może dopuścić 9/10."""
    entry = ELEMENT_FACETS["SWIFT"]
    declared = xsd_declared_types["SWIFT"]
    patterns = {
        _resolve(type_name, xsd_types).get("pattern")
        for type_name in declared
    } - {None}
    assert patterns, "SWIFT nie ma wzorca w schemacie"
    compiled = [re.compile(p) for p in patterns]
    samples = [f"DEUTDEFF{n}" for n in ("", "0", "00", "000", "0000")]
    for sample in samples:
        schema_ok = any(p.fullmatch(sample) for p in compiled)
        table_ok = bool(entry.pattern and entry.pattern.fullmatch(sample))
        assert table_ok == schema_ok, f"{sample!r}: tabela={table_ok} schemat={schema_ok}"
        assert schema_ok == (len(sample) in {8, 11})


def test_lengths_match_the_lengths_allowed_by_the_schema_pattern() -> None:
    """`lengths` musi odpowiadać zbiorowi długości dopuszczonych przez wzorzec.

    Dla `SWIFT` schemat nie podaje `minLength`/`maxLength` — o dopuszczalnych
    długościach decyduje wzorzec `[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?`, czyli
    dokładnie 8 albo 11 znaków. Usunięcie 11 z tabeli pozwoliłoby wyemitować
    numer SWIFT, który KSeF odrzuci.
    """
    # Próbka dla SWIFT musi mieć DOKŁADNIE długość `n`, inaczej wzorzec dopasuje
    # krótszy prefiks i zbiór „dozwolonych długości" wyjdzie fałszywie szeroki.
    probe = {
        "SWIFT": lambda n: ("DEUTDEFF" + "0" * n)[:n],
    }
    for element, build in sorted(probe.items()):
        entry = ELEMENT_FACETS[element]
        assert entry.facet.lengths is not None, element
        declared = _xsd_declared_types_cached()
        patterns = {
            _resolve(type_name, _xsd_types_cached()).get("pattern")
            for type_name in declared.get(element, set())
        } - {None}
        assert patterns, f"{element}: brak wzorca w schemacie"
        compiled = [re.compile(p) for p in patterns]
        allowed = {
            length
            for length in range(1, 21)
            if any(p.fullmatch(build(length)) for p in compiled)
        }
        assert allowed, f"{element}: nie znaleziono żadnej dozwolonej długości"
        assert entry.facet.lengths == frozenset(allowed), (
            f"{element}: tabela={sorted(entry.facet.lengths)} wzorzec={sorted(allowed)}"
        )


_XSD_TYPES_CACHE: dict[str, ET.Element] | None = None
_XSD_DECLARED_CACHE: dict[str, set[str]] | None = None


def _xsd_types_cached() -> dict[str, ET.Element]:
    global _XSD_TYPES_CACHE
    if _XSD_TYPES_CACHE is None:
        _XSD_TYPES_CACHE = _xsd_simple_types()
    return _XSD_TYPES_CACHE


def _xsd_declared_types_cached() -> dict[str, set[str]]:
    global _XSD_DECLARED_CACHE
    if _XSD_DECLARED_CACHE is None:
        _XSD_DECLARED_CACHE = _xsd_declared_type_map()
    return _XSD_DECLARED_CACHE


def test_required_and_occurrence_tables_cover_the_schema(
    xsd_children: dict[tuple[str, str], tuple[str | None, str | None]],
) -> None:
    """Tabele muszą pokrywać KAŻDĄ parę, którą schemat czyni wymaganą/jednokrotną.

    Poprzednie testy sprawdzały tylko, że wpisy tabeli istnieją w schemacie —
    więc USUNIĘCIE wpisu przechodziło na zielono. Ten test wyprowadza oczekiwany
    zbiór z XSD i porównuje go z tabelą, więc raportuje konkretne braki.
    """
    required_expected = {
        key
        for key, (min_occurs, _max) in xsd_children.items()
        if min_occurs not in (None, "0")
    }
    missing_required = sorted(required_expected - REQUIRED_IN_PARENT)
    assert not missing_required, (
        "pary wymagane w schemacie, których brak w REQUIRED_IN_PARENT: "
        + ", ".join(f"{p}/{c}" for p, c in missing_required[:40])
        + (f" (+{len(missing_required) - 40} więcej)" if len(missing_required) > 40 else "")
    )

    single_expected = {
        key
        for key, (_min, max_occurs) in xsd_children.items()
        if max_occurs == "1"
    }
    missing_limits = sorted(
        key for key in single_expected if occurrence_limit(*key) != 1
    )
    assert not missing_limits, (
        "pary jednokrotne w schemacie bez limitu w tabeli: "
        + ", ".join(f"{p}/{c}" for p, c in missing_limits[:40])
        + (f" (+{len(missing_limits) - 40} więcej)" if len(missing_limits) > 40 else "")
    )
