from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from importlib import resources
from pathlib import Path
from xml.etree import ElementTree as ET

from .xsd_map import RAW_EXTENSION_PATHS, UNSUPPORTED_PATHS

XSD_NS = {"xsd": "http://www.w3.org/2001/XMLSchema"}


class CoverageStatus(str, Enum):
    SUPPORTED = "supported"
    PARTIALLY_SUPPORTED = "partially_supported"
    RAW_EXTENSION = "raw_extension"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class XsdElement:
    path: str
    name: str
    type_name: str | None
    min_occurs: str
    max_occurs: str
    choices: int = 0
    enum_values: tuple[str, ...] = ()


@dataclass(frozen=True)
class XsdCoverageEntry:
    path: str
    status: CoverageStatus
    note: str
    domain_field: str | None = None
    handler: str | None = None
    evidence_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class XsdCoverageReport:
    elements: tuple[XsdElement, ...]
    coverage: tuple[XsdCoverageEntry, ...]

    def by_status(self, status: CoverageStatus) -> tuple[XsdCoverageEntry, ...]:
        return tuple(entry for entry in self.coverage if entry.status is status)


def audit_fa3_xsd_coverage(
    evidence_xml_by_source: Mapping[str, str | bytes] | None = None,
) -> XsdCoverageReport:
    elements = parse_fa3_xsd_elements()
    evidence = _collect_evidence_paths(evidence_xml_by_source or {})
    coverage = tuple(
        _entry_for_element(
            element,
            evidence_sources=tuple(sorted(evidence.get(element.path, ()))),
        )
        for element in elements
    )
    return XsdCoverageReport(tuple(elements), coverage)


def extract_xml_paths(xml_content: str | bytes) -> set[str]:
    xml_bytes = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
    root = ET.fromstring(xml_bytes)
    paths: set[str] = set()

    def walk(node: ET.Element, current_path: str) -> None:
        paths.add(current_path)
        for child in node:
            local_name = _local_xml_name(child.tag)
            walk(child, f"{current_path}/{local_name}")

    walk(root, "/Faktura")
    return paths


#: Pliki schematu składające się na kontrakt FA(3). Struktura siedzi w typach
#: nazwanych rozsianych po wszystkich czterech plikach (schemat główny importuje
#: trzy pozostałe), więc audyt musi je wszystkie sparsować i rozwiązywać
#: referencje `type="tns:X"`.
SCHEMA_FILES: tuple[str, ...] = (
    "schemat_FA(3)_v1-0E.xsd",
    "StrukturyDanych_v10-0E.xsd",
    "ElementarneTypyDanych_v10-0E.xsd",
    "KodyKrajow_v10-0E.xsd",
)


def parse_fa3_xsd_elements(path: str | Path | None = None) -> list[XsdElement]:
    """Zwraca wszystkie elementy FA(3) wraz z ich ścieżkami w drzewie dokumentu.

    Wcześniejsza wersja wchodziła wyłącznie w typy **anonimowe** wpisane wprost
    w deklarację elementu i nie rozwiązywała `type="tns:X"`, przez co nie widziała
    ¼ schematu — w tym elementów wymaganych, takich jak `Naglowek/KodFormularza`,
    `Podmiot1/DaneIdentyfikacyjne/NIP` czy `Platnosc/RachunekBankowy/NrRB`.
    """
    schema_path = _schema_path(path)
    roots = [ET.parse(schema_path).getroot()]
    for name in SCHEMA_FILES[1:]:
        sibling = schema_path.parent / name
        if sibling.exists():
            roots.append(ET.parse(sibling).getroot())

    simple_enums: dict[str, tuple[str, ...]] = {}
    named_types: dict[str, ET.Element] = {}
    for root in roots:
        simple_enums.update(_simple_type_enums(root))
        for complex_type in root.findall(".//xsd:complexType", XSD_NS):
            type_name = complex_type.attrib.get("name")
            if type_name:
                named_types.setdefault(type_name, complex_type)

    faktura = roots[0].find("xsd:element[@name='Faktura']", XSD_NS)
    if faktura is None:
        return []
    elements: list[XsdElement] = []
    _walk_element(faktura, "/Faktura", elements, simple_enums, named_types)
    return elements


def _walk_element(
    node: ET.Element,
    path: str,
    elements: list[XsdElement],
    simple_enums: dict[str, tuple[str, ...]],
    named_types: dict[str, ET.Element],
    seen_types: frozenset[str] = frozenset(),
) -> None:
    type_name = node.attrib.get("type")
    local_type_name = _local_type_name(type_name)
    elements.append(
        XsdElement(
            path=path,
            name=node.attrib.get("name", path.rsplit("/", 1)[-1]),
            type_name=type_name,
            min_occurs=node.attrib.get("minOccurs", "1"),
            max_occurs=node.attrib.get("maxOccurs", "1"),
            choices=len(node.findall(".//xsd:choice", XSD_NS)),
            enum_values=simple_enums.get(local_type_name or "", ()),
        )
    )
    complex_type = node.find("./xsd:complexType", XSD_NS)
    if complex_type is not None:
        _walk_particles(complex_type, path, elements, simple_enums, named_types, seen_types)
        return
    # Referencja do nazwanego typu: bez tego całe poddrzewo zostaje niewidoczne.
    if local_type_name and local_type_name not in seen_types:
        definition = named_types.get(local_type_name)
        if definition is not None:
            _walk_particles(
                definition,
                path,
                elements,
                simple_enums,
                named_types,
                seen_types | {local_type_name},
            )


def _walk_particles(
    node: ET.Element,
    path: str,
    elements: list[XsdElement],
    simple_enums: dict[str, tuple[str, ...]],
    named_types: dict[str, ET.Element],
    seen_types: frozenset[str] = frozenset(),
) -> None:
    for child in node:
        tag = child.tag
        if tag == f"{{{XSD_NS['xsd']}}}element":
            child_name = child.attrib.get("name")
            if child_name:
                _walk_element(
                    child,
                    f"{path}/{child_name}",
                    elements,
                    simple_enums,
                    named_types,
                    seen_types,
                )
        elif (
            tag
            in {
                f"{{{XSD_NS['xsd']}}}sequence",
                f"{{{XSD_NS['xsd']}}}choice",
                f"{{{XSD_NS['xsd']}}}all",
                f"{{{XSD_NS['xsd']}}}complexContent",
                f"{{{XSD_NS['xsd']}}}extension",
                f"{{{XSD_NS['xsd']}}}restriction",
                f"{{{XSD_NS['xsd']}}}group",
            }
            or tag == f"{{{XSD_NS['xsd']}}}complexType"
        ):
            _walk_particles(child, path, elements, simple_enums, named_types, seen_types)


def _simple_type_enums(root: ET.Element) -> dict[str, tuple[str, ...]]:
    values: dict[str, tuple[str, ...]] = {}
    for simple_type in root.findall(".//xsd:simpleType", XSD_NS):
        name = simple_type.attrib.get("name")
        if not name:
            continue
        enums = tuple(
            enum.attrib["value"]
            for enum in simple_type.findall(".//xsd:enumeration", XSD_NS)
            if "value" in enum.attrib
        )
        if enums:
            values[name] = enums
    return values


def _local_type_name(type_name: str | None) -> str | None:
    if type_name is None:
        return None
    return type_name.rsplit(":", 1)[-1]


def _local_xml_name(tag: str) -> str:
    if tag.startswith("{"):
        return tag.rsplit("}", 1)[-1]
    return tag


def _collect_evidence_paths(
    evidence_xml_by_source: Mapping[str, str | bytes],
) -> dict[str, set[str]]:
    evidence: dict[str, set[str]] = {}
    for source, xml in evidence_xml_by_source.items():
        for path in extract_xml_paths(xml):
            evidence.setdefault(path, set()).add(source)
    return evidence


def _entry_for_element(
    element: XsdElement,
    *,
    evidence_sources: tuple[str, ...],
) -> XsdCoverageEntry:
    """Ustala status pokrycia na podstawie RZECZYWISTEGO sygnału.

    Wcześniejsza wersja opierała się na `SUPPORTED_BUILDER_PATHS`, który zawierał
    jeden wpis ``/Faktura`` dopasowywany prefiksem — więc **każda** ścieżka
    schematu (łącznie z wymyśloną) dostawała status „mapping exists", a statusy
    ``UNSUPPORTED`` i ``RAW_EXTENSION`` były nieosiągalne. Teraz porównujemy
    nazwę elementu ze znacznikami, które serializer faktycznie wypisuje
    (`_q("...")` w `xml.py`).
    """
    path = element.path
    status: CoverageStatus
    if _match_path(path, RAW_EXTENSION_PATHS):
        status = CoverageStatus.RAW_EXTENSION
    elif _match_path(path, UNSUPPORTED_PATHS):
        status = CoverageStatus.UNSUPPORTED
    elif element.name in _emitted_tags():
        # Element wypisywany przez serializer; z dowodem z testów = SUPPORTED,
        # bez dowodu = PARTIALLY_SUPPORTED (mapowanie istnieje, brakuje testu).
        status = (
            CoverageStatus.SUPPORTED if evidence_sources else CoverageStatus.PARTIALLY_SUPPORTED
        )
    else:
        # Serializer nie zna tego elementu. Jeśli żadne z jego dzieci też nie jest
        # wypisywane, całe poddrzewo jest nieobsługiwane.
        status = CoverageStatus.UNSUPPORTED

    note = _coverage_note(path, status=status, evidence_sources=evidence_sources)
    return XsdCoverageEntry(
        path=path,
        status=status,
        note=note,
        domain_field=_domain_field(path),
        handler=_handler_name(path),
        evidence_sources=evidence_sources,
    )


#: Znaczniki, które serializer faktycznie wypisuje, wczytane raz z `xml.py`.
_EMITTED_TAGS: frozenset[str] | None = None


def _emitted_tags() -> frozenset[str]:
    """Nazwy elementów, które serializer potrafi wypisać.

    Trzy źródła, bo znaczniki trafiają do XML na trzy sposoby:

    1. wprost w ``_q("...")``,
    2. jako argument funkcji pomocniczej (``_party(root, "Podmiot1", ...)``,
       ``_address(node, "AdresKoresp", ...)``, ``_bank_account(node, "RachunekBankowy", ...)``),
    3. z tabel pól podsumowania stawek (``_TAX_SUMMARY_ORDER``, ``_DRAFT_SUMMARY_ORDER``).

    To jedyny wiarygodny sygnał pokrycia: ``SUPPORTED_BUILDER_PATHS`` był ręczną
    mapą, która przez dopasowanie prefiksem obejmowała cały dokument i czyniła
    status ``UNSUPPORTED`` nieosiągalnym.
    """
    global _EMITTED_TAGS
    if _EMITTED_TAGS is None:
        import re

        source = Path(__file__).with_name("xml.py").read_text(encoding="utf-8")
        tags = set(re.findall(r'_q\("([A-Za-z_][A-Za-z0-9_.]*)"\)', source))
        # (2) literały przekazywane jako argument: nazwa zaczyna się wielką literą
        # i nie zawiera spacji — to znacznik XML, nie tekst komunikatu.
        for match in re.finditer(
            r'\(\s*(?:node|root|parent|fa|carrier)?\s*,?\s*"([A-Z][A-Za-z0-9_]*)"', source
        ):
            tags.add(match.group(1))
        # (3) wartości map wybierane warunkowo (np. {"travel": "P_PMarzy_2"}) oraz
        # wszystkie pola podsumowania stawek z tabel i krotek.
        for match in re.finditer(r':\s*"([A-Z][A-Za-z0-9_]*)"', source):
            tags.add(match.group(1))
        for match in re.finditer(r'"(P_1[34]_[0-9A-Za-z_]+)"', source):
            tags.add(match.group(1))
        # (4) znaczniki wybierane warunkowo w wyrażeniach (np.
        # `email_tag = "EmailPU" if authorized else "Email"`).
        tags.update(re.findall(r'"(EmailPU|TelefonPU|Email|Telefon|NrKlienta)"', source))
        _EMITTED_TAGS = frozenset(tags)
    return _EMITTED_TAGS


def _match_path(path: str, path_map: Mapping[str, str]) -> str | None:
    exact = path_map.get(path)
    if exact is not None:
        return exact
    for key in path_map:
        if path.startswith(f"{key}/"):
            return path_map[key]
    return None


def _coverage_note(
    path: str,
    *,
    status: CoverageStatus,
    evidence_sources: tuple[str, ...],
) -> str:
    if evidence_sources:
        return f"validated by scenarios: {', '.join(evidence_sources)}"
    if path == "/Faktura":
        return "root invoice document"
    if status is CoverageStatus.UNSUPPORTED:
        return "element not emitted by the serializer and no test XML evidence"
    if "/Adnotacje/" in path:
        return "typed annotation section"
    if "/Platnosc/" in path:
        return "typed payment section"
    if "/FaWiersz/" in path or "/ZamowienieWiersz/" in path:
        return "typed line section"
    if status is CoverageStatus.PARTIALLY_SUPPORTED:
        return "element emitted by the serializer, but no test XML evidence yet"
    return "typed SDK model and serializer coverage"


def _domain_field(path: str) -> str:
    return "invoice." + path.removeprefix("/Faktura/").replace("/", ".")


def _handler_name(path: str) -> str:
    if path.startswith("/Faktura/Fa/Adnotacje"):
        return "_domain_annotations"
    if path.startswith("/Faktura/Fa/Platnosc"):
        return "_domain_payment"
    if path.startswith("/Faktura/Fa/FaWiersz"):
        return "_domain_line"
    if path.startswith("/Faktura/Fa/Zamowienie"):
        return "_domain_order"
    if path.startswith("/Faktura/Stopka"):
        return "_domain_footer"
    if path.startswith("/Faktura/Zalacznik"):
        return "_attachment"
    return "_domain_invoice"


def _schema_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path)
    schema_package = resources.files("ksef_client.documents.fa3.schemas")
    with resources.as_file(schema_package / "schemat_FA(3)_v1-0E.xsd") as resolved:
        return Path(resolved)
