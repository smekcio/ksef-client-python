from __future__ import annotations

import ast
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
    """Pokrycie jednej ścieżki schematu.

    `handler` to funkcja `xml.py`, która tworzy ten element, `domain_field` —
    etykieta miejsca w dokumencie w konwencji modelu (`invoice.Fa.P_15`), a nie
    odwzorowanie na konkretny atrybut `FA3Invoice`, natomiast `evidence_sources`
    to nazwy scenariuszy testowych, których XML zawiera tę ścieżkę.
    """

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
    """Zbiera ścieżki wszystkich elementów dokumentu (korzeń to ``/Faktura``).

    Przejście jest iteracyjne (jawny stos): rekurencja wywracała się na
    `RecursionError` przy ok. 1000 zagnieżdżonych elementach, czyli na
    dokumencie, który parsuje się bez problemu. Kolejność odwiedzania nie ma
    znaczenia, bo wynikiem jest zbiór.
    """
    xml_bytes = xml_content.encode("utf-8") if isinstance(xml_content, str) else xml_content
    root = ET.fromstring(xml_bytes)
    paths: set[str] = set()

    stack: list[tuple[ET.Element, str]] = [(root, "/Faktura")]
    while stack:
        node, current_path = stack.pop()
        paths.add(current_path)
        for child in node:
            stack.append((child, f"{current_path}/{_local_xml_name(child.tag)}"))
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
    """Ustala status pokrycia elementu schematu.

    Reguły są trzy, a żadna nie polega na dopasowaniu prefiksu ścieżki (dawny
    `SUPPORTED_BUILDER_PATHS` zawierał sam wpis ``/Faktura`` i obejmował
    prefiksem cały dokument, więc każda ścieżka — także wymyślona — wychodziła
    jako „pokryta"):

    1. jawne mapy z `xsd_map` (``RAW_EXTENSION_PATHS``, ``UNSUPPORTED_PATHS``)
       mają pierwszeństwo — to jedyne miejsce na świadomą decyzję o ścieżce,
    2. znacznik wypisywany przez serializer (`_emitted_tags`) daje ``SUPPORTED``,
       gdy dokument z tą ścieżką jest w dowodach z testów, a bez dowodu
       ``PARTIALLY_SUPPORTED`` (serializer potrafi, test tego nie pokrywa),
    3. znacznik, którego serializer nie wypisuje w żadnym miejscu `xml.py`,
       daje ``UNSUPPORTED``.

    Pomiar na schemacie FA(3) v1-0E (402 ścieżki, 288 różnych nazw elementów):
    serializer wypisuje **każdą** z tych nazw, więc ``UNSUPPORTED`` jest dla tego
    schematu pusty z powodu kompletności SDK, a nie ekstrakcji znaczników.
    Status pozostaje osiągalny dla elementu spoza serializatora (dryf schematu)
    i test na to istnieje.
    """
    path = element.path
    status: CoverageStatus
    if _match_path(path, RAW_EXTENSION_PATHS):
        status = CoverageStatus.RAW_EXTENSION
    elif _match_path(path, UNSUPPORTED_PATHS):
        status = CoverageStatus.UNSUPPORTED
    elif element.name in _emitted_tags():
        # Element wypisywany przez serializer; z dowodem z testów = SUPPORTED,
        # bez dowodu = PARTIALLY_SUPPORTED (serializer potrafi, test nie pokrywa).
        status = (
            CoverageStatus.SUPPORTED if evidence_sources else CoverageStatus.PARTIALLY_SUPPORTED
        )
    else:
        # Serializer nie wypisuje takiego znacznika w żadnym miejscu: elementu
        # nie da się wyemitować (np. nowy element schematu przed implementacją).
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


#: Znaczniki wypisywane przez `xml.py` -> funkcje, które je tworzą (w kolejności
#: występowania w pliku). Pusty napis oznacza poziom modułu, np. tabelę
#: `_TAX_SUMMARY_ORDER`, której znaczniki przypisujemy funkcjom jej używającym.
_EMISSION_SITES: dict[str, tuple[str, ...]] | None = None

#: Funkcje `xml.py`, którym nazwa elementu jest przekazywana argumentem. To
#: jedyne miejsca, w których znacznik nie stoi wprost w ``_q(...)``.
_TAG_ARGUMENT_FUNCTIONS = frozenset({"_party", "_domain_party", "_address", "_bank_account"})

#: Funkcje `xml.py` osiągalne z typowanego serializatora ``invoice_to_xml``.
_TYPED_FUNCTIONS: frozenset[str] | None = None


def _emitted_tags() -> frozenset[str]:
    """Nazwy elementów, które serializer FA(3) faktycznie potrafi wypisać.

    Źródłem jest drzewo AST `xml.py` i wzorce emisji opisane w `_tag_literals` —
    a nie „dowolny napis zaczynający się wielką literą", bo poprzednie wyrażenia
    regularne wciągały do zbioru także napisy, które znacznikami nie są (np. nazwę
    atrybutu ``Typ`` z ``column.set("Typ", ...)``). Dzięki temu zbiór odpowiada
    dokładnie temu, co serializer wypisuje: pomiar na schemacie FA(3) v1-0E daje
    288 różnych nazw, czyli wszystkie nazwy elementów schematu.
    """
    return frozenset(_emission_sites())


def _emission_sites() -> dict[str, tuple[str, ...]]:
    """Mapa „znacznik -> funkcje `xml.py`, które go tworzą"."""
    global _EMISSION_SITES
    if _EMISSION_SITES is None:
        _EMISSION_SITES = _scan_emissions(_xml_module_tree())
    return _EMISSION_SITES


def _xml_module_tree() -> ast.Module:
    source = Path(__file__).with_name("xml.py").read_text(encoding="utf-8")
    return ast.parse(source)


def _scan_emissions(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    """Zbiera miejsca emisji znaczników wraz z funkcjami, które je tworzą.

    Kolejność właścicieli odpowiada kolejności w pliku, bo ona rozstrzyga wybór
    handlera, gdy ten sam znacznik wypisuje kilka funkcji (np. `P_7` w typowanym
    ``_domain_line`` oraz w zgodnościowym ``_invoice``).
    """
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    constants = _module_tag_constants(tree)
    sites: dict[str, list[str]] = {}
    for node in sorted(ast.walk(tree), key=lambda item: getattr(item, "lineno", 0)):
        owner = _emission_owner(node, parents)
        for tag in _tag_literals(node, constants):
            owners = sites.setdefault(tag, [])
            if owner not in owners:
                owners.append(owner)
    return {tag: tuple(owners) for tag, owners in sites.items()}


def _emission_owner(node: ast.AST, parents: Mapping[ast.AST, ast.AST]) -> str:
    """Funkcja, która tworzy element o znaczniku z tego węzła.

    Dla znacznika przekazanego argumentem (``_address(node, "Adres", ...)``)
    twórcą jest funkcja pomocnicza, bo to ona wywołuje ``ET.SubElement``.
    """
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _TAG_ARGUMENT_FUNCTIONS
    ):
        return node.func.id
    return _enclosing_function(node, parents)


def _module_tag_constants(tree: ast.Module) -> dict[str, tuple[str, ...]]:
    """Tabele znaczników z poziomu modułu, np. ``_TAX_SUMMARY_ORDER``.

    Znaczniki z tabeli nie mają właściciela w miejscu definicji, więc
    `_scan_emissions` przypisuje je funkcjom, które odwołują się do jej nazwy.
    Bierzemy wyłącznie przypisania literałów kolekcji — zwykła stała tekstowa
    (``KOD_WALUTY_LOCAL_NAME = "KodWaluty"``) znacznikiem nie jest, choć sam
    napis wygląda jak nazwa elementu.
    """
    constants: dict[str, tuple[str, ...]] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, (ast.Tuple, ast.List, ast.Set, ast.Dict)):
            continue
        tags = _literal_tags(node.value)
        if not tags:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                constants[target.id] = tags
    return constants


def _tag_literals(node: ast.AST, constants: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Znaczniki wypisywane przez jeden węzeł AST.

    Serializer trafia z nazwą elementu do XML-a na cztery sposoby:

    1. ``_q("Tag")`` — znacznik wprost w miejscu emisji,
    2. ``_party(root, "Podmiot1", ...)`` — znacznik argumentem funkcji tworzącej
       element (`_party`, `_domain_party`, `_address`, `_bank_account`),
    3. literał kolekcji: tabele stawek (``_TAX_SUMMARY_ORDER``), słowniki
       wariantów (``basis_tag``, ``tag``) i pętla ``for tag in ("P_16", ...)``,
    4. wyrażenie warunkowe wybierające jeden z dwóch znaczników
       (``email_tag = "EmailPU" if authorized else "Email"``).

    Piąty wzorzec to odwołanie do tabeli znaczników z poziomu modułu
    (``_q(net_tag)`` w pętli po ``_TAX_SUMMARY_ORDER``) — takie znaczniki
    przypisujemy funkcji, która tabeli używa.
    """
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        values = [
            argument.value
            for argument in node.args
            if isinstance(argument, ast.Constant) and isinstance(argument.value, str)
        ]
        if node.func.id == "_q":
            return tuple(values)
        if node.func.id in _TAG_ARGUMENT_FUNCTIONS:
            return tuple(value for value in values if _is_tag_literal(value))
        return ()
    if isinstance(node, (ast.Tuple, ast.List, ast.Set, ast.Dict, ast.IfExp)):
        return _literal_tags(node)
    if isinstance(node, ast.Name) and node.id in constants:
        return constants[node.id]
    return ()


def _literal_tags(node: ast.AST) -> tuple[str, ...]:
    """Znaczniki z literału kolekcji albo z wyrażenia warunkowego."""
    values: set[str] = set()
    for child in ast.walk(node):
        value = child.value if isinstance(child, ast.Constant) else None
        if isinstance(value, str) and _is_tag_literal(value):
            values.add(value)
    return tuple(sorted(values))


def _is_tag_literal(value: str) -> bool:
    """Czy napis wygląda jak nazwa elementu FA(3), a nie jak komunikat lub wartość.

    Nazwy elementów zaczynają się wielką literą ASCII i składają wyłącznie
    z liter, cyfr oraz podkreśleń (`P_13_6_1`, `AdresL1`, `EmailPU`). Dlatego
    zdania komunikatów (spacje, kropki, ukośniki) i wartości pól (``"0 KR"``,
    ``"płatność mobilna"``) nie są brane za znaczniki.
    """
    body = value.replace("_", "")
    return bool(value) and value.isascii() and value[0].isupper() and body.isalnum()


def _enclosing_function(node: ast.AST, parents: Mapping[ast.AST, ast.AST]) -> str:
    """Nazwa funkcji, w której ciele leży węzeł ("" dla poziomu modułu)."""
    current = node
    while current in parents:
        current = parents[current]
        if isinstance(current, ast.FunctionDef):
            return current.name
    return ""


def _typed_functions() -> frozenset[str]:
    """Funkcje `xml.py` osiągalne z typowanego serializatora ``invoice_to_xml``.

    Te same znaczniki emituje zarówno typowane SDK (``invoice_to_xml``), jak
    i zgodnościowy draft (``draft_to_xml``). Raport nazywa handlerem funkcję
    z typowanej ścieżki, bo tylko ona należy do modelu FA(3) — inaczej np.
    `Adres` wskazywałby na ``_party``, czyli emiter draftu.
    """
    global _TYPED_FUNCTIONS
    if _TYPED_FUNCTIONS is None:
        call_graph: dict[str, set[str]] = {}
        for node in ast.walk(_xml_module_tree()):
            if isinstance(node, ast.FunctionDef):
                call_graph[node.name] = {
                    child.func.id
                    for child in ast.walk(node)
                    if isinstance(child, ast.Call) and isinstance(child.func, ast.Name)
                }
        reachable = {"invoice_to_xml"}
        pending = ["invoice_to_xml"]
        while pending:
            for callee in call_graph.get(pending.pop(), ()):
                if callee not in reachable:
                    reachable.add(callee)
                    pending.append(callee)
        _TYPED_FUNCTIONS = frozenset(reachable)
    return _TYPED_FUNCTIONS


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
    """Etykieta ścieżki w konwencji modelu (`invoice.Fa.FaWiersz.P_7`).

    Nazwa jest wyprowadzona ze ścieżki XSD, a nie z atrybutów `FA3Invoice` —
    służy temu, by w raporcie od razu było widać, o które miejsce dokumentu chodzi.
    """
    return "invoice." + path.removeprefix("/Faktura/").replace("/", ".")


def _handler_name(path: str) -> str:
    """Funkcja `xml.py`, która tworzy element spod tej ścieżki.

    Wcześniejsza wersja trzymała ręczną tabelę prefiksów, przez co np.
    `WarunkiTransakcji` i `Transport` raportowano jako ``_domain_invoice``, mimo
    że tworzą je ``_domain_transaction_terms`` i ``_domain_transport``. Teraz
    handler wynika z miejsc emisji znacznika: wybieramy funkcję z typowanego
    serializatora, a przy kilku kandydatach rozstrzyga kontekst rodzica (ta sama
    funkcja tworzy też element nadrzędny).
    """
    *ancestors, name = path.split("/")
    sites = tuple(site for site in _emission_sites().get(name, ()) if site)
    typed = tuple(site for site in sites if site in _typed_functions())
    candidates = typed or sites
    if ancestors:
        parent_sites = _emission_sites().get(ancestors[-1], ())
        shared = tuple(site for site in candidates if site in parent_sites)
        candidates = shared or candidates
    return (candidates or ("_domain_invoice",))[0]


def _schema_path(path: str | Path | None) -> Path:
    if path is not None:
        return Path(path)
    schema_package = resources.files("ksef_client.documents.fa3.schemas")
    with resources.as_file(schema_package / "schemat_FA(3)_v1-0E.xsd") as resolved:
        return Path(resolved)
