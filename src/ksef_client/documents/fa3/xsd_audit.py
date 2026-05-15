from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from importlib import resources
from pathlib import Path
from xml.etree import ElementTree as ET

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


@dataclass(frozen=True)
class XsdCoverageReport:
    elements: tuple[XsdElement, ...]
    coverage: tuple[XsdCoverageEntry, ...]

    def by_status(self, status: CoverageStatus) -> tuple[XsdCoverageEntry, ...]:
        return tuple(entry for entry in self.coverage if entry.status is status)


def audit_fa3_xsd_coverage() -> XsdCoverageReport:
    elements = parse_fa3_xsd_elements()
    coverage = tuple(
        XsdCoverageEntry(
            element.path,
            CoverageStatus.SUPPORTED,
            _coverage_note(element.path),
            domain_field=_domain_field(element.path),
            handler=_handler_name(element.path),
        )
        for element in elements
    )
    return XsdCoverageReport(tuple(elements), coverage)


def parse_fa3_xsd_elements(path: str | Path | None = None) -> list[XsdElement]:
    schema_path = _schema_path(path)
    root = ET.parse(schema_path).getroot()
    simple_enums = _simple_type_enums(root)
    faktura = root.find("xsd:element[@name='Faktura']", XSD_NS)
    if faktura is None:
        return []
    elements: list[XsdElement] = []
    _walk_element(faktura, "/Faktura", elements, simple_enums)
    return elements


def _walk_element(
    node: ET.Element,
    path: str,
    elements: list[XsdElement],
    simple_enums: dict[str, tuple[str, ...]],
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
        _walk_particles(complex_type, path, elements, simple_enums)


def _walk_particles(
    node: ET.Element,
    path: str,
    elements: list[XsdElement],
    simple_enums: dict[str, tuple[str, ...]],
) -> None:
    for child in node:
        if child.tag == f"{{{XSD_NS['xsd']}}}element":
            child_name = child.attrib.get("name")
            if child_name:
                _walk_element(child, f"{path}/{child_name}", elements, simple_enums)
        elif child.tag in {
            f"{{{XSD_NS['xsd']}}}sequence",
            f"{{{XSD_NS['xsd']}}}choice",
            f"{{{XSD_NS['xsd']}}}all",
        }:
            _walk_particles(child, path, elements, simple_enums)


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


def _coverage_note(path: str) -> str:
    if path == "/Faktura":
        return "root invoice document"
    if "/Adnotacje/" in path:
        return "typed annotation section"
    if "/Platnosc/" in path:
        return "typed payment section"
    if "/FaWiersz/" in path or "/ZamowienieWiersz/" in path:
        return "typed line section"
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
