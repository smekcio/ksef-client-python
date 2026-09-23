"""Niezmienniki plików XSD FA(3) dołączonych do pakietu.

README w katalogu `schemas/` deklaruje, że kopie różnią się od źródeł MF wyłącznie
formatowaniem. Ten moduł pilnuje cech możliwych do sprawdzenia offline:

- wszystkie pliki używają `LF` (brak `CR`/`CRLF`), więc walidacja jest niezależna
  od platformy i od `git autocrlf`,
- brak końcowego whitespace poza jednym udokumentowanym wyjątkiem,
- schemat FA(3) definiuje oczekiwane typy i liczbę kodów walut.

Zmiana tych niezmienników wymaga świadomej aktualizacji README, a nie cichego
rozjechania się kopii ze źródłem.
"""

from __future__ import annotations

import re
from importlib import resources

import pytest

SCHEMA_NAMES = (
    "schemat_FA(3)_v1-0E.xsd",
    "ElementarneTypyDanych_v10-0E.xsd",
    "KodyKrajow_v10-0E.xsd",
    "StrukturyDanych_v10-0E.xsd",
)

# Jedyna udokumentowana różnica wobec źródła: w `schemat_FA(3)_v1-0E.xsd` linia 2258
# w oryginale MF ma końcowy whitespace, którego kopia lokalna nie zawiera.
ALLOWED_TRAILING_WHITESPACE: dict[str, set[int]] = {}

# `schemaLocation` celowo wskazuje URL do crd.gov.pl - walidacja offline opiera się
# na `_schema_resolver`, nie na relatywnych ścieżkach.
EXPECTED_SCHEMA_LOCATION_HOST = "crd.gov.pl"


def _schema_bytes(name: str) -> bytes:
    return (resources.files("ksef_client.documents.fa3.schemas") / name).read_bytes()


def _schema_text(name: str) -> str:
    return _schema_bytes(name).decode("utf-8")


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schemas_are_present(name: str) -> None:
    assert len(_schema_bytes(name)) > 0


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schemas_use_lf_line_endings(name: str) -> None:
    """Brak `CR` gwarantuje, że walidacja nie zależy od platformy ani `git autocrlf`."""
    data = _schema_bytes(name)

    assert b"\r\n" not in data, f"{name}: zawiera CRLF"
    assert b"\r" not in data, f"{name}: zawiera samotny CR"


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schemas_have_no_unexpected_trailing_whitespace(name: str) -> None:
    """Końcowy whitespace musi odpowiadać udokumentowanemu stanowi."""
    allowed = ALLOWED_TRAILING_WHITESPACE.get(name, set())
    offending = [
        index
        for index, line in enumerate(_schema_text(name).splitlines(), 1)
        if line != line.rstrip() and index not in allowed
    ]

    assert offending == [], f"{name}: nieoczekiwany trailing whitespace w liniach {offending}"


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schemas_keep_original_schema_location_urls(name: str) -> None:
    """README deklaruje, że adresy URL zostają - walidacja offline działa przez resolver."""
    locations = re.findall(r'schemaLocation="([^"]+)"', _schema_text(name))

    for location in locations:
        assert EXPECTED_SCHEMA_LOCATION_HOST in location, (
            f"{name}: `schemaLocation` {location!r} nie wskazuje na "
            f"{EXPECTED_SCHEMA_LOCATION_HOST}; jeśli zmieniono to świadomie, "
            f"zaktualizuj README w katalogu schemas/"
        )


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schemas_are_well_formed_xml(name: str) -> None:
    from xml.etree import ElementTree

    # Parsowanie potwierdza, że plik nie został uszkodzony przy edycji.
    root = ElementTree.fromstring(_schema_bytes(name))

    assert root.tag.endswith("schema"), f"{name}: korzeń nie jest xsd:schema"


def test_fa3_schema_defines_expected_currency_type() -> None:
    text = _schema_text("schemat_FA(3)_v1-0E.xsd")
    match = re.search(
        r'<xsd:simpleType[^>]*name="TKodWaluty".*?</xsd:simpleType>',
        text,
        re.DOTALL,
    )

    assert match is not None, "brak typu TKodWaluty w schemacie FA(3)"
    codes = re.findall(r'<xsd:enumeration value="([A-Z]{3})"', match.group(0))

    assert len(codes) == 182, f"oczekiwano 182 kodów walut, jest {len(codes)}"
    assert "PLN" in codes and "EUR" in codes
