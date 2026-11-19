"""Offline validation of original invoice bytes with diagnostics safe for CI logs."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from decimal import Context, Decimal, localcontext
from functools import lru_cache
from typing import Any

from .domain import _CORRECTION_KINDS, _KINDS_REQUIRING_LINES, ThirdPartyRole
from .models import FA3InvoiceKind
from .parse import MAX_XML_BYTES, _as_bytes, _reject_dtd, _XmlStructureLimit
from .validation.facets import facet_for
from .xml import FA3_NAMESPACE, _fa3_schema
from .xsd_audit import parse_fa3_xsd_elements

_MAX_XML_NODES = 250_000
_MAX_XML_DEPTH = 64
_MAX_ISSUES = 50
_NS = {"f": FA3_NAMESPACE}
_ELEMENT = re.compile(r"Element '\{" + re.escape(FA3_NAMESPACE) + r"\}([A-Za-z_0-9]+)'")
_EXPECTED = re.compile(r"Expected is \( \{" + re.escape(FA3_NAMESPACE) + r"\}([A-Za-z_0-9]+) \)")


@dataclass(frozen=True)
class FA3XmlIssue:
    code: str
    message: str
    hint: str
    field: str | None = None
    line: int | None = None


@dataclass(frozen=True)
class FA3XmlReport:
    issues: tuple[FA3XmlIssue, ...] = ()
    truncated: bool = False

    @property
    def valid(self) -> bool:
        return not self.issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "issues": [asdict(issue) for issue in self.issues],
            "truncated": self.truncated,
        }


@lru_cache(maxsize=1)
def _field_names() -> frozenset[str]:
    return frozenset(field.name for field in parse_fa3_xsd_elements())


def _xsd_issue(entry: Any) -> FA3XmlIssue:
    # libxml messages, XPath prefixes and unknown element names can contain invoice data.
    # Only publish identifiers matched against the *bundled* schema.
    match = _ELEMENT.match(entry.message)
    field = match[1] if match and match[1] in _field_names() else None
    code = entry.type_name
    hint = "Sprawdź typ i ograniczenia pola w schemacie FA(3)."
    if code == "SCHEMAV_ELEMENT_CONTENT":
        hint = "Sprawdź wymagane elementy, ich kolejność i liczbę wystąpień."
        expected = _EXPECTED.search(entry.message)
        if expected and expected[1] in _field_names():
            hint += f" Oczekiwany element: {expected[1]}."
    elif field and (facet := facet_for(field)):
        hint = facet.pattern_hint or facet.facet.describe() or hint
    return FA3XmlIssue(code, "Naruszenie schematu FA(3).", hint, field, entry.line or None)


def _business_issues(root: Any) -> list[FA3XmlIssue]:
    """Inspect only conditions derivable from the original, XSD-valid document."""
    issues: list[FA3XmlIssue] = []
    kind_node = root.find("f:Fa/f:RodzajFaktury", _NS)
    kind = FA3InvoiceKind.parse(kind_node.text)
    if kind in _KINDS_REQUIRING_LINES and root.find("f:Fa/f:FaWiersz", _NS) is None:
        issues.append(
            FA3XmlIssue(
                "LINE_REQUIRED",
                "Brak pozycji faktury.",
                "Dodaj co najmniej jeden Fa/FaWiersz dla faktury VAT, UPR lub ROZ.",
                "FaWiersz",
                kind_node.sourceline,
            )
        )
    for applies, field, hint in (
        (
            kind in _CORRECTION_KINDS,
            "DaneFaKorygowanej",
            "Wskaż fakturę korygowaną w Fa/DaneFaKorygowanej.",
        ),
        (
            kind in {FA3InvoiceKind.SETTLEMENT, FA3InvoiceKind.SETTLEMENT_CORRECTION},
            "FakturaZaliczkowa",
            "Podaj odwołanie do faktury zaliczkowej w Fa/FakturaZaliczkowa.",
        ),
    ):
        if applies and root.find(f"f:Fa/f:{field}", _NS) is None:
            issues.append(
                FA3XmlIssue(
                    "REFERENCE_REQUIRED",
                    "Brak odwołania do faktury.",
                    hint,
                    field,
                    kind_node.sourceline,
                )
            )

    for flag, role in (
        ("JST", ThirdPartyRole.JST_SUBUNIT),
        ("GV", ThirdPartyRole.VAT_GROUP_MEMBER),
    ):
        node = root.find(f"f:Podmiot2/f:{flag}", _NS)
        if node is None or Decimal(node.text) != 1:
            continue
        parties = [
            party
            for party in root.findall("f:Podmiot3", _NS)
            if Decimal(party.findtext("f:Rola", "0", _NS)) == int(role.value)
        ]
        if not parties or any(
            party.find("f:DaneIdentyfikacyjne/f:NIP", _NS) is None
            and party.find("f:DaneIdentyfikacyjne/f:IDWew", _NS) is None
            for party in parties
        ):
            issues.append(
                FA3XmlIssue(
                    "PARTY_ROLE_REQUIRED",
                    "Brak kompletnych danych odbiorcy Podmiot3.",
                    f"Sprawdź Podmiot2/{flag} i podaj NIP lub IDWew podmiotu z rolą {role.value}.",
                    flag,
                    node.sourceline,
                )
            )

    settlement = root.find("f:Fa/f:Rozliczenie", _NS)
    if settlement is not None:
        due = settlement.find("f:DoZaplaty", _NS)
        with localcontext(Context(prec=40)):
            expected = Decimal(root.findtext("f:Fa/f:P_15", namespaces=_NS))
            for item, total, sign in (
                ("Obciazenia", "SumaObciazen", 1),
                ("Odliczenia", "SumaOdliczen", -1),
            ):
                lines = settlement.findall(f"f:{item}/f:Kwota", _NS)
                declared = settlement.find(f"f:{total}", _NS)
                amount = sum((Decimal(n.text) for n in lines), Decimal(0))
                if declared is not None:
                    if lines and amount != Decimal(declared.text):
                        issues.append(
                            FA3XmlIssue(
                                "ADJUSTMENT_SUM",
                                "Suma nie odpowiada pozycjom rozliczenia.",
                                f"Zsumuj pola {item}/Kwota.",
                                total,
                                declared.sourceline,
                            )
                        )
                    amount = Decimal(declared.text)
                expected += amount * sign
            if due is not None and Decimal(due.text) != expected:
                issues.append(
                    FA3XmlIssue(
                        "AMOUNT_DUE",
                        "Niespójna kwota do zapłaty.",
                        "Sprawdź równanie DoZaplaty = P_15 + obciążenia − odliczenia.",
                        "DoZaplaty",
                        due.sourceline,
                    )
                )
    return issues


def validate_invoice_xml(xml: bytes | bytearray | str) -> FA3XmlReport:
    """Check the original FA(3) against its offline XSD and documented business rules.

    Requires the `fa3` extra. Reports contain schema field names and locations,
    never document values. The first 50 schema diagnostics are returned.
    """
    from lxml import etree

    limit = FA3XmlIssue(
        "XML_LIMIT",
        "Przekroczono limit walidatora.",
        f"Limit to {MAX_XML_BYTES} bajtów, {_MAX_XML_NODES} elementów i atrybutów "
        f"łącznie oraz {_MAX_XML_DEPTH} poziomy.",
    )
    if len(xml) > MAX_XML_BYTES:
        return FA3XmlReport((limit,))
    try:
        data = _as_bytes(xml)
        if len(data) > MAX_XML_BYTES:
            return FA3XmlReport((limit,))
        _reject_dtd(data, max_nodes=_MAX_XML_NODES, max_depth=_MAX_XML_DEPTH)
        parser = etree.XMLParser(
            no_network=True,
            load_dtd=False,
            resolve_entities=False,
            remove_comments=True,
            remove_pis=True,
        )
        root = etree.fromstring(data, parser)
    except _XmlStructureLimit:
        return FA3XmlReport((limit,))
    except (etree.XMLSyntaxError, LookupError, ValueError) as exc:
        source = exc.__cause__ or exc
        line = getattr(source, "lineno", None)
        issue = FA3XmlIssue(
            "INVALID_XML",
            "Nie można odczytać dokumentu XML.",
            "Sprawdź składnię i kodowanie XML. Deklaracje DTD są niedozwolone.",
            line=line,
        )
        return FA3XmlReport((issue,))

    if root.tag != f"{{{FA3_NAMESPACE}}}Faktura":
        issue = FA3XmlIssue(
            "NOT_FA3",
            "Dokument nie jest fakturą FA(3).",
            "Sprawdź element główny Faktura i przestrzeń nazw FA(3).",
            "Faktura",
            root.sourceline,
        )
        return FA3XmlReport((issue,))
    schema = _fa3_schema(etree)
    if not schema.validate(root):
        errors = schema.error_log
        return FA3XmlReport(
            tuple(_xsd_issue(e) for e in errors[:_MAX_ISSUES]), len(errors) > _MAX_ISSUES
        )
    return FA3XmlReport(tuple(_business_issues(root)))
