"""Podstawy silnika faset: wymagania zależne od przodka, wartości stałe, liczność.

Ten plik powstał, żeby commit z tabelą faset (`d6dcfff`) sam przechodził bramkę
`--cov-fail-under=100`: sprawdza ścieżki `_check_required` (wymagania zależne od
przodka), `_check_occurrences` (limity liczności) i wartości stałe z
`FIXED_IN_PARENT` — bez odwołań do warstwy domenowej.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

from ksef_client.documents.fa3.validation import validate_xml_facets

NAMESPACE = "http://crd.gov.pl/wzor/2025/06/25/13775/"


def _invoice(body: str) -> ET.Element:
    return ET.fromstring(f'<Faktura xmlns="{NAMESPACE}">{body}</Faktura>')


def _party(name: str, *, inner: str) -> str:
    return f"<{name}>{inner}</{name}>"


def test_missing_name_under_podmiot1_is_reported() -> None:
    """`Nazwa` jest wymagana w `TPodmiot1` (wymaganie zależne od przodka)."""
    document = _invoice(
        _party(
            "Podmiot1",
            inner="<DaneIdentyfikacyjne><NIP>1111111111</NIP></DaneIdentyfikacyjne>",
        )
    )

    issues = validate_xml_facets(document)

    assert any(
        issue.element == "Nazwa" and "Podmiot1/DaneIdentyfikacyjne" in issue.message
        for issue in issues
    ), [str(issue) for issue in issues]


def test_missing_name_under_podmiot2_is_accepted() -> None:
    """Ta sama nazwa elementu pod `Podmiot2` nie jest wymagana (faktura uproszczona)."""
    document = _invoice(
        _party(
            "Podmiot2",
            inner="<DaneIdentyfikacyjne><NIP>2222222222</NIP></DaneIdentyfikacyjne>",
        )
    )

    issues = validate_xml_facets(document)

    assert not [issue for issue in issues if issue.element == "Nazwa"]


def test_occurrence_limit_is_reported() -> None:
    """`DaneKontaktowe` ma w schemacie `maxOccurs="3"`."""
    contacts = (
        "<DaneKontaktowe><Email>a@example.com</Email></DaneKontaktowe>"
        "<DaneKontaktowe><Email>b@example.com</Email></DaneKontaktowe>"
        "<DaneKontaktowe><Email>c@example.com</Email></DaneKontaktowe>"
        "<DaneKontaktowe><Email>d@example.com</Email></DaneKontaktowe>"
    )
    document = _invoice(
        _party(
            "Podmiot1",
            inner=(
                "<DaneIdentyfikacyjne><NIP>1111111111</NIP><Nazwa>Firma</Nazwa>"
                "</DaneIdentyfikacyjne>"
                f"{contacts}"
            ),
        )
    )

    issues = validate_xml_facets(document)

    assert any(
        issue.element == "DaneKontaktowe" and "maksymalnie 3" in issue.message
        for issue in issues
    ), [str(issue) for issue in issues]


def test_fixed_prefix_other_than_pl_is_reported() -> None:
    """`Podmiot1/PrefiksPodatnika` ma w schemacie `fixed="PL"`."""
    document = _invoice(
        _party(
            "Podmiot1",
            inner=(
                "<PrefiksPodatnika>DE</PrefiksPodatnika>"
                "<DaneIdentyfikacyjne><NIP>1111111111</NIP><Nazwa>Firma</Nazwa>"
                "</DaneIdentyfikacyjne>"
            ),
        )
    )

    issues = validate_xml_facets(document)

    assert any(
        issue.element == "PrefiksPodatnika" and "PL" in issue.message for issue in issues
    ), [str(issue) for issue in issues]


def test_valid_minimal_parties_have_no_issues() -> None:
    """Kontrola: poprawni podmioty nie generują zgłoszeń z tych trzech kontroli.

    Minimalny dokument nie ma wszystkich elementów wymaganych przez schemat
    (np. `Naglowek`), więc sprawdzamy tylko, że nie pojawia się nic z zakresu
    wymagań zależnych od przodka, liczności kontaktów ani wartości stałej.
    """
    document = _invoice(
        _party(
            "Podmiot1",
            inner=(
                "<PrefiksPodatnika>PL</PrefiksPodatnika>"
                "<DaneIdentyfikacyjne><NIP>1111111111</NIP><Nazwa>Firma</Nazwa>"
                "</DaneIdentyfikacyjne>"
                "<DaneKontaktowe><Email>a@example.com</Email></DaneKontaktowe>"
            ),
        )
        + _party(
            "Podmiot2",
            inner="<DaneIdentyfikacyjne><NIP>2222222222</NIP></DaneIdentyfikacyjne>",
        )
        + "<Fa><RodzajFaktury>VAT</RodzajFaktury><P_15>0.00</P_15></Fa>"
    )

    issues = validate_xml_facets(document)

    assert not [
        issue
        for issue in issues
        if issue.element in {"Nazwa", "DaneKontaktowe", "PrefiksPodatnika"}
    ], [str(issue) for issue in issues]
