"""Walidacja walut FA(3): preflight, ostrzeżenia i brak zależności od sieci."""

from __future__ import annotations

import socket
import warnings
from datetime import date
from unittest.mock import patch

import pytest

from ksef_client.documents.fa3 import FA3InvoiceBuilder, FA3Party
from ksef_client.documents.fa3.currency import (
    Fa3CurrencyMismatchError,
    is_fa3_currency_supported,
    validate_fa3_currency,
)
from ksef_client.documents.fa3.xml import (
    FA3XmlValidationError,
    validate_fa3_xml_xsd,
)
from ksef_client.models import CurrencyCode


def _invoice_xml(currency: str, *, xsd_validate: bool) -> bytes:
    draft = (
        FA3InvoiceBuilder(
            invoice_number="FV/TEST/1",
            issue_date=date(2026, 9, 23),
            seller=FA3Party(name="Sprzedawca", tax_id="1234567890", address="ul. Prosta 1"),
            buyer=FA3Party(name="Nabywca", tax_id="1111111111", address="ul. Jasna 2"),
            currency=currency,
            issue_place="Warszawa",
        )
        .add_line("Usluga", quantity="1", unit_net_price="100", vat_rate="23")
        .build()
    )
    return draft.to_xml(xsd_validate=xsd_validate)


# --- P1: preflight musi łapać walutę niezależnie od formy XML ---


@pytest.mark.parametrize(
    "xml",
    [
        '<KodWaluty>CNH</KodWaluty>',
        '<KodWaluty> CNH </KodWaluty>',
        '<x:KodWaluty xmlns:x="urn:test">CNH</x:KodWaluty>',
        '<KodWaluty >CNH</KodWaluty >',
        '<KodWaluty>cnh</KodWaluty>',
    ],
)
def test_preflight_detects_currency_regardless_of_xml_form(xml: str) -> None:
    """Regex gubił prefiks namespace i spacje - parsowanie XML musi być odporne."""
    with pytest.raises(FA3XmlValidationError) as ctx:
        validate_fa3_xml_xsd(xml)
    assert "CNH" in str(ctx.value)


def test_preflight_detects_currency_in_waluta_umowna() -> None:
    """`WalutaUmowna` ma ten sam typ `TKodWaluty`, więc podlega tej samej kontroli.

    Wcześniejsza wersja sprawdzała wyłącznie `KodWaluty`, przez co waluta umowna
    z kodem spoza FA(3) przechodziła preflight i warning bez sygnału, a odrzucał
    ją dopiero schemat - czyli dokładnie ten mylący błąd, który moduł ma tłumaczyć.
    """
    xml = '<Faktura><WalutaUmowna>CNH</WalutaUmowna></Faktura>'

    with pytest.raises(FA3XmlValidationError) as ctx:
        validate_fa3_xml_xsd(xml)

    assert "CNH" in str(ctx.value)
    assert "OpenAPI" in str(ctx.value)


def test_preflight_ignores_currency_text_outside_currency_elements() -> None:
    """Wyszukiwanie działa po nazwie elementu, nie po dowolnym wystąpieniu tekstu."""
    xml = '<Faktura><Opis>CNH</Opis></Faktura>'

    with pytest.raises(FA3XmlValidationError) as ctx:
        validate_fa3_xml_xsd(xml)

    # Brak elementu walutowego -> komunikat pochodzi z walidacji schematu,
    # a nie z preflight o rozjeździe słowników.
    assert "OpenAPI" not in str(ctx.value)


def test_warning_covers_waluta_umowna() -> None:
    """Warning w ścieżce bez XSD również musi widzieć walutę umowną."""
    from ksef_client.documents.fa3.xml import _warn_unsupported_currencies

    with pytest.warns(UserWarning, match="CNH"):
        _warn_unsupported_currencies("<Faktura><WalutaUmowna>CNH</WalutaUmowna></Faktura>")


def test_malformed_xml_does_not_crash_preflight() -> None:
    """Nieparsowalny dokument ma trafić do walidacji XSD, a nie wywalić preflight."""
    with pytest.raises(FA3XmlValidationError):
        validate_fa3_xml_xsd("<KodWaluty>CNH")


# --- P1b: walidator nie może być łagodniejszy niż serializacja ---


@pytest.mark.parametrize("currency", [" eur ", "eur ", " EUR", "\tEUR"])
def test_currency_with_whitespace_is_rejected(currency: str) -> None:
    """Spacje nie są obcinane przy serializacji, więc XML byłby niepoprawny.

    Wcześniej walidator robił `strip()`, uznawał taką wartość za poprawną, a XSD
    odrzucał dokument - walidator dawał fałszywe poczucie poprawności.
    """
    with pytest.raises(Fa3CurrencyMismatchError, match="format"):
        validate_fa3_currency(currency)


@pytest.mark.parametrize("currency", ["eur", "pln", "usd"])
def test_lowercase_currency_is_accepted_because_serialization_upcases(currency: str) -> None:
    """Serializacja robi `upper()`, więc małe litery są bezpieczne i nie mogą być błędem."""
    validate_fa3_currency(currency)


def test_is_fa3_currency_supported_rejects_none() -> None:
    """`None` nie jest walutą - brak wartości nie może udawać wspieranej waluty."""
    assert is_fa3_currency_supported(None) is False


def test_is_fa3_currency_supported_accepts_enum_and_str() -> None:
    assert is_fa3_currency_supported(CurrencyCode.PLN) is True
    assert is_fa3_currency_supported("PLN") is True
    assert is_fa3_currency_supported("CNH") is False


def test_currency_type_missing_from_schema_is_a_hard_error() -> None:
    """Brak typu `TKodWaluty` w schemacie to błąd pakietu, nie dane użytkownika."""
    from ksef_client.documents.fa3 import currency as currency_module

    broken = "<xsd:schema><xsd:simpleType name='InnyTyp'/></xsd:schema>"

    class _FakePath:
        def read_text(self, encoding: str = "utf-8") -> str:
            return broken

    class _FakeFiles:
        def __truediv__(self, other: str) -> _FakePath:
            return _FakePath()

    currency_module.fa3_xsd_currency_codes.cache_clear()
    try:
        with (
            patch.object(currency_module.resources, "files", return_value=_FakeFiles()),
            pytest.raises(RuntimeError, match="TKodWaluty"),
        ):
            currency_module.fa3_xsd_currency_codes()
    finally:
        currency_module.fa3_xsd_currency_codes.cache_clear()


def test_validator_accepts_exactly_what_xsd_accepts() -> None:
    """Walidator i schemat muszą zgadzać się co do każdej wartości granicznej."""
    accepted_by_xsd: list[str] = []
    for currency in ["PLN", "eur", " eur ", "CNH", " XYZ"]:
        try:
            build = _invoice_xml(currency, xsd_validate=True)
        except FA3XmlValidationError:
            xsd_ok = False
        else:
            xsd_ok = b"KodWaluty" in build

        try:
            validate_fa3_currency(currency)
            validator_ok = True
        except Fa3CurrencyMismatchError:
            validator_ok = False

        if xsd_ok:
            accepted_by_xsd.append(currency)
        # Walidator nie może przepuścić niczego, co XSD odrzuca...
        assert not (validator_ok and not xsd_ok), f"{currency!r} przeszło walidator, ale nie XSD"

    assert "PLN" in accepted_by_xsd
    assert " eur " not in accepted_by_xsd


# --- P2 (wariant B): ostrzeżenie w domyślnej ścieżce ---


def test_default_path_warns_about_currency_rejected_by_ksef() -> None:
    with pytest.warns(UserWarning, match="CNH"):
        _invoice_xml("CNH", xsd_validate=False)


def test_default_path_is_silent_for_supported_currency() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _invoice_xml("PLN", xsd_validate=False)


def test_xsd_validation_raises_instead_of_warning() -> None:
    with pytest.raises(FA3XmlValidationError):
        _invoice_xml("CNH", xsd_validate=True)


def test_warning_is_not_emitted_when_xsd_validation_succeeds() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _invoice_xml("EUR", xsd_validate=True)


def test_warning_points_at_the_caller() -> None:
    """`stacklevel` musi wskazywać wywołanie użytkownika, nie wewnętrzny shim SDK.

    Przy zbyt niskim `stacklevel` ostrzeżenie było przypisywane do
    `models.FA3Draft.to_xml`, więc użytkownik nie wiedział, gdzie je naprawić.
    """
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _invoice_xml("CNH", xsd_validate=False)

    assert caught, "oczekiwano ostrzeżenia o walucie"
    assert caught[0].filename == __file__, (
        f"ostrzeżenie przypisane do {caught[0].filename}, a nie do miejsca wywołania"
    )


# --- P1a: walidacja XSD nie może wymagać dostępu do sieci ---


def test_xsd_validation_is_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """`schemaLocation` wskazuje URL do crd.gov.pl, ale resolver mapuje lokalne kopie.

    Gdyby resolver przestał działać, walidacja zaczęłaby pobierać schematy z sieci
    (albo wisieć) - ten test to wykryje.
    """

    def _blocked(*args: object, **kwargs: object) -> None:
        raise AssertionError("Walidacja XSD probowala uzyc sieci")

    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)

    xml = _invoice_xml("PLN", xsd_validate=True)
    assert b"KodWaluty" in xml


def test_currency_preflight_preserves_whitespace_from_xml() -> None:
    """Preflight nie może naprawiać wartości, którą XSD faktycznie odrzuci."""
    from ksef_client.documents.fa3.xml import _warn_unsupported_currencies

    with pytest.warns(UserWarning, match="nieprawidłowy format"):
        _warn_unsupported_currencies(
            "<Faktura><KodWaluty> PLN </KodWaluty></Faktura>"
        )
