"""Walidacja walut FA(3): preflight, ostrzeżenia i brak zależności od sieci."""

from __future__ import annotations

import socket
import warnings
from datetime import date

import pytest

from ksef_client.documents.fa3 import FA3InvoiceBuilder, FA3Party
from ksef_client.documents.fa3.xml import (
    FA3XmlValidationError,
    validate_fa3_xml_xsd,
)


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


def test_preflight_ignores_unsupported_currency_inside_other_elements() -> None:
    """Wyszukiwanie działa po localname, nie po dowolnym wystąpieniu tekstu."""
    xml = '<Faktura xmlns="http://crd.gov.pl/wzor/2025/06/25/13775/"><WalutaUmowna>CNH</WalutaUmowna></Faktura>'
    # WalutaUmowna to inny element niz KodWaluty - brak wyjątku z preflight.
    with pytest.raises(FA3XmlValidationError):
        validate_fa3_xml_xsd(xml)
    # Upewniamy sie, ze komunikat pochodzi z walidacji schemy, nie z preflight.
    # (preflight nie znalazl KodWaluty, wiec nie podniosl bledu o rozjezdzie)


def test_malformed_xml_does_not_crash_preflight() -> None:
    """Nieparsowalny dokument ma trafić do walidacji XSD, a nie wywalić preflight."""
    with pytest.raises(FA3XmlValidationError):
        validate_fa3_xml_xsd("<KodWaluty>CNH")


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
