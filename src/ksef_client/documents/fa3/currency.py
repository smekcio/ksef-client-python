"""Spójność słowników walut: OpenAPI KSeF ↔ schemat XSD FA(3).

KSeF publikuje **dwie niezależne listy kodów walut**:

- ``CurrencyCode`` w OpenAPI — używany m.in. w identyfikatorach zbiorczych
  i filtrach wyszukiwania faktur,
- ``TKodWaluty`` w schemacie ``schemat_FA(3)_v1-0E.xsd`` — używany przy
  walidacji treści faktury.

Listy te nie są tożsame i rozjeżdżają się między wydaniami API. W szczególności
API 2.8.0 rozszerzyło ``CurrencyCode`` o kody ``CNH``, ``VED``, ``XTS``, ``ZWG``
i ``SLE``, których **nie ma** w schemacie FA(3). Próba wystawienia faktury w takiej
walucie kończy się błędem walidacji XSD po stronie klienta — a po pominięciu
walidacji lokalnej — odrzuceniem dokumentu przez KSeF.

Ten moduł wykrywa taki rozjazd **przed** wysłaniem dokumentu i zwraca komunikat
wyjaśniający przyczynę, zamiast surowego błędu ``SCHEMAV_CVC_ENUMERATION_VALID``.
"""

from __future__ import annotations

import re
from functools import lru_cache
from importlib import resources

from ...models import CurrencyCode

FA3_SCHEMA_FILE = "schemat_FA(3)_v1-0E.xsd"
_CURRENCY_TYPE_NAME = "TKodWaluty"

# Kody obecne w OpenAPI ``CurrencyCode``, ale nieobecne w schemacie FA(3).
# Odzwierciedla stan KSeF API 2.8.1; pilnowane testem regresyjnym.
_KNOWN_OPENAPI_ONLY_CURRENCIES: frozenset[str] = frozenset(
    {"CNH", "VED", "XTS", "ZWG", "SLE"}
)


class Fa3CurrencyMismatchError(ValueError):
    """Waluta jest znana OpenAPI, ale nie występuje w schemacie FA(3)."""


@lru_cache(maxsize=1)
def fa3_xsd_currency_codes() -> frozenset[str]:
    """Zwraca kody walut dozwolone przez schemat XSD FA(3) (``TKodWaluty``)."""
    schema_path = resources.files("ksef_client.documents.fa3.schemas") / FA3_SCHEMA_FILE
    text = schema_path.read_text(encoding="utf-8")
    match = re.search(
        rf'<xsd:simpleType[^>]*name="{_CURRENCY_TYPE_NAME}".*?</xsd:simpleType>',
        text,
        re.DOTALL,
    )
    if match is None:
        raise RuntimeError(
            f"Nie znaleziono typu {_CURRENCY_TYPE_NAME} w schemacie {FA3_SCHEMA_FILE}."
        )
    return frozenset(re.findall(r'<xsd:enumeration value="([A-Z]{3})"', match.group(0)))


@lru_cache(maxsize=1)
def openapi_currency_codes() -> frozenset[str]:
    """Zwraca kody walut z OpenAPI ``CurrencyCode``."""
    return frozenset(member.value for member in CurrencyCode)


def openapi_only_currency_codes() -> frozenset[str]:
    """Kody akceptowane przez OpenAPI, ale odrzucane przez schemat FA(3)."""
    return openapi_currency_codes() - fa3_xsd_currency_codes()


def known_openapi_only_currency_codes() -> frozenset[str]:
    """Udokumentowane wyjątki rozjazdu — te, które znamy i obsługujemy świadomie."""
    return _KNOWN_OPENAPI_ONLY_CURRENCIES


def is_fa3_currency_supported(currency: str | CurrencyCode | None) -> bool:
    """Czy waluta przejdzie walidację schematu FA(3)."""
    if currency is None:
        return False
    value = currency.value if isinstance(currency, CurrencyCode) else str(currency)
    return value.strip().upper() in fa3_xsd_currency_codes()


def validate_fa3_currency(currency: str | CurrencyCode | None) -> None:
    """Sprawdza walutę pod kątem schematu FA(3) i podnosi czytelny błąd.

    Różnicuje dwa przypadki: walutę nieznaną OpenAPI oraz walutę znaną OpenAPI,
    ale nieobsługiwaną przez schemat faktury — bo w drugim przypadku użytkownik
    nie ma błędu w kodzie, tylko trafił na rozjazd kontraktów MF.
    """
    value = currency.value if isinstance(currency, CurrencyCode) else str(currency or "")
    normalized = value.strip().upper()
    if not normalized:
        raise Fa3CurrencyMismatchError("Waluta jest wymagana.")
    if normalized in fa3_xsd_currency_codes():
        return
    if normalized in openapi_currency_codes():
        raise Fa3CurrencyMismatchError(
            f"Waluta {normalized} jest akceptowana przez OpenAPI KSeF, ale nie występuje "
            f"w schemacie FA(3) ({FA3_SCHEMA_FILE}, typ {_CURRENCY_TYPE_NAME}). "
            f"Faktura w tej walucie zostanie odrzucona przez KSeF."
        )
    raise Fa3CurrencyMismatchError(
        f"Waluta {normalized} nie występuje w schemacie FA(3) ({FA3_SCHEMA_FILE})."
    )
