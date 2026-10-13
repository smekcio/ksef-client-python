"""Typy i ograniczenia pól FA(3) wyprowadzone ze schematu XSD.

Ten moduł jest **jednym źródłem prawdy** o tym, jakie wartości wolno wpisać do
poszczególnych elementów XML FA(3). Ograniczenia nie są przepisane „z głowy" —
każdy wpis odpowiada konkretnemu `xsd:simpleType` w schemacie
`schemat_FA(3)_v1-0E.xsd` (oraz importowanych `StrukturyDanych_v10-0E.xsd`
i `ElementarneTypyDanych_v10-0E.xsd`).

Spójność tabeli ze schematem pilnuje `tests/test_fa3_validation_facets.py`:
parsuje XSD i porównuje — dla każdego elementu — zadeklarowany typ, długości,
minLength, precyzję, zakresy liczbowe i daty, słowniki, wzorce oraz liczności
i elementy wymagane. Każdy z tych testów był weryfikowany mutacyjnie (19/19
celowych rozjazdów daje czerwony test).

Dlaczego własna tabela, a nie parsowanie XSD w runtime: walidacja biznesowa musi
działać także wtedy, gdy `lxml` nie jest zainstalowany (walidacja XSD jest
opcjonalnym extra `fa3`). Tabela jest mała, czytelna i weryfikowalna, a schemat
pozostaje ostatecznym arbitrem przez `to_xml(xsd_validate=True)`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum

# ---------------------------------------------------------------------------
# Rodzaje ograniczeń
# ---------------------------------------------------------------------------


class FacetKind(str, Enum):
    """Rodzaj wartości, jaki wolno wpisać w element."""

    STRING = "string"
    """Tekst — ogranicza go długość (``max_length``)."""

    INTEGER = "integer"
    """Liczba całkowita — opcjonalnie z zakresem i listą dozwolonych wartości."""

    DECIMAL = "decimal"
    """Liczba dziesiętna — ogranicza ją liczba miejsc po przecinku."""


#: Wzorzec liczby dziesiętnej zgodny ze schematem FA(3):
#: ``-?([1-9]\d{0,N}|0)(\.\d{1,M})?`` — bez separatorów tysięcy i bez wykładnika.
_DECIMAL_TEXT = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?")

#: Wzorzec liczby całkowitej (schemat używa ``xsd:integer``/``xsd:byte``).
_INTEGER_TEXT = re.compile(r"-?\d+")

#: Od ilu wartości słownik przestajemy wypisywać w komunikacie walidacji.
_MAX_LISTED_ALLOWED = 32


@dataclass(frozen=True)
class Facet:
    """Ograniczenia jednego elementu XML.

    Atrybuty odpowiadają ściśle konstrukcjom schematu:

    * ``max_length`` — ``xsd:maxLength``,
    * ``decimals`` — ``xsd:fractionDigits``,
    * ``allowed`` — ``xsd:enumeration`` (dla typów wyliczeniowych),
    * ``minimum``/``maximum`` — ``xsd:minInclusive``/``xsd:maxInclusive``,
    * ``minimum_length`` — ``xsd:minLength`` (np. ``NrRB`` ma 10),
    * ``whitespace`` — ``xsd:whiteSpace`` typu bazowego: ``preserve`` (``xsd:string``),
      ``replace`` (``xsd:normalizedString``) albo ``collapse`` (``xsd:token``,
      typy liczbowe i daty).

    ``whitespace`` jest istotne, bo schemat liczy długość i dopasowuje wzorce do
    wartości PO zastosowaniu tego trybu. Mierzenie surowej wartości odrzucało
    dokument zgodny ze schematem (``P_2`` z wcięciem), a mierzenie zawsze
    obciętej przepuszczało dokument niezgodny (``<NIP> 1111111111</NIP>`` —
    ``TNrNIP`` bazuje na ``xsd:string``, czyli ``preserve``).
    """

    kind: FacetKind
    xsd_type: str | None
    max_length: int | None = None
    minimum_length: int | None = None
    decimals: int | None = None
    allowed: frozenset[str] | None = None
    total_digits: int | None = None
    integer_digits: int | None = None
    minimum: Decimal | None = None
    maximum: Decimal | None = None
    minimum_date: str | None = None
    maximum_date: str | None = None
    lengths: frozenset[int] | None = None
    date_format: str | None = None
    whitespace: str = "preserve"

    def describe(self) -> str:
        """Krótki, czytelny opis ograniczenia do komunikatów walidacji."""
        parts: list[str] = []
        if self.allowed is not None:
            # Duże słowniki (np. 254 kody krajów) wypisane w całości czyniłyby
            # komunikat nieczytelnym — samą nazwę typu wystarczy podać.
            if len(self.allowed) > _MAX_LISTED_ALLOWED:
                parts.append(
                    f"wartość musi należeć do słownika {self.xsd_type} "
                    f"({len(self.allowed)} wartości)"
                )
            else:
                parts.append("dozwolone wartości: " + ", ".join(sorted(self.allowed)))
        if self.lengths is not None:
            allowed_lengths = ", ".join(str(value) for value in sorted(self.lengths))
            parts.append(f"długość {allowed_lengths} znaków")
        elif self.max_length is not None and self.minimum_length is not None:
            parts.append(f"długość {self.minimum_length}-{self.max_length} znaków")
        elif self.max_length is not None:
            parts.append(f"maksymalnie {self.max_length} znaków")
        elif self.minimum_length is not None:
            parts.append(f"co najmniej {self.minimum_length} znaków")
        if self.decimals is not None:
            parts.append(f"maksymalnie {self.decimals} miejsc po przecinku")
        if self.integer_digits is not None:
            parts.append(f"maksymalnie {self.integer_digits} cyfr części całkowitej")
        if self.minimum is not None and self.maximum is not None:
            parts.append(f"zakres {self.minimum}-{self.maximum}")
        elif self.minimum is not None:
            parts.append(f"minimum {self.minimum}")
        elif self.maximum is not None:
            parts.append(f"maksimum {self.maximum}")
        if self.minimum_date is not None and self.maximum_date is not None:
            parts.append(f"zakres dat {self.minimum_date} - {self.maximum_date}")
        if not parts and self.xsd_type is not None:
            parts.append(f"typ {self.xsd_type}")
        return ", ".join(parts)


# ---------------------------------------------------------------------------
# Typy schematu FA(3)
# ---------------------------------------------------------------------------

# Tryby `ws-collapse` (``xsd:token``, typy liczbowe, daty) i `ws-replace`
# (``xsd:normalizedString``) wynikają wprost z ``xsd:whiteSpace`` typu bazowego
# w schemacie; pilnuje tego ``tests/test_fa3_validation_facets.py``.
_WS_COLLAPSE = "collapse"
_WS_REPLACE = "replace"
_WS_PRESERVE = "preserve"

#: `tns:TZnakowy` — tekst do 256 znaków (schemat: maxLength=256, minLength=1).
TZN = Facet(
    FacetKind.STRING, "TZnakowy", max_length=256, minimum_length=1, whitespace=_WS_COLLAPSE
)
#: `tns:TZnakowy2` — jak wyżej, ale schemat dopuszcza tu wartość pustą (`minLength=0`).
TZN2 = Facet(
    FacetKind.STRING, "TZnakowy2", max_length=256, minimum_length=0, whitespace=_WS_COLLAPSE
)
#: `tns:TZnakowy512` — tekst do 512 znaków.
TZN512 = Facet(
    FacetKind.STRING, "TZnakowy512", max_length=512, minimum_length=1, whitespace=_WS_COLLAPSE
)
#: `tns:TZnakowy50` — tekst do 50 znaków.
TZN50 = Facet(
    FacetKind.STRING, "TZnakowy50", max_length=50, minimum_length=1, whitespace=_WS_COLLAPSE
)
#: `tns:TZnakowy20` — tekst do 20 znaków.
TZN20 = Facet(
    FacetKind.STRING, "TZnakowy20", max_length=20, minimum_length=1, whitespace=_WS_COLLAPSE
)
#: `etd:TAdresEmail` — 3-255 znaków z co najmniej jednym `@`.
EMAIL = Facet(
    FacetKind.STRING, "TAdresEmail", max_length=255, minimum_length=3, whitespace=_WS_COLLAPSE
)
#: `tns:TNumerTelefonu` — tekst do 16 znaków.
TELEFON = Facet(
    FacetKind.STRING, "TNumerTelefonu", max_length=16, minimum_length=1, whitespace=_WS_COLLAPSE
)
#: `tns:TGLN` — do 13 znaków.
GLN = Facet(FacetKind.STRING, "TGLN", max_length=13, minimum_length=1, whitespace=_WS_COLLAPSE)
#: `tns:TNrRB` — numer rachunku 10-34 znaków. Baza `xsd:string` → `preserve`,
#: więc spacje w numerze rachunku NIE są obcinane i muszą zostać zgłoszone.
NRRB = Facet(FacetKind.STRING, "TNrRB", max_length=34, minimum_length=10)
#: `tns:TKodWaluty` — trzyliterowy kod waluty. Schemat ma 182 wartości, ale
#: słownik OpenAPI KSeF bywa od niego nowszy (API 2.8.1 dodaje CNH/VED/XTS/ZWG/SLE),
#: więc rozjazd wykrywa osobny moduł :mod:`ksef_client.documents.fa3.currency`:
#: domyślna ścieżka ostrzega, a `xsd_validate=True` odrzuca dokument. Twardy
#: słownik w tej tabeli odebrałby wołającemu możliwość świadomej decyzji.
KOD_WALUTY = Facet(FacetKind.STRING, "TKodWaluty", max_length=3, whitespace=_WS_REPLACE)
#: `tns:TIlosci` — liczba dziesiętna: 6 miejsc, do 16 cyfr całkowitych.
#: Schemat: `pattern="-?([1-9]\d{0,15}|0)(\.\d{1,6})?"`, `totalDigits=22`.
ILOSCI = Facet(
    FacetKind.DECIMAL,
    "TIlosci",
    decimals=6,
    total_digits=22,
    integer_digits=16,
    whitespace=_WS_COLLAPSE,
)
#: `tns:TProcentowy` — procent: 0-100, do 6 miejsc po przecinku.
PROCENT = Facet(
    FacetKind.DECIMAL,
    "TProcentowy",
    decimals=6,
    total_digits=9,
    minimum=Decimal("0"),
    maximum=Decimal("100"),
    whitespace=_WS_COLLAPSE,
)
#: `tns:TKwotowy` — kwota: 2 miejsca, do 16 cyfr całkowitych.
#: Schemat: `pattern="-?([1-9]\d{0,15}|0)(\.\d{1,2})?"`, `totalDigits=18`.
KWOTOWY = Facet(
    FacetKind.DECIMAL,
    "TKwotowy",
    decimals=2,
    total_digits=18,
    integer_digits=16,
    whitespace=_WS_COLLAPSE,
)
#: `tns:TKwotowy2` — cena jednostkowa/rabat: 8 miejsc, do 14 cyfr całkowitych.
#: Schemat: `pattern="-?([1-9]\d{0,13}|0)(\.\d{1,8})?"`, `totalDigits=22`.
KWOTOWY2 = Facet(
    FacetKind.DECIMAL,
    "TKwotowy2",
    decimals=8,
    total_digits=22,
    integer_digits=14,
    whitespace=_WS_COLLAPSE,
)
#: `tns:TNaturalny` — liczba całkowita większa od zera.
NATURALNY = Facet(
    FacetKind.INTEGER, "TNaturalny", minimum=Decimal("1"), whitespace=_WS_COLLAPSE
)

#: `tns:TData` — data ``YYYY-MM-DD`` z zakresem 2016-07-01..2050-01-01.
DATA = Facet(
    FacetKind.STRING,
    "TData",
    minimum_date="2016-07-01",
    maximum_date="2050-01-01",
    date_format="%Y-%m-%d",
    whitespace=_WS_COLLAPSE,
)
#: `tns:TDataU` — data umowy/zamówienia: 1990-01-01..2050-01-01.
DATA_UMOWY = Facet(
    FacetKind.STRING,
    "TDataU",
    minimum_date="1990-01-01",
    maximum_date="2050-01-01",
    date_format="%Y-%m-%d",
    whitespace=_WS_COLLAPSE,
)
#: `tns:TDataT` — data dopuszczenia środka transportu: 2006-01-01..2050-01-01.
DATA_TRANSPORTU = Facet(
    FacetKind.STRING,
    "TDataT",
    minimum_date="2006-01-01",
    maximum_date="2050-01-01",
    date_format="%Y-%m-%d",
    whitespace=_WS_COLLAPSE,
)
#: `tns:TDataCzas` — znacznik czasu UTC: 2021-10-01T00:00:00Z..2050-01-01T23:59:59Z.
DATA_CZAS = Facet(
    FacetKind.STRING,
    "TDataCzas",
    minimum_date="2021-10-01T00:00:00Z",
    maximum_date="2050-01-01T23:59:59Z",
    date_format="%Y-%m-%dT%H:%M:%S%z",
    whitespace=_WS_COLLAPSE,
)
#: `Naglowek/DataWytworzeniaFa` — element ma WŁASNE, węższe ograniczenie inline
#: (`xsd:restriction base="etd:TDataCzas"` z `minInclusive="2025-09-01T00:00:00Z"`),
#: a nie dolne ograniczenie `TDataCzas` (2021-10-01). Użycie samego `DATA_CZAS`
#: przepuszczało ok. 4 lata znaczników, które schemat odrzuca.
DATA_WYTWORZENIA_FA = Facet(
    FacetKind.STRING,
    "TDataCzas",
    minimum_date="2025-09-01T00:00:00Z",
    maximum_date="2050-01-01T23:59:59Z",
    date_format="%Y-%m-%dT%H:%M:%S%z",
    whitespace=_WS_COLLAPSE,
)


def _enum(
    name: str,
    values: frozenset[str],
    *,
    kind: FacetKind = FacetKind.INTEGER,
    whitespace: str = _WS_COLLAPSE,
) -> Facet:
    """Słownik wartości. Domyślnie ``collapse`` — schemat opiera je na ``xsd:token``
    albo typie liczbowym; wyjątki (``TKodyKrajowUE``, ``TKodKraju``, ``TKodWaluty``,
    ``TKodFormularza``) mają bazę ``normalizedString``/``string`` i podają tryb jawnie."""
    return Facet(kind, name, allowed=values, whitespace=whitespace)


#: `tns:TNumerKSeF` — numer KSeF: NIP/M-dowolny/kod-data-6hex-6hex-2hex.
#: Schemat dopuszcza dwie długości: 35 znaków (grupy hex zlepione) albo 36
#: (z opcjonalnym myślnikiem między nimi) — stąd ``lengths``, a nie ``max_length``.
NUMER_KSEF = Facet(
    FacetKind.STRING,
    "TNumerKSeF",
    lengths=frozenset({35, 36}),
    whitespace=_WS_COLLAPSE,
)

#: `tns:TWybor1` — znacznik „tak" (schemat: enumeration {1}).
WYBOR1 = _enum("TWybor1", frozenset({"1"}))
#: `tns:TWybor1_2` — znacznik tak/nie (schemat: enumeration {1,2}).
WYBOR1_2 = _enum("TWybor1_2", frozenset({"1", "2"}))
#: `tns:TStawkaPodatku` — 14 kodów stawek (ze spacjami, np. ``0 KR``).
STAWKA_PODATKU = _enum(
    "TStawkaPodatku",
    frozenset(
        {
            "23",
            "22",
            "8",
            "7",
            "5",
            "4",
            "3",
            "0 KR",
            "0 WDT",
            "0 EX",
            "zw",
            "oo",
            "np I",
            "np II",
        }
    ),
    kind=FacetKind.STRING,
)
#: `tns:TRodzajFaktury` — rodzaj faktury.
RODZAJ_FAKTURY = _enum(
    "TRodzajFaktury",
    frozenset({"VAT", "KOR", "ZAL", "ROZ", "UPR", "KOR_ZAL", "KOR_ROZ"}),
    kind=FacetKind.STRING,
)
#: `tns:TTypKorekty` — typ skutku korekty.
TYP_KOREKTY = _enum("TTypKorekty", frozenset({"1", "2", "3"}))
#: `tns:TRolaPodmiotu3` — rola podmiotu trzeciego (1-11).
ROLA_PODMIOTU3 = _enum("TRolaPodmiotu3", frozenset(str(i) for i in range(1, 12)))
#: `tns:TRolaPodmiotuUpowaznionego` — rola podmiotu upoważnionego (1-3).
ROLA_PODMIOTU_UPOWAZNIONEGO = _enum("TRolaPodmiotuUpowaznionego", frozenset({"1", "2", "3"}))
#: `tns:TStatusInfoPodatnika` — status podatnika (1-4).
STATUS_PODATNIKA = _enum("TStatusInfoPodatnika", frozenset(str(i) for i in range(1, 5)))
#: `tns:TFormaPlatnosci` — forma płatności (1-7).
FORMA_PLATNOSCI = _enum("TFormaPlatnosci", frozenset(str(i) for i in range(1, 8)))
#: `tns:TRachunekWlasnyBanku` — rodzaj rachunku własnego banku (1-3).
RACHUNEK_WLASNY_BANKU = _enum("TRachunekWlasnyBanku", frozenset({"1", "2", "3"}))
#: `tns:TRodzajTransportu` — rodzaj transportu (bez kodu 6, celowo pominiętego).
RODZAJ_TRANSPORTU = _enum("TRodzajTransportu", frozenset({"1", "2", "3", "4", "5", "7", "8"}))
#: `tns:TLadunek` — opis ładunku (1-20).
LADUNEK = _enum("TLadunek", frozenset(str(i) for i in range(1, 21)))
#: `tns:TGTU` — oznaczenia GTU_01..GTU_13.
GTU = _enum("TGTU", frozenset(f"GTU_{i:02d}" for i in range(1, 14)), kind=FacetKind.STRING)
#: `tns:TOznaczenieProcedury` — oznaczenia procedur dla faktur.
PROCEDURA = _enum(
    "TOznaczenieProcedury",
    frozenset(
        {
            "WSTO_EE",
            "IED",
            "TT_D",
            "I_42",
            "I_63",
            "B_SPV",
            "B_SPV_DOSTAWA",
            "B_MPV_PROWIZJA",
        }
    ),
    kind=FacetKind.STRING,
)
#: `tns:TOznaczenieProceduryZ` — oznaczenia procedur dla zamówień (węższy słownik).
PROCEDURA_Z = _enum(
    "TOznaczenieProceduryZ",
    frozenset({"WSTO_EE", "IED", "TT_D", "B_SPV", "B_SPV_DOSTAWA", "B_MPV_PROWIZJA"}),
    kind=FacetKind.STRING,
)
#: `tns:TKodyKrajowUE` — kody krajów UE (28 wartości, w tym XI dla Irlandii Płn.).
KODY_KRAJOW_UE = _enum(
    "TKodyKrajowUE",
    frozenset(
        {
            "AT",
            "BE",
            "BG",
            "CY",
            "CZ",
            "DK",
            "EE",
            "FI",
            "FR",
            "DE",
            "EL",
            "HR",
            "HU",
            "IE",
            "IT",
            "LV",
            "LT",
            "LU",
            "MT",
            "NL",
            "PL",
            "PT",
            "RO",
            "SK",
            "SI",
            "ES",
            "SE",
            "XI",
        }
    ),
    kind=FacetKind.STRING,
    whitespace=_WS_REPLACE,
)
#: `etd:TKodKraju` — pełny słownik 254 kodów krajów z `KodyKrajow_v10-0E.xsd`.
#:
#: Bez niego literówka (`XX`, `UK` zamiast `GB`) przechodziła walidację SDK,
#: a całą fakturę odrzucał dopiero KSeF surowym `SCHEMAV_CVC_ENUMERATION_VALID`.
KODY_KRAJOW = _enum(
    "TKodKraju",
    frozenset(
        (
            "AF", "AX", "AL", "DZ", "AD", "AO", "AI", "AQ", "AG", "AN", "SA", "AR",
            "AM", "AW", "AU", "AT", "AZ", "BS", "BH", "BD", "BB", "BE", "BZ", "BJ",
            "BM", "BT", "BY", "BO", "BQ", "BA", "BW", "BR", "BN", "IO", "BG", "BF",
            "BI", "XC", "CL", "CN", "HR", "CW", "CY", "TD", "ME", "DK", "DM", "DO",
            "DJ", "EG", "EC", "ER", "EE", "ET", "FK", "FJ", "PH", "FI", "FR", "TF",
            "GA", "GM", "GH", "GI", "GR", "GD", "GL", "GE", "GU", "GG", "GY", "GF",
            "GP", "GT", "GN", "GQ", "GW", "HT", "ES", "HN", "HK", "IN", "ID", "IQ",
            "IR", "IE", "IS", "IL", "JM", "JP", "YE", "JE", "JO", "KY", "KH", "CM",
            "CA", "QA", "KZ", "KE", "KG", "KI", "CO", "KM", "CG", "CD", "KP", "XK",
            "CR", "CU", "KW", "LA", "LS", "LB", "LR", "LY", "LI", "LT", "LV", "LU",
            "MK", "MG", "YT", "MO", "MW", "MV", "MY", "ML", "MT", "MP", "MA", "MQ",
            "MR", "MU", "MX", "XL", "FM", "UM", "MD", "MC", "MN", "MS", "MZ", "MM",
            "NA", "NR", "NP", "NL", "DE", "NE", "NG", "NI", "NU", "NF", "NO", "NC",
            "NZ", "PS", "OM", "PK", "PW", "PA", "PG", "PY", "PE", "PN", "PF", "PL",
            "GS", "PT", "PR", "CF", "CZ", "KR", "ZA", "RE", "RU", "RO", "RW", "EH",
            "BL", "KN", "LC", "MF", "VC", "SV", "WS", "AS", "SM", "SN", "RS", "SC",
            "SL", "SG", "SK", "SI", "SO", "LK", "PM", "US", "SZ", "SD", "SS", "SR",
            "SJ", "SH", "SY", "CH", "SE", "TJ", "TH", "TW", "TZ", "TG", "TK", "TO",
            "TT", "TN", "TR", "TM", "TV", "UG", "UA", "UY", "UZ", "VU", "WF", "VA",
            "HU", "VE", "GB", "VN", "IT", "TL", "CI", "BV", "CX", "IM", "SX", "CK",
            "VI", "VG", "HM", "CC", "MH", "FO", "SB", "ST", "TC", "ZM", "CV", "ZW",
            "AE", "XI",
        )
    ),
    kind=FacetKind.STRING,
    whitespace=_WS_REPLACE,
)
#: `tns:TKodFormularza` — schemat dopuszcza wyłącznie wartość ``FA``.
KOD_FORMULARZA = _enum(
    "TKodFormularza", frozenset({"FA"}), kind=FacetKind.STRING, whitespace=_WS_PRESERVE
)


@dataclass(frozen=True)
class ElementFacet:
    """Ograniczenie elementu: typ + opcjonalne reguły ponadtypowe.

    ``max_occurrences`` pochodzi z ``xsd:maxOccurs`` rodzica, dlatego jest
    przechowywane razem z elementem, a nie w typie.
    """

    facet: Facet
    max_occurrences: int | None = None
    pattern: re.Pattern[str] | None = None
    pattern_hint: str = ""
    extra: tuple[str, ...] = field(default=())


#: Element o typie ``tns:TNumerKSeF`` (``NrKSeFFaKorygowanej``,
#: ``NrKSeFFaZaliczkowej``): 35 albo 36 znaków i wzorzec
#: ``NIP|M-dowolny|kod-dowolny`` + data + 6hex + 6hex + 2hex.
#:
#: Jedna definicja dla obu elementów — wcześniej ``NrKSeFFaZaliczkowej``
#: deklarował wyłącznie długości, więc dowolny 35-znakowy napis (``"X" * 35``)
#: przechodził walidację, a dokument odrzucał dopiero KSeF.
NUMER_KSEF_ELEMENT = ElementFacet(
    NUMER_KSEF,
    pattern=re.compile(
        r"([1-9]((\d[1-9])|([1-9]\d))\d{7}|M\d{9}|[A-Z]{3}\d{7})-"
        r"(20[2-9][0-9]|2[1-9][0-9]{2}|[3-9][0-9]{3})"
        r"(0[1-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1])-"
        r"([0-9A-F]{6})-?([0-9A-F]{6})-([0-9A-F]{2})"
    ),
    pattern_hint=(
        "numer KSeF: NIP-data-6hex-6hex-2hex, np. 1111111111-20260714-D5FB0C-9ED490-9A"
    ),
)

# ---------------------------------------------------------------------------
# Mapa element -> ograniczenie
# ---------------------------------------------------------------------------

#: Elementy XML FA(3) i ich ograniczenia. Klucz to nazwa lokalna elementu.
#:
#: Wpisy bez ``max_occurrences`` nie mają limitu liczby wystąpień w schemacie
#: (albo są unikalne z natury, np. ``Naglowek``).
ELEMENT_FACETS: dict[str, ElementFacet] = {
    # --- Naglowek ---------------------------------------------------------
    "KodFormularza": ElementFacet(Facet(FacetKind.STRING, None, allowed=frozenset({"FA"}))),
    "WariantFormularza": ElementFacet(
        Facet(FacetKind.INTEGER, None, allowed=frozenset({"3"}), whitespace=_WS_COLLAPSE)
    ),
    "SystemInfo": ElementFacet(TZN),
    # --- Podmioty: identyfikacja i dane opisowe ---------------------------
    "NIP": ElementFacet(
        Facet(FacetKind.STRING, "TNrNIP", max_length=10, minimum_length=10),
        pattern=re.compile(r"[1-9]((\d[1-9])|([1-9]\d))\d{7}"),
        pattern_hint="10 cyfr, bez zer wiodących na dwóch pierwszych pozycjach",
    ),
    "IDWew": ElementFacet(
        Facet(
            FacetKind.STRING,
            "TNIPIdWew",
            max_length=16,
            minimum_length=16,
            whitespace=_WS_COLLAPSE,
        ),
        pattern=re.compile(r"[1-9]((\d[1-9])|([1-9]\d))\d{7}-\d{5}"),
        pattern_hint="NIP i 5 cyfr, np. 1111111111-00001",
    ),
    "Nazwa": ElementFacet(TZN512),
    "NrVatUE": ElementFacet(
        Facet(FacetKind.STRING, "TNrVatUE", max_length=12, minimum_length=1),
        pattern=re.compile(r"(\d|[A-Z]|\+|\*){1,12}"),
        pattern_hint="do 12 znaków: cyfry, wielkie litery, '+' lub '*'",
    ),
    "KodUE": ElementFacet(KODY_KRAJOW_UE),
    "KodKraju": ElementFacet(KODY_KRAJOW),
    "NrID": ElementFacet(
        Facet(
            FacetKind.STRING,
            "TNrIdentyfikacjiPodatkowej",
            max_length=50,
            minimum_length=1,
            whitespace=_WS_REPLACE,
        )
    ),
    "BrakID": ElementFacet(WYBOR1),
    "PrefiksPodatnika": ElementFacet(KODY_KRAJOW_UE),
    "StatusInfoPodatnika": ElementFacet(STATUS_PODATNIKA),
    "NrKlienta": ElementFacet(TZN),
    "IDNabywcy": ElementFacet(
        Facet(
            FacetKind.STRING,
            None,
            max_length=32,
            minimum_length=1,
            whitespace=_WS_COLLAPSE,
        )
    ),
    "NrEORI": ElementFacet(TZN),
    # --- Adres ------------------------------------------------------------
    "AdresL1": ElementFacet(TZN512),
    "AdresL2": ElementFacet(TZN512),
    "GLN": ElementFacet(GLN),
    "Email": ElementFacet(
        EMAIL,
        pattern=re.compile(r"(.)+@(.)+"),
        pattern_hint="adres e-mail z co najmniej jednym '@'",
    ),
    "EmailPU": ElementFacet(
        EMAIL,
        pattern=re.compile(r"(.)+@(.)+"),
        pattern_hint="adres e-mail z co najmniej jednym '@'",
    ),
    "Telefon": ElementFacet(TELEFON),
    "TelefonPU": ElementFacet(TELEFON),
    # --- Znaczniki JST/GV -------------------------------------------------
    "DataWytworzeniaFa": ElementFacet(DATA_WYTWORZENIA_FA),
    "FP": ElementFacet(WYBOR1),
    "TP": ElementFacet(WYBOR1),
    "ZwrotAkcyzy": ElementFacet(WYBOR1),
    "PelnaNazwa": ElementFacet(TZN),
    "P_22B": ElementFacet(TZN),
    "P_22BK": ElementFacet(TZN),
    "P_22BMK": ElementFacet(TZN),
    "P_22BMD": ElementFacet(TZN),
    "P_22BNR": ElementFacet(TZN),
    "P_22BRP": ElementFacet(TZN),
    "P_22BT": ElementFacet(TZN),
    "P_22D1": ElementFacet(TZN),
    "JST": ElementFacet(
        Facet(FacetKind.INTEGER, None, allowed=frozenset({"1", "2"}), whitespace=_WS_COLLAPSE)
    ),
    "GV": ElementFacet(
        Facet(FacetKind.INTEGER, None, allowed=frozenset({"1", "2"}), whitespace=_WS_COLLAPSE)
    ),
    "Rola": ElementFacet(ROLA_PODMIOTU3),
    "RolaInna": ElementFacet(WYBOR1),
    "OpisRoli": ElementFacet(TZN),
    "Udzial": ElementFacet(PROCENT),
    "RolaPU": ElementFacet(ROLA_PODMIOTU_UPOWAZNIONEGO),
    # --- Nagłówek faktury -------------------------------------------------
    "KodWaluty": ElementFacet(KOD_WALUTY),
    "P_1": ElementFacet(DATA_TRANSPORTU),
    "P_1M": ElementFacet(TZN),
    "P_2": ElementFacet(TZN),
    "WZ": ElementFacet(TZN, max_occurrences=1000),
    "P_6": ElementFacet(DATA_TRANSPORTU),
    "P_6_Od": ElementFacet(DATA_TRANSPORTU),
    "P_6_Do": ElementFacet(DATA_TRANSPORTU),
    "RodzajFaktury": ElementFacet(RODZAJ_FAKTURY),
    # --- Podsumowanie stawek ---------------------------------------------
    "P_13_1": ElementFacet(KWOTOWY),
    "P_14_1": ElementFacet(KWOTOWY),
    "P_14_1W": ElementFacet(KWOTOWY),
    "P_13_2": ElementFacet(KWOTOWY),
    "P_14_2": ElementFacet(KWOTOWY),
    "P_14_2W": ElementFacet(KWOTOWY),
    "P_13_3": ElementFacet(KWOTOWY),
    "P_14_3": ElementFacet(KWOTOWY),
    "P_14_3W": ElementFacet(KWOTOWY),
    "P_13_4": ElementFacet(KWOTOWY),
    "P_14_4": ElementFacet(KWOTOWY),
    "P_14_4W": ElementFacet(KWOTOWY),
    "P_13_5": ElementFacet(KWOTOWY),
    "P_14_5": ElementFacet(KWOTOWY),
    "P_13_6_1": ElementFacet(KWOTOWY),
    "P_13_6_2": ElementFacet(KWOTOWY),
    "P_13_6_3": ElementFacet(KWOTOWY),
    "P_13_7": ElementFacet(KWOTOWY),
    "P_13_8": ElementFacet(KWOTOWY),
    "P_13_9": ElementFacet(KWOTOWY),
    "P_13_10": ElementFacet(KWOTOWY),
    "P_13_11": ElementFacet(KWOTOWY),
    "P_15": ElementFacet(KWOTOWY),
    # --- Adnotacje --------------------------------------------------------
    "P_16": ElementFacet(WYBOR1_2),
    "P_17": ElementFacet(WYBOR1_2),
    "P_18": ElementFacet(WYBOR1_2),
    "P_18A": ElementFacet(WYBOR1_2),
    "P_19": ElementFacet(WYBOR1),
    "P_19A": ElementFacet(TZN),
    "P_19B": ElementFacet(TZN),
    "P_19C": ElementFacet(TZN),
    "P_19N": ElementFacet(WYBOR1),
    "P_22": ElementFacet(WYBOR1),
    "P_42_5": ElementFacet(WYBOR1_2),
    "P_22N": ElementFacet(WYBOR1),
    "P_23": ElementFacet(WYBOR1_2),
    "P_PMarzy": ElementFacet(WYBOR1),
    "P_PMarzy_2": ElementFacet(WYBOR1),
    "P_PMarzy_3_1": ElementFacet(WYBOR1),
    "P_PMarzy_3_2": ElementFacet(WYBOR1),
    "P_PMarzy_3_3": ElementFacet(WYBOR1),
    "P_PMarzyN": ElementFacet(WYBOR1),
    # --- Pozycje faktury --------------------------------------------------
    "NrWierszaFa": ElementFacet(NATURALNY),
    "UU_ID": ElementFacet(TZN50),
    "P_6A": ElementFacet(DATA_TRANSPORTU),
    "P_7": ElementFacet(TZN512),
    "Indeks": ElementFacet(TZN50),
    "GTIN": ElementFacet(TZN20),
    "PKWiU": ElementFacet(TZN50),
    "CN": ElementFacet(TZN50),
    "PKOB": ElementFacet(TZN50),
    "P_8A": ElementFacet(TZN),
    "P_8B": ElementFacet(ILOSCI),
    "P_9A": ElementFacet(KWOTOWY2),
    "P_9B": ElementFacet(KWOTOWY2),
    "P_10": ElementFacet(KWOTOWY2),
    "P_11": ElementFacet(KWOTOWY),
    "P_11A": ElementFacet(KWOTOWY),
    "P_11Vat": ElementFacet(KWOTOWY),
    "P_12": ElementFacet(STAWKA_PODATKU),
    "P_12_XII": ElementFacet(PROCENT),
    "P_12_Zal_15": ElementFacet(WYBOR1),
    "KwotaAkcyzy": ElementFacet(KWOTOWY),
    "GTU": ElementFacet(GTU),
    "Procedura": ElementFacet(PROCEDURA),
    "KursWaluty": ElementFacet(ILOSCI),
    "StanPrzed": ElementFacet(WYBOR1),
    # --- Korekta ----------------------------------------------------------
    "PrzyczynaKorekty": ElementFacet(TZN),
    "TypKorekty": ElementFacet(TYP_KOREKTY),
    "DataWystFaKorygowanej": ElementFacet(DATA_TRANSPORTU),
    "NrFaKorygowanej": ElementFacet(TZN),
    "NrKSeF": ElementFacet(WYBOR1),
    "NrKSeFFaKorygowanej": ElementFacet(
        NUMER_KSEF,
        pattern=re.compile(
            r"([1-9]((\d[1-9])|([1-9]\d))\d{7}|M\d{9}|[A-Z]{3}\d{7})-"
            r"(20[2-9][0-9]|2[1-9][0-9]{2}|[3-9][0-9]{3})"
            r"(0[1-9]|1[0-2])(0[1-9]|[1-2][0-9]|3[0-1])-"
            r"([0-9A-F]{6})-?([0-9A-F]{6})-([0-9A-F]{2})"
        ),
        pattern_hint=(
            "numer KSeF: NIP-data-6hex-6hex-2hex, np. 1111111111-20260714-D5FB0C-9ED490-9A"
        ),
    ),
    "NrKSeFN": ElementFacet(WYBOR1),
    "OkresFaKorygowanej": ElementFacet(TZN),
    "NrFaKorygowany": ElementFacet(TZN),
    "P_15ZK": ElementFacet(KWOTOWY),
    "KursWalutyZK": ElementFacet(ILOSCI),
    # --- Zaliczki, zamówienie, opis dodatkowy -----------------------------
    "P_6Z": ElementFacet(DATA_TRANSPORTU),
    "P_15Z": ElementFacet(KWOTOWY),
    "KursWalutyZW": ElementFacet(ILOSCI),
    "NrKSeFFaZaliczkowej": ElementFacet(
        NUMER_KSEF,
    ),
    "NrKSeFZN": ElementFacet(WYBOR1),
    "NrFaZaliczkowej": ElementFacet(TZN),
    "Klucz": ElementFacet(TZN),
    "Wartosc": ElementFacet(TZN),
    "NrWiersza": ElementFacet(NATURALNY),
    "WartoscZamowienia": ElementFacet(KWOTOWY),
    "NrWierszaZam": ElementFacet(NATURALNY),
    "UU_IDZ": ElementFacet(TZN50),
    "P_7Z": ElementFacet(TZN512),
    "IndeksZ": ElementFacet(TZN50),
    "GTINZ": ElementFacet(TZN20),
    "PKWiUZ": ElementFacet(TZN50),
    "CNZ": ElementFacet(TZN50),
    "PKOBZ": ElementFacet(TZN50),
    "P_8AZ": ElementFacet(TZN),
    "P_8BZ": ElementFacet(ILOSCI),
    "P_9AZ": ElementFacet(KWOTOWY2),
    "P_11NettoZ": ElementFacet(KWOTOWY),
    "P_11VatZ": ElementFacet(KWOTOWY),
    "P_12Z": ElementFacet(STAWKA_PODATKU),
    "P_12Z_XII": ElementFacet(PROCENT),
    "P_12Z_Zal_15": ElementFacet(WYBOR1),
    "KwotaAkcyzyZ": ElementFacet(KWOTOWY),
    "GTUZ": ElementFacet(GTU),
    "ProceduraZ": ElementFacet(PROCEDURA_Z),
    "StanPrzedZ": ElementFacet(WYBOR1),
    "KursWalutyZ": ElementFacet(ILOSCI),
    # --- Rozliczenie ------------------------------------------------------
    "Kwota": ElementFacet(KWOTOWY),
    "Powod": ElementFacet(TZN),
    "SumaObciazen": ElementFacet(KWOTOWY),
    "SumaOdliczen": ElementFacet(KWOTOWY),
    "DoZaplaty": ElementFacet(KWOTOWY),
    "DoRozliczenia": ElementFacet(KWOTOWY),
    # --- Płatność ---------------------------------------------------------
    "Zaplacono": ElementFacet(WYBOR1),
    "DataZaplaty": ElementFacet(DATA),
    "ZnacznikZaplatyCzesciowej": ElementFacet(WYBOR1_2),
    "KwotaZaplatyCzesciowej": ElementFacet(KWOTOWY),
    "DataZaplatyCzesciowej": ElementFacet(DATA),
    "Termin": ElementFacet(DATA),
    "Ilosc": ElementFacet(Facet(FacetKind.INTEGER, None, whitespace=_WS_COLLAPSE)),
    "Jednostka": ElementFacet(TZN50),
    "ZdarzeniePoczatkowe": ElementFacet(TZN),
    "FormaPlatnosci": ElementFacet(FORMA_PLATNOSCI),
    "PlatnoscInna": ElementFacet(WYBOR1),
    "OpisPlatnosci": ElementFacet(TZN),
    "NrRB": ElementFacet(NRRB),
    "SWIFT": ElementFacet(
        Facet(FacetKind.STRING, "SWIFT_Type", lengths=frozenset({8, 11})),
        pattern=re.compile(r"[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?"),
        pattern_hint="8 lub 11 znaków: 6 liter, 2 znaki alfanumeryczne i opcjonalne 3",
    ),
    "RachunekWlasnyBanku": ElementFacet(RACHUNEK_WLASNY_BANKU),
    "NazwaBanku": ElementFacet(TZN),
    "OpisRachunku": ElementFacet(TZN),
    "WarunkiSkonta": ElementFacet(TZN),
    "WysokoscSkonta": ElementFacet(TZN),
    "LinkDoPlatnosci": ElementFacet(TZN512),
    "IPKSeF": ElementFacet(
        Facet(FacetKind.STRING, None, lengths=frozenset({13}), whitespace=_WS_COLLAPSE),
        pattern=re.compile(r"[0-9]{3}[a-zA-Z0-9]{10}"),
        pattern_hint="3 cyfry i 10 znaków alfanumerycznych",
    ),
    # --- Warunki transakcji ----------------------------------------------
    "DataUmowy": ElementFacet(DATA_UMOWY),
    "NrUmowy": ElementFacet(TZN),
    "DataZamowienia": ElementFacet(DATA_UMOWY),
    "NrZamowienia": ElementFacet(TZN),
    "NrPartiiTowaru": ElementFacet(TZN),
    "WarunkiDostawy": ElementFacet(TZN),
    "KursUmowny": ElementFacet(ILOSCI),
    "WalutaUmowna": ElementFacet(KOD_WALUTY),
    "PodmiotPosredniczacy": ElementFacet(WYBOR1),
    # --- Transport --------------------------------------------------------
    "RodzajTransportu": ElementFacet(RODZAJ_TRANSPORTU),
    "TransportInny": ElementFacet(WYBOR1),
    "OpisInnegoTransportu": ElementFacet(TZN50),
    "NrZleceniaTransportu": ElementFacet(TZN),
    "OpisLadunku": ElementFacet(LADUNEK),
    "LadunekInny": ElementFacet(WYBOR1),
    "OpisInnegoLadunku": ElementFacet(TZN50),
    "JednostkaOpakowania": ElementFacet(TZN),
    "DataGodzRozpTransportu": ElementFacet(DATA_CZAS),
    "DataGodzZakTransportu": ElementFacet(DATA_CZAS),
    # --- Stopka -----------------------------------------------------------
    "StopkaFaktury": ElementFacet(Facet(FacetKind.STRING, "TTekstowy", max_length=3500)),
    "KRS": ElementFacet(
        Facet(FacetKind.STRING, "TNrKRS", max_length=10, minimum_length=10),
        pattern=re.compile(r"\d{10}"),
        pattern_hint="10 cyfr",
    ),
    "REGON": ElementFacet(
        Facet(FacetKind.STRING, "TNrREGON", max_length=14),
        pattern=re.compile(r"\d{9}|\d{14}"),
        pattern_hint="9 albo 14 cyfr",
    ),
    "BDO": ElementFacet(Facet(FacetKind.STRING, None, max_length=9, whitespace=_WS_COLLAPSE)),
    # --- Załącznik --------------------------------------------------------
    "ZNaglowek": ElementFacet(TZN512),
    "ZKlucz": ElementFacet(TZN),
    "ZWartosc": ElementFacet(TZN),
    "TMetaDane": ElementFacet(Facet(FacetKind.STRING, None)),
    "TKlucz": ElementFacet(TZN),
    "TWartosc": ElementFacet(TZN),
    "Akapit": ElementFacet(TZN512),
    "Opis": ElementFacet(TZN512),
    # `NKom` to `xsd:extension base="tns:TZnakowy2"` (minLength=0), tak jak `SKom`.
    "NKom": ElementFacet(TZN2),
    "WKom": ElementFacet(TZN2),
    "SKom": ElementFacet(TZN2),
    # --- Nowe środki transportu ------------------------------------------
    "P_22A": ElementFacet(DATA_TRANSPORTU),
    "P_NrWierszaNST": ElementFacet(NATURALNY),
    "P_22B1": ElementFacet(TZN),
    "P_22B2": ElementFacet(TZN),
    "P_22B3": ElementFacet(TZN),
    "P_22B4": ElementFacet(TZN),
    "P_22C": ElementFacet(TZN),
    "P_22C1": ElementFacet(TZN),
    "P_22D": ElementFacet(TZN),
}


#: Limity liczby wystąpień rodzeństwa wewnątrz danego rodzica, dla przypadków,
#: w których sam element ma różne limity w różnych kontekstach albo limit jest
#: istotny dla poprawnego dokumentu. Klucz: ``(rodzic, dziecko)``.
OCCURRENCE_LIMITS: dict[tuple[str, str], int] = {
    ("Faktura", "Podmiot3"): 100,
    ("Faktura", "PodmiotUpowazniony"): 1,
    ("Faktura", "Zalacznik"): 1,
    ("Faktura", "Stopka"): 1,
    ("Fa", "FaWiersz"): 10000,
    ("Fa", "DodatkowyOpis"): 10000,
    ("Fa", "ZaliczkaCzesciowa"): 31,
    ("Fa", "FakturaZaliczkowa"): 100,
    ("Fa", "DaneFaKorygowanej"): 50000,
    ("Fa", "Podmiot1K"): 1,
    ("Fa", "Podmiot2K"): 101,
    ("Fa", "WZ"): 1000,
    ("Platnosc", "TerminPlatnosci"): 100,
    ("Platnosc", "RachunekBankowy"): 100,
    ("Platnosc", "RachunekBankowyFaktora"): 20,
    # Schemat: `Platnosc/ZaplataCzesciowa` ma `maxOccurs="100"`.
    ("Platnosc", "ZaplataCzesciowa"): 100,
    # Schemat: `DaneKontaktowe` ma `maxOccurs="3"` w każdym z podmiotów.
    ("Podmiot1", "DaneKontaktowe"): 3,
    ("Podmiot2", "DaneKontaktowe"): 3,
    ("Podmiot3", "DaneKontaktowe"): 3,
    ("PodmiotUpowazniony", "DaneKontaktowe"): 3,
    ("Rozliczenie", "Obciazenia"): 100,
    ("Rozliczenie", "Odliczenia"): 100,
    ("WarunkiTransakcji", "Umowy"): 100,
    ("WarunkiTransakcji", "Zamowienia"): 100,
    ("WarunkiTransakcji", "NrPartiiTowaru"): 1000,
    ("WarunkiTransakcji", "Transport"): 20,
    ("Transport", "WysylkaPrzez"): 20,
    ("Zamowienie", "ZamowienieWiersz"): 10000,
    ("Stopka", "Informacje"): 3,
    ("Stopka", "Rejestry"): 100,
    ("Zalacznik", "BlokDanych"): 1000,
    ("BlokDanych", "MetaDane"): 1000,
    ("Tekst", "Akapit"): 10,
    ("BlokDanych", "Tabela"): 1000,
    ("TNaglowek", "Kol"): 20,
    ("Tabela", "Wiersz"): 1000,
    ("Wiersz", "WKom"): 20,
    ("Suma", "SKom"): 20,
    ("DaneKontaktowe", "Email"): 1,
    ("DaneKontaktowe", "Telefon"): 1,
    ("Faktura", "Podmiot1"): 1,
    ("Faktura", "Podmiot2"): 1,
    ("Faktura", "Naglowek"): 1,
    ("Faktura", "Fa"): 1,
}


#: Elementy, które muszą wystąpić co najmniej raz w swoim rodzicu.
REQUIRED_IN_PARENT: frozenset[tuple[str, str]] = frozenset(
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
        ("BlokDanych", "MetaDane"),
        ("Zamowienie", "WartoscZamowienia"),
        ("Zamowienie", "ZamowienieWiersz"),
        ("Przewoznik", "AdresPrzewoznika"),
        ("Zalacznik", "BlokDanych"),
        ("Tabela", "TNaglowek"),
        ("Tabela", "Wiersz"),
        ("TNaglowek", "Kol"),
        ("RachunekBankowy", "NrRB"),
        ("RachunekBankowyFaktora", "NrRB"),
        ("ZaplataCzesciowa", "KwotaZaplatyCzesciowej"),
        ("ZaplataCzesciowa", "DataZaplatyCzesciowej"),
        # Pary wynikające z typów dziedzinowych: schemat nie ma tam `minOccurs="0"`,
        # więc pominięcie któregokolwiek daje XML odrzucany przez KSeF.
        ("Podmiot1K", "Adres"),
        ("Podmiot1K", "DaneIdentyfikacyjne"),
        ("Wiersz", "WKom"),
        ("Adres", "KodKraju"),
        ("Adres", "AdresL1"),
        ("Fa", "RodzajFaktury"),
        ("Fa", "Adnotacje"),
        ("FaWiersz", "NrWierszaFa"),
        ("MetaDane", "ZKlucz"),
        ("MetaDane", "ZWartosc"),
        ("TerminOpis", "Ilosc"),
        ("TerminOpis", "Jednostka"),
        ("TerminOpis", "ZdarzeniePoczatkowe"),
    }
)


#: Wartości wymuszone przez ``xsd:element/@fixed`` — klucz to
#: ``(rodzic, element, wartość)``.
#:
#: Kluczem jest PARA (rodzic, element), bo ten sam element bywa wolny w innym
#: miejscu schematu: ``Podmiot1/PrefiksPodatnika`` ma ``fixed="PL"``
#: (schemat_FA(3):2137), ale ``Podmiot1K/PrefiksPodatnika`` już nie
#: (schemat_FA(3):2948) — tam typ ``TKodyKrajowUE`` dopuszcza 28 kodów i
#: odrzucanie ich byłoby błędem (dokument jest wtedy zgodny ze schematem).
FIXED_IN_PARENT: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("Podmiot1", "PrefiksPodatnika", "PL"),
    }
)


#: Wymagania zależne od PRZODKA (``(przodek, rodzic, element)``).
#:
#: ``REQUIRED_IN_PARENT`` dopasowuje rodzica po nazwie lokalnej, a ta sama nazwa
#: ``DaneIdentyfikacyjne`` występuje w siedmiu kontekstach o różnych typach:
#: ``Nazwa`` jest obowiązkowa w ``TPodmiot1`` (``<xsd:sequence>`` bez
#: ``minOccurs="0"``), ale opcjonalna w ``TPodmiot2``/``TPodmiot3``
#: (``<xsd:sequence minOccurs="0">`` — faktura uproszczona, art. 106e ust. 5
#: pkt 3). Bez rozróżnienia kontekstu SDK odrzucał dwa z 26 oficjalnych
#: przykładów MF (``FA_3_Przykład_15/16.xml``: nabywca bez nazwy).
REQUIRED_IN_ANCESTOR: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("Podmiot1", "DaneIdentyfikacyjne", "Nazwa"),
        ("Podmiot1K", "DaneIdentyfikacyjne", "Nazwa"),
        ("PodmiotUpowazniony", "DaneIdentyfikacyjne", "Nazwa"),
    }
)


def fixed_value(parent: str, child: str) -> str | None:
    """Wartość wymuszona przez ``xsd:element/@fixed`` dla pary rodzic/element."""
    for fixed_parent, fixed_child, value in FIXED_IN_PARENT:
        if fixed_parent == parent and fixed_child == child:
            return value
    return None


def facet_for(element_name: str) -> ElementFacet | None:
    """Zwraca ograniczenie elementu albo ``None``, jeśli element nie ma wpisu."""
    return ELEMENT_FACETS.get(element_name)


def occurrence_limit(parent: str, child: str) -> int | None:
    """Limit liczby wystąpień ``child`` wewnątrz ``parent`` (albo ``None``)."""
    explicit = OCCURRENCE_LIMITS.get((parent, child))
    if explicit is not None:
        return explicit
    entry = ELEMENT_FACETS.get(child)
    return entry.max_occurrences if entry is not None else None
