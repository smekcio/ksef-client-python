from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import date
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from typing import Any

from ksef_client.utils.zip_utils import build_zip

MONEY_QUANT = Decimal("0.01")
QUANTITY_QUANT = Decimal("0.0001")


class FA3InvoiceKind(str, Enum):
    BASIC = "podstawowa"
    SIMPLIFIED = "uproszczona"
    CORRECTION = "korygująca"
    ADVANCE = "zaliczkowa"
    SETTLEMENT = "rozliczeniowa"
    ADVANCE_CORRECTION = "korekta zaliczki"
    SETTLEMENT_CORRECTION = "korekta rozliczenia"

    @property
    def xml_code(self) -> str:
        return _INVOICE_KIND_XML_CODES[self]

    @classmethod
    def parse(cls, value: Any) -> FA3InvoiceKind:
        if isinstance(value, cls):
            return value
        normalized = _normalize_label(value)
        aliases = {
            "podstawowa": cls.BASIC,
            "faktura podstawowa": cls.BASIC,
            "vat": cls.BASIC,
            "uproszczona": cls.SIMPLIFIED,
            "faktura uproszczona": cls.SIMPLIFIED,
            "upr": cls.SIMPLIFIED,
            "korygujaca": cls.CORRECTION,
            "korygująca": cls.CORRECTION,
            "faktura korygujaca": cls.CORRECTION,
            "faktura korygująca": cls.CORRECTION,
            "kor": cls.CORRECTION,
            "zaliczkowa": cls.ADVANCE,
            "faktura zaliczkowa": cls.ADVANCE,
            "zal": cls.ADVANCE,
            "rozliczeniowa": cls.SETTLEMENT,
            "faktura rozliczeniowa": cls.SETTLEMENT,
            "roz": cls.SETTLEMENT,
            "korekta zaliczki": cls.ADVANCE_CORRECTION,
            "korekta faktury zaliczkowej": cls.ADVANCE_CORRECTION,
            "kor zal": cls.ADVANCE_CORRECTION,
            "kor_zal": cls.ADVANCE_CORRECTION,
            "korekta rozliczenia": cls.SETTLEMENT_CORRECTION,
            "korekta faktury rozliczeniowej": cls.SETTLEMENT_CORRECTION,
            "kor roz": cls.SETTLEMENT_CORRECTION,
            "kor_roz": cls.SETTLEMENT_CORRECTION,
        }
        try:
            return aliases[normalized]
        except KeyError as exc:
            raise ValueError(f"Nieznany typ faktury: {value!r}.") from exc


_INVOICE_KIND_XML_CODES = {
    FA3InvoiceKind.BASIC: "VAT",
    FA3InvoiceKind.SIMPLIFIED: "UPR",
    FA3InvoiceKind.CORRECTION: "KOR",
    FA3InvoiceKind.ADVANCE: "ZAL",
    FA3InvoiceKind.SETTLEMENT: "ROZ",
    FA3InvoiceKind.ADVANCE_CORRECTION: "KOR_ZAL",
    FA3InvoiceKind.SETTLEMENT_CORRECTION: "KOR_ROZ",
}


def _normalize_label(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", " ").replace("_", " ")


def decimal_from_value(value: Any, *, field_name: str) -> Decimal:
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int | float):
        return Decimal(str(value))
    text = str(value or "").strip().replace(" ", "").replace(",", ".")
    if not text:
        raise ValueError(f"Pole '{field_name}' jest wymagane.")
    try:
        return Decimal(text)
    except InvalidOperation as exc:
        raise ValueError(f"Pole '{field_name}' musi być liczbą.") from exc


def money(value: Decimal) -> Decimal:
    return value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)


def _decimal_to_json(value: Decimal | None) -> str | None:
    return None if value is None else format(value, "f")


def _date_to_json(value: date | None) -> str | None:
    return None if value is None else value.isoformat()


@dataclass(frozen=True)
class FA3ValidationIssue:
    message: str
    invoice_number: str | None = None
    row_number: int | None = None
    column: str | None = None
    cell: str | None = None
    severity: str = "error"

    def with_location(
        self,
        *,
        row_number: int | None = None,
        cell: str | None = None,
    ) -> FA3ValidationIssue:
        return FA3ValidationIssue(
            message=self.message,
            invoice_number=self.invoice_number,
            row_number=self.row_number if row_number is None else row_number,
            column=self.column,
            cell=self.cell if cell is None else cell,
            severity=self.severity,
        )


@dataclass(frozen=True)
class FA3Party:
    name: str
    tax_id: str
    address: str = ""
    country_code: str = "PL"

    def validate(self, label: str) -> list[FA3ValidationIssue]:
        issues: list[FA3ValidationIssue] = []
        if not self.name.strip():
            issues.append(FA3ValidationIssue(f"{label}: nazwa jest wymagana."))
        if not self.tax_id.strip():
            issues.append(FA3ValidationIssue(f"{label}: NIP jest wymagany."))
        if not self.country_code.strip():
            issues.append(FA3ValidationIssue(f"{label}: kraj jest wymagany."))
        return issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "nazwa": self.name,
            "nip": self.tax_id,
            "adres": self.address,
            "kraj": self.country_code,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FA3Party:
        return cls(
            name=str(data.get("nazwa") or data.get("name") or ""),
            tax_id=str(data.get("nip") or data.get("tax_id") or data.get("taxId") or ""),
            address=str(data.get("adres") or data.get("address") or ""),
            country_code=str(
                data.get("kraj") or data.get("country_code") or data.get("countryCode") or "PL"
            ),
        )


@dataclass(frozen=True)
class FA3Line:
    description: str
    quantity: Decimal
    unit: str
    unit_net_price: Decimal
    vat_rate: Decimal | None
    net_amount: Decimal | None = None
    vat_amount: Decimal | None = None
    gross_amount: Decimal | None = None

    @property
    def computed_net_amount(self) -> Decimal:
        return money(self.quantity * self.unit_net_price)

    @property
    def computed_vat_amount(self) -> Decimal:
        if self.vat_rate is None:
            return Decimal("0.00")
        return money(self.computed_net_amount * self.vat_rate / Decimal("100"))

    @property
    def computed_gross_amount(self) -> Decimal:
        return money(self.computed_net_amount + self.computed_vat_amount)

    @property
    def effective_net_amount(self) -> Decimal:
        if self.net_amount is not None:
            return money(self.net_amount)
        return self.computed_net_amount

    @property
    def effective_vat_amount(self) -> Decimal:
        if self.vat_amount is not None:
            return money(self.vat_amount)
        return self.computed_vat_amount

    @property
    def effective_gross_amount(self) -> Decimal:
        if self.gross_amount is not None:
            return money(self.gross_amount)
        return self.computed_gross_amount

    def validate(self) -> tuple[list[FA3ValidationIssue], list[FA3ValidationIssue]]:
        errors: list[FA3ValidationIssue] = []
        warnings: list[FA3ValidationIssue] = []
        if not self.description.strip():
            errors.append(
                FA3ValidationIssue(
                    "Pozycja: opis pozycji jest wymagany.",
                    column="Opis pozycji",
                )
            )
        if self.quantity <= 0:
            errors.append(
                FA3ValidationIssue("Pozycja: ilość musi być większa od zera.", column="Ilość")
            )
        if self.unit_net_price < 0:
            errors.append(
                FA3ValidationIssue(
                    "Pozycja: cena netto nie może być ujemna.",
                    column="Cena netto",
                )
            )
        if self.vat_rate is not None and self.vat_rate < 0:
            errors.append(
                FA3ValidationIssue("Pozycja: stawka VAT nie może być ujemna.", column="VAT")
            )
        expected = {
            "Wartość netto": (self.net_amount, self.computed_net_amount),
            "Kwota VAT": (self.vat_amount, self.computed_vat_amount),
            "Wartość brutto": (self.gross_amount, self.computed_gross_amount),
        }
        for column, (provided, computed) in expected.items():
            if provided is not None and abs(money(provided) - computed) > MONEY_QUANT:
                warnings.append(
                    FA3ValidationIssue(
                        f"{column}: wpisana kwota {money(provided)} różni się od "
                        f"wyliczonej {computed}. "
                        "Zostanie zachowana jako świadomy override.",
                        column=column,
                        severity="warning",
                    )
                )
        return errors, warnings

    def to_dict(self) -> dict[str, Any]:
        return {
            "opis": self.description,
            "ilosc": _decimal_to_json(self.quantity),
            "jm": self.unit,
            "cena_netto": _decimal_to_json(self.unit_net_price),
            "vat": "zw" if self.vat_rate is None else _decimal_to_json(self.vat_rate),
            "wartosc_netto": _decimal_to_json(self.net_amount),
            "kwota_vat": _decimal_to_json(self.vat_amount),
            "wartosc_brutto": _decimal_to_json(self.gross_amount),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FA3Line:
        vat_value = data.get("vat")
        return cls(
            description=str(data.get("opis") or data.get("description") or ""),
            quantity=decimal_from_value(
                _first_present_value(data, "ilosc", "quantity"), field_name="ilosc"
            ),
            unit=str(data.get("jm") or data.get("unit") or "szt"),
            unit_net_price=decimal_from_value(
                _first_present_value(data, "cena_netto", "unit_net_price", "unitNetPrice"),
                field_name="cena_netto",
            ),
            vat_rate=parse_vat_rate(vat_value),
            net_amount=_optional_decimal(data, "wartosc_netto", "net_amount", "netAmount"),
            vat_amount=_optional_decimal(data, "kwota_vat", "vat_amount", "vatAmount"),
            gross_amount=_optional_decimal(data, "wartosc_brutto", "gross_amount", "grossAmount"),
        )


def parse_vat_rate(value: Any) -> Decimal | None:
    text = _normalize_label(value).replace("%", "").replace("vat", "").strip()
    if text in {"zw", "zwolniony", "np", "nie podlega"}:
        return None
    return decimal_from_value(text, field_name="VAT")


def _optional_decimal(data: dict[str, Any], *keys: str) -> Decimal | None:
    for key in keys:
        value = data.get(key)
        if value not in (None, ""):
            return decimal_from_value(value, field_name=key)
    return None


def _first_present_value(data: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = data.get(key)
        if value is not None:
            return value
    return None


@dataclass(frozen=True)
class FA3Draft:
    invoice_number: str
    issue_date: date
    seller: FA3Party
    buyer: FA3Party
    lines: list[FA3Line]
    kind: FA3InvoiceKind = FA3InvoiceKind.BASIC
    currency: str = "PLN"
    issue_place: str = ""
    payment_due_date: date | None = None
    payment_method: str | None = None
    correction_reason: str | None = None
    corrected_invoice_number: str | None = None
    corrected_invoice_date: date | None = None
    corrected_ksef_number: str | None = None
    advance_invoice_number: str | None = None
    advance_ksef_number: str | None = None
    settlement_amount: Decimal | None = None
    warnings: tuple[FA3ValidationIssue, ...] = field(default_factory=tuple)

    @property
    def total_net(self) -> Decimal:
        return money(sum((line.effective_net_amount for line in self.lines), Decimal("0.00")))

    @property
    def total_vat(self) -> Decimal:
        return money(sum((line.effective_vat_amount for line in self.lines), Decimal("0.00")))

    @property
    def total_gross(self) -> Decimal:
        return money(sum((line.effective_gross_amount for line in self.lines), Decimal("0.00")))

    def validate(self) -> tuple[list[FA3ValidationIssue], list[FA3ValidationIssue]]:
        errors: list[FA3ValidationIssue] = []
        warnings = list(self.warnings)
        if not self.invoice_number.strip():
            errors.append(
                FA3ValidationIssue("Numer faktury jest wymagany.", column="Numer faktury")
            )
        if not self.currency.strip():
            errors.append(FA3ValidationIssue("Waluta jest wymagana.", column="Waluta"))
        if not self.lines:
            errors.append(FA3ValidationIssue("Faktura musi zawierać co najmniej jedną pozycję."))
        errors.extend(self.seller.validate("Sprzedawca"))
        errors.extend(self.buyer.validate("Nabywca"))
        for line in self.lines:
            line_errors, line_warnings = line.validate()
            errors.extend(line_errors)
            warnings.extend(line_warnings)
        errors.extend(self._validate_kind_specific())
        errors.extend(self._validate_xml_shape())
        numbered_errors = [self._tag_issue(issue) for issue in errors]
        numbered_warnings = [self._tag_issue(issue) for issue in warnings]
        return numbered_errors, numbered_warnings

    def _tag_issue(self, issue: FA3ValidationIssue) -> FA3ValidationIssue:
        return FA3ValidationIssue(
            message=issue.message,
            invoice_number=self.invoice_number,
            row_number=issue.row_number,
            column=issue.column,
            cell=issue.cell,
            severity=issue.severity,
        )

    def _validate_kind_specific(self) -> list[FA3ValidationIssue]:
        correction_kinds = {
            FA3InvoiceKind.CORRECTION,
            FA3InvoiceKind.ADVANCE_CORRECTION,
            FA3InvoiceKind.SETTLEMENT_CORRECTION,
        }
        issues: list[FA3ValidationIssue] = []
        if self.kind in correction_kinds:
            if not self.correction_reason:
                issues.append(
                    FA3ValidationIssue(
                        "Korekta: przyczyna korekty jest wymagana.",
                        column="Przyczyna korekty",
                    )
                )
            if not self.corrected_invoice_date:
                issues.append(
                    FA3ValidationIssue(
                        "Korekta: data faktury korygowanej jest wymagana.",
                        column="Data faktury korygowanej",
                    )
                )
            if not self.corrected_invoice_number:
                issues.append(
                    FA3ValidationIssue(
                        "Korekta: numer faktury korygowanej jest wymagany.",
                        column="Numer faktury korygowanej",
                    )
                )
        settlement_kinds = {FA3InvoiceKind.SETTLEMENT, FA3InvoiceKind.SETTLEMENT_CORRECTION}
        if self.kind in settlement_kinds and not (
            self.advance_invoice_number or self.advance_ksef_number
        ):
            issues.append(
                FA3ValidationIssue(
                    "Rozliczenie: podaj numer faktury zaliczkowej albo numer KSeF "
                    "faktury zaliczkowej.",
                    column="Numer faktury zaliczkowej",
                )
            )
        return issues

    def _validate_xml_shape(self) -> list[FA3ValidationIssue]:
        issues: list[FA3ValidationIssue] = []
        has_invoice_number = bool(str(self.advance_invoice_number or "").strip())
        has_ksef_number = bool(str(self.advance_ksef_number or "").strip())
        if has_invoice_number and has_ksef_number:
            issues.append(
                FA3ValidationIssue(
                    "invoice.advance_invoice_number: podaj numer faktury zaliczkowej albo numer KSeF, nie oba."
                )
            )
        return issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "numer_faktury": self.invoice_number,
            "typ_faktury": self.kind.value,
            "data_wystawienia": self.issue_date.isoformat(),
            "waluta": self.currency,
            "miejsce_wystawienia": self.issue_place,
            "sprzedawca": self.seller.to_dict(),
            "nabywca": self.buyer.to_dict(),
            "pozycje": [line.to_dict() for line in self.lines],
            "platnosc": {
                "termin": _date_to_json(self.payment_due_date),
                "forma": self.payment_method,
            },
            "korekta": {
                "przyczyna": self.correction_reason,
                "numer_faktury_korygowanej": self.corrected_invoice_number,
                "data_faktury_korygowanej": _date_to_json(self.corrected_invoice_date),
                "numer_ksef_faktury_korygowanej": self.corrected_ksef_number,
            },
            "zaliczka": {
                "numer_faktury_zaliczkowej": self.advance_invoice_number,
                "numer_ksef_faktury_zaliczkowej": self.advance_ksef_number,
            },
            "rozliczenie": {
                "kwota": _decimal_to_json(self.settlement_amount),
            },
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FA3Draft:
        payment = _first_present_value(data, "platnosc", "payment") or {}
        correction = _first_present_value(data, "korekta", "correction") or {}
        advance = _first_present_value(data, "zaliczka", "advance") or {}
        settlement = _first_present_value(data, "rozliczenie", "settlement") or {}
        lines_data = _first_present_value(data, "pozycje", "lines") or []
        issue_date = _first_present_value(data, "data_wystawienia", "issue_date", "issueDate")
        return cls(
            invoice_number=str(
                _first_present_value(data, "numer_faktury", "invoice_number", "invoiceNumber")
                or ""
            ),
            kind=FA3InvoiceKind.parse(
                _first_present_value(data, "typ_faktury", "kind") or FA3InvoiceKind.BASIC
            ),
            issue_date=_parse_iso_date(issue_date),
            currency=str(_first_present_value(data, "waluta", "currency") or "PLN").upper(),
            issue_place=str(_first_present_value(data, "miejsce_wystawienia", "issue_place") or ""),
            seller=FA3Party.from_dict(_first_present_value(data, "sprzedawca", "seller") or {}),
            buyer=FA3Party.from_dict(_first_present_value(data, "nabywca", "buyer") or {}),
            lines=[FA3Line.from_dict(line) for line in lines_data],
            payment_due_date=_optional_iso_date(
                _first_present_value(payment, "termin", "due_date")
            ),
            payment_method=_first_present_value(payment, "forma", "method"),
            correction_reason=_first_present_value(correction, "przyczyna", "reason"),
            corrected_invoice_number=_first_present_value(
                correction,
                "numer_faktury_korygowanej",
                "invoice_number",
            ),
            corrected_invoice_date=_optional_iso_date(
                _first_present_value(correction, "data_faktury_korygowanej", "invoice_date")
            ),
            corrected_ksef_number=_first_present_value(
                correction,
                "numer_ksef_faktury_korygowanej",
                "ksef_number",
            ),
            advance_invoice_number=_first_present_value(
                advance,
                "numer_faktury_zaliczkowej",
                "invoice_number",
            ),
            advance_ksef_number=_first_present_value(
                advance,
                "numer_ksef_faktury_zaliczkowej",
                "ksef_number",
            ),
            settlement_amount=_optional_decimal(settlement, "kwota", "amount"),
        )

    def to_xml(self, *, validate: bool = True, xsd_validate: bool = False) -> bytes:
        from .xml import draft_to_xml

        return draft_to_xml(self, validate=validate, xsd_validate=xsd_validate)


def _parse_iso_date(value: Any) -> date:
    if isinstance(value, date):
        return value
    text = str(value or "").strip()
    if not text:
        raise ValueError("Data jest wymagana.")
    return date.fromisoformat(text)


def _optional_iso_date(value: Any) -> date | None:
    if value in (None, ""):
        return None
    return _parse_iso_date(value)


@dataclass
class FA3InvoiceBuilder:
    invoice_number: str
    issue_date: date
    seller: FA3Party
    buyer: FA3Party
    kind: FA3InvoiceKind = FA3InvoiceKind.BASIC
    currency: str = "PLN"
    issue_place: str = ""
    payment_due_date: date | None = None
    payment_method: str | None = None
    correction_reason: str | None = None
    corrected_invoice_number: str | None = None
    corrected_invoice_date: date | None = None
    corrected_ksef_number: str | None = None
    advance_invoice_number: str | None = None
    advance_ksef_number: str | None = None
    settlement_amount: Decimal | None = None
    _lines: list[FA3Line] = field(default_factory=list)
    _warnings: list[FA3ValidationIssue] = field(default_factory=list)

    def add_line(
        self,
        description: str,
        *,
        quantity: Decimal | str | int | float,
        unit: str = "szt",
        unit_net_price: Decimal | str | int | float,
        vat_rate: Decimal | str | int | float | None = Decimal("23"),
        net_amount: Decimal | str | int | float | None = None,
        vat_amount: Decimal | str | int | float | None = None,
        gross_amount: Decimal | str | int | float | None = None,
    ) -> FA3InvoiceBuilder:
        line = FA3Line(
            description=description,
            quantity=decimal_from_value(quantity, field_name="quantity"),
            unit=unit,
            unit_net_price=decimal_from_value(unit_net_price, field_name="unit_net_price"),
            vat_rate=parse_vat_rate(vat_rate),
            net_amount=_coerce_optional_decimal(net_amount, "net_amount"),
            vat_amount=_coerce_optional_decimal(vat_amount, "vat_amount"),
            gross_amount=_coerce_optional_decimal(gross_amount, "gross_amount"),
        )
        _errors, warnings = line.validate()
        self._warnings.extend(warnings)
        self._lines.append(line)
        return self

    def build(self) -> FA3Draft:
        draft = FA3Draft(
            invoice_number=self.invoice_number,
            issue_date=self.issue_date,
            seller=self.seller,
            buyer=self.buyer,
            lines=list(self._lines),
            kind=self.kind,
            currency=self.currency.upper(),
            issue_place=self.issue_place,
            payment_due_date=self.payment_due_date,
            payment_method=self.payment_method,
            correction_reason=self.correction_reason,
            corrected_invoice_number=self.corrected_invoice_number,
            corrected_invoice_date=self.corrected_invoice_date,
            corrected_ksef_number=self.corrected_ksef_number,
            advance_invoice_number=self.advance_invoice_number,
            advance_ksef_number=self.advance_ksef_number,
            settlement_amount=self.settlement_amount,
            warnings=tuple(self._warnings),
        )
        errors, _warnings = draft.validate()
        if errors:
            joined = "; ".join(issue.message for issue in errors)
            raise ValueError(joined)
        return draft


def _coerce_optional_decimal(
    value: Decimal | str | int | float | None,
    field_name: str,
) -> Decimal | None:
    if value in (None, ""):
        return None
    return decimal_from_value(value, field_name=field_name)


@dataclass(frozen=True)
class FA3BatchDraft:
    drafts: tuple[FA3Draft, ...]

    def to_json(self, path: str | Path | None = None) -> str:
        payload = {
            "format": "ksef-client.fa3.batch-draft",
            "version": 1,
            "faktury": [draft.to_dict() for draft in self.drafts],
        }
        data = json.dumps(payload, ensure_ascii=False, indent=2)
        if path is not None:
            Path(path).write_text(data, encoding="utf-8")
        return data

    @classmethod
    def from_json(cls, value: str | Path | dict[str, Any]) -> FA3BatchDraft:
        if isinstance(value, dict):
            payload = value
        else:
            text_or_path = str(value)
            if text_or_path.lstrip().startswith(("{", "[")):
                payload = json.loads(text_or_path)
            else:
                payload = json.loads(Path(text_or_path).read_text(encoding="utf-8"))
        invoices = payload.get("faktury") or payload.get("invoices") or []
        return cls(tuple(FA3Draft.from_dict(invoice) for invoice in invoices))

    def to_xml_files(self, path: str | Path) -> list[Path]:
        directory = Path(path)
        directory.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for draft in self.drafts:
            file_path = directory / f"{_safe_file_stem(draft.invoice_number)}.xml"
            file_path.write_bytes(draft.to_xml())
            written.append(file_path)
        return written

    def to_xml_zip(self, path: str | Path) -> Path:
        files = {
            f"{_safe_file_stem(draft.invoice_number)}.xml": draft.to_xml() for draft in self.drafts
        }
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(build_zip(files))
        return target


def _safe_file_stem(value: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return stem or "faktura"
