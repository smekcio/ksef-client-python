from __future__ import annotations

import math
import re
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from ..models import (
    CollectiveIdentifierInvoice,
    CollectiveIdentifierInvoicePayment,
    CurrencyCode,
)
from .ksef_number import ValidationResult, _crc8, require_ksef_number

COLLECTIVE_IDENTIFIER_LENGTH = 35
COLLECTIVE_IDENTIFIER_PATTERN = re.compile(
    r"^([0-9]{10})-IZ([0-9]{4})(0[1-9]|1[0-2])-([0-9A-F]{12})-([0-9A-F]{2})$"
)

# The effective limit is context-dependent. This is the absolute upper bound
# accepted by the API's context-limit override schema.
MAX_INVOICES_PER_IDENTIFIER = 5000
MIN_INVOICES_PER_IDENTIFIER = 2
MAX_IDENTIFIERS_PER_INVOICE = 132
MAX_IDENTIFIERS_PER_INVOICES_QUERY = 10
MAX_QUERY_RANGE_DAYS = 100
MAX_INVOICE_DESCRIPTION_LENGTH = 512
PAGE_SIZE_MIN = 10
PAGE_SIZE_MAX = 200
PAGE_SIZE_INVOICES_MAX = 500

COLLECTIVE_IDENTIFIER_EXCEPTION_CODES = {
    71001: "Invoice cannot be assigned to a collective identifier",
    71002: "Invoice is already assigned to the maximum number of collective identifiers",
    71004: "Invoices belong to different sellers",
    71005: "Duplicated KSeF number in the request",
}

# Kody błędów sesji wysyłki istotne dla logiki ponawiania (KSeF API 2.8.0+).
SESSION_EXCEPTION_CODES = {
    21180: "Session status does not allow the operation",
    21184: "Session temporarily unavailable - open a new session and continue sending",
}

_DATE_ONLY_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def validate_collective_identifier_number(
    collective_identifier_number: str,
) -> ValidationResult:
    if not collective_identifier_number:
        return ValidationResult(False, "empty value")

    if len(collective_identifier_number) != COLLECTIVE_IDENTIFIER_LENGTH:
        return ValidationResult(False, "invalid length")

    if not COLLECTIVE_IDENTIFIER_PATTERN.match(collective_identifier_number):
        return ValidationResult(False, "invalid format")

    data_part = collective_identifier_number[:32]
    checksum = collective_identifier_number[-2:]
    expected = f"{_crc8(data_part.encode('ascii')):02X}"
    if expected != checksum:
        return ValidationResult(False, f"checksum mismatch (expected {expected})")

    return ValidationResult(True, "ok")


def is_valid_collective_identifier_number(collective_identifier_number: str) -> bool:
    return validate_collective_identifier_number(collective_identifier_number).is_valid


def require_collective_identifier_number(collective_identifier_number: str) -> str:
    result = validate_collective_identifier_number(collective_identifier_number)
    if not result.is_valid:
        raise ValueError(f"Invalid collective identifier number: {result.message}")
    return collective_identifier_number


def require_page_size(value: int, *, maximum: int = PAGE_SIZE_MAX) -> int:
    if PAGE_SIZE_MIN <= value <= maximum:
        return value
    raise ValueError(f"page_size must be between {PAGE_SIZE_MIN} and {maximum}")


def require_invoices_query_identifiers(
    collective_identifier_numbers: str | Sequence[str],
) -> list[str]:
    if isinstance(collective_identifier_numbers, str):
        numbers = [collective_identifier_numbers]
    else:
        numbers = list(collective_identifier_numbers)
    if not numbers:
        raise ValueError("At least one collective identifier number is required")
    if len(numbers) > MAX_IDENTIFIERS_PER_INVOICES_QUERY:
        raise ValueError(
            "Cannot query more than "
            f"{MAX_IDENTIFIERS_PER_INVOICES_QUERY} collective identifiers at once"
        )
    seen: set[str] = set()
    normalized: list[str] = []
    for number in numbers:
        number = require_collective_identifier_number(number)
        if number in seen:
            raise ValueError(f"Duplicate collective identifier number in invoices query: {number}")
        seen.add(number)
        normalized.append(number)
    return normalized


def require_query_date_range(date_from: str, date_to: str) -> tuple[str, str]:
    parsed_from = _parse_query_datetime(date_from, field_name="dateCreatedFrom")
    parsed_to = _parse_query_datetime(date_to, field_name="dateCreatedTo")
    if parsed_from > parsed_to:
        raise ValueError("dateCreatedFrom must be earlier than or equal to dateCreatedTo")
    if parsed_to - parsed_from > timedelta(days=MAX_QUERY_RANGE_DAYS):
        raise ValueError(
            f"Collective identifier query range cannot exceed {MAX_QUERY_RANGE_DAYS} days"
        )
    return date_from, date_to


def expand_query_date_bound(value: str, *, end_of_day: bool) -> str:
    if _DATE_ONLY_RE.match(value):
        suffix = "T23:59:59.999999Z" if end_of_day else "T00:00:00Z"
        return f"{value}{suffix}"
    return value


def make_collective_identifier_invoice(
    ksef_number: str,
    *,
    description: str | None = None,
    amount: Decimal | str | int | float | None = None,
    currency: CurrencyCode | str | None = None,
) -> CollectiveIdentifierInvoice:
    ksef_number = require_ksef_number(ksef_number)
    if description is not None and len(description) > MAX_INVOICE_DESCRIPTION_LENGTH:
        raise ValueError(
            f"Invoice description cannot exceed {MAX_INVOICE_DESCRIPTION_LENGTH} characters"
        )
    payment = _build_payment(amount=amount, currency=currency)
    return CollectiveIdentifierInvoice(
        ksef_number=ksef_number,
        description=description,
        payment=payment,
    )


def require_generate_invoices(
    invoices: Sequence[CollectiveIdentifierInvoice],
    *,
    max_invoices: int | None = None,
) -> list[CollectiveIdentifierInvoice]:
    items = list(invoices)
    count = len(items)
    if count < MIN_INVOICES_PER_IDENTIFIER:
        raise ValueError(
            f"Collective identifier requires at least {MIN_INVOICES_PER_IDENTIFIER} invoices"
        )
    if max_invoices is not None and (
        isinstance(max_invoices, bool)
        or not isinstance(max_invoices, int)
        or not MIN_INVOICES_PER_IDENTIFIER <= max_invoices <= MAX_INVOICES_PER_IDENTIFIER
    ):
        raise ValueError(
            "max_invoices must be between "
            f"{MIN_INVOICES_PER_IDENTIFIER} and {MAX_INVOICES_PER_IDENTIFIER}"
        )
    max_allowed = (
        MAX_INVOICES_PER_IDENTIFIER if max_invoices is None else max_invoices
    )
    if count > max_allowed:
        raise ValueError(
            f"Collective identifier cannot contain more than {max_allowed} invoices"
        )

    seen: set[str] = set()
    seller_nip: str | None = None
    for invoice in items:
        ksef_number = require_ksef_number(str(invoice.ksef_number))
        invoice_seller_nip = ksef_number.split("-", 1)[0]
        if seller_nip is None:
            seller_nip = invoice_seller_nip
        elif invoice_seller_nip != seller_nip:
            raise ValueError(
                "All invoices in a collective identifier must belong to the same seller"
            )
        if ksef_number in seen:
            raise ValueError(
                f"Duplicate KSeF number in collective identifier request: {ksef_number}"
            )
        seen.add(ksef_number)
        description = invoice.description
        if description is not None and len(description) > MAX_INVOICE_DESCRIPTION_LENGTH:
            raise ValueError(
                f"Invoice description cannot exceed {MAX_INVOICE_DESCRIPTION_LENGTH} characters"
            )
    return items


def _build_payment(
    *,
    amount: Decimal | str | int | float | None,
    currency: CurrencyCode | str | None,
) -> CollectiveIdentifierInvoicePayment | None:
    if amount is None and currency is None:
        return None
    if amount is None or currency is None:
        raise ValueError("payment amount and currency must be provided together")
    try:
        amount_decimal = amount if isinstance(amount, Decimal) else Decimal(str(amount))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError("Invalid payment amount") from exc
    if not amount_decimal.is_finite():
        raise ValueError("Payment amount must be finite")
    try:
        amount_float = float(amount_decimal)
    except (OverflowError, ValueError) as exc:
        raise ValueError("Payment amount is outside the supported range") from exc
    if not math.isfinite(amount_float):
        raise ValueError("Payment amount is outside the supported range")
    currency_code = currency if isinstance(currency, CurrencyCode) else CurrencyCode(str(currency))
    return CollectiveIdentifierInvoicePayment(
        amount=amount_float,
        currency=currency_code,
    )


def _parse_query_datetime(value: str, *, field_name: str) -> datetime:
    if not value:
        raise ValueError(f"{field_name} is required")
    normalized = expand_query_date_bound(value, end_of_day=field_name == "dateCreatedTo")
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"Invalid {field_name} datetime: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
